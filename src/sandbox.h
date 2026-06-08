#ifndef _SANDBOX_H
#define _SANDBOX_H

#include <linux/types.h>
#include <linux/fs.h>
#include <linux/hashtable.h>
#include <linux/mutex.h>
#include <linux/refcount.h>
#include <linux/sched.h>
#include <linux/version.h>

/* Корень хранилища теневых данных всех песочниц. */
#define SB_SHADOW_BASE   "/var/lib/sandbox"
#define SB_PATH_MAX      4096
#define SB_HASH_BITS     8

/*
 * struct open_flags - внутренняя структура ядра (fs/internal.h), в публичных
 * заголовках отсутствует. Объявляем сами, чтобы знать тип третьего аргумента
 * do_filp_open
 */
struct open_flags {
	int open_flag;
	umode_t mode;
	int acc_mode;
	int intent;
	int lookup_flags;
};

/*
 * Контекст одной песочницы. Базово ключ - tgid процесса; поле gid выделено под
 * доп.задание (логические группы родственных процессов с общим shadow-root)
 */
struct sb_ctx {
	struct hlist_node hnode;
	pid_t pid;			/* tgid отслеживаемого процесса */
	pid_t gid;			/* группа (база: == pid) - group-ready */
	char shadow[SB_PATH_MAX];	/* SB_SHADOW_BASE/<gid> */
	struct task_struct *bypass;	/* поток, выполняющий внутр. ФС-операции */
	struct mutex lock;		/* сериализация copy-up */
	refcount_t ref;
	atomic_long_t n_open, n_unlink, n_stat, n_other;
};

/* --- registry.c --- */
int  sb_registry_init(void);
void sb_registry_exit(void);
int  sb_add(pid_t tgid);
int  sb_add_member(pid_t tgid, pid_t gid, const char *shadow);
int  sb_del(pid_t tgid);
struct sb_ctx *sb_get(pid_t tgid);	/* refcounted; NULL если не песочный */
struct sb_ctx *sb_get_current(void);	/* по current->tgid */
void sb_put(struct sb_ctx *ctx);
void sb_for_each(void (*fn)(struct sb_ctx *, void *), void *arg);

/* --- shadow.c --- */
char *sb_abspath(int dfd, const char *name);	/* kmalloc'd; caller kfree; NULL=fail */
bool  sb_in_shadow_base(const char *abspath);
char *sb_data_path(struct sb_ctx *ctx, const char *abspath);	/* kmalloc'd */
char *sb_wh_path(struct sb_ctx *ctx, const char *abspath);	/* kmalloc'd */
bool  sb_exists(const char *path);
bool  sb_lexists(const char *path);	/* существование без перехода по симлинку */
bool  sb_skip_path(const char *abspath);	/* псевдо-ФС/устройства - не песочим */
int   sb_path_kind(const char *abspath);	/* 0=нет, 1=обычный файл, 2=иное */
int   sb_check_access(const char *path, int mode);	/* faccessat по тени */
bool  sb_is_whiteout(struct sb_ctx *ctx, const char *abspath);
int   sb_make_whiteout(struct sb_ctx *ctx, const char *abspath);
int   sb_clear_whiteout(struct sb_ctx *ctx, const char *abspath);
int   sb_copy_up(struct sb_ctx *ctx, const char *abspath, int open_flags);
char *sb_resolve_shadow_link(struct sb_ctx *ctx, const char *abspath);
int   sb_mkdir_p(const char *dir);
void  sb_mkdir_parent(const char *path);
int   sb_chmod(const char *path, umode_t mode);
int   sb_chown(const char *path, uid_t uid, gid_t gid);
int   sb_utimes(const char *path, struct timespec64 *times);
char *sb_materialize(struct sb_ctx *ctx, const char *abspath);
int   sb_unlink_path(const char *path);
int   sb_copy_file(const char *src, const char *dst);
int   sb_make_shadow_dirs(struct sb_ctx *ctx);

static inline bool sb_write_intent(int flags)
{
	return (flags & O_ACCMODE) != O_RDONLY ||
	       (flags & (O_CREAT | O_TRUNC | O_APPEND));
}

/* --- hooks.c --- */
int  sb_hooks_install(void);
void sb_hooks_remove(void);

/* --- procfs.c --- */
int  sb_proc_init(void);
void sb_proc_exit(void);

#endif /* _SANDBOX_H */
