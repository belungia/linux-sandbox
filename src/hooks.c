/*
 * Replacement-функции для syscall-обёрток VFS. Все перехватываемые функции
 * принимают (dfd, struct filename *) - это даёт единый способ получить
 * абсолютный путь (sb_abspath) и согласованные ключи между всеми хуками.
 *
 * Перенаправление: write-intent open -> copy-up + открыть теневой файл;
 * read-only -> открыть тень, если есть; unlink/rmdir -> whiteout;
 * mkdir/rename -> в тень; statx -> метаданные из тени или -ENOENT по whiteout.
 */
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/stat.h>
#include <linux/fcntl.h>
#include <linux/uaccess.h>
#include <linux/limits.h>
#include <linux/fs_struct.h>
#include <linux/ptrace.h>
#include <linux/list.h>
#include <linux/dcache.h>

#include "sandbox.h"
#include "ftrace_hook.h"

/* Указатели на оригиналы (заполняет fh_install). */
static struct file *(*real_do_filp_open)(int, struct filename *,
					 const struct open_flags *);
static int (*real_do_unlinkat)(int, struct filename *);
static int (*real_do_rmdir)(int, struct filename *);
static int (*real_do_mkdirat)(int, struct filename *, umode_t);
static int (*real_do_mknodat)(int, struct filename *, umode_t, unsigned int);
static int (*real_do_renameat2)(int, struct filename *, int,
				struct filename *, unsigned int);
static int (*real_vfs_statx)(int, struct filename *, int,
			     struct kstat *, u32);
static int (*real_do_symlinkat)(struct filename *, int, struct filename *);
static int (*real_do_linkat)(int, struct filename *, int,
			     struct filename *, int);
static int (*real_do_readlinkat)(int, const char __user *, char __user *, int);
static long (*real_do_faccessat)(int, const char __user *, int, int);
/* 4-й арг (kernel_xattr_ctx*) трактуем как непрозрачный указатель — пробрасываем */
static ssize_t (*real_filename_getxattr)(int, struct filename *,
					 unsigned int, void *);
static ssize_t (*real_path_listxattrat)(int, const char __user *, unsigned int,
					char __user *, size_t);
/* chmod_common/chown_common — ядро chmod/chown (после разрешения пути) */
static int (*real_chmod_common)(const struct path *, umode_t);
static int (*real_chown_common)(const struct path *, uid_t, gid_t);
static int (*real_vfs_utimes)(const struct path *, struct timespec64 *);
static long (*real_sys_chdir)(const struct pt_regs *);
static void (*real_set_fs_pwd)(struct fs_struct *, const struct path *);
static int (*real_iterate_dir)(struct file *, struct dir_context *);

/* Быстрая проверка: песочный ли current и не внутренняя ли это операция. */
static struct sb_ctx *sb_enter(void)
{
	struct sb_ctx *ctx = sb_get_current();

	if (!ctx)
		return NULL;
	if (ctx->bypass == current) {
		sb_put(ctx);
		return NULL;
	}
	return ctx;
}

/* ---- open ---- */
static struct file *fh_do_filp_open(int dfd, struct filename *pathname,
				    const struct open_flags *op)
{
	struct sb_ctx *ctx;
	char *ab, *data;
	struct filename *redir;
	struct file *ret;
	int flags;
	bool resolved = false;

	ctx = sb_enter();
	if (!ctx)
		return real_do_filp_open(dfd, pathname, op);

	ab = sb_abspath(dfd, pathname->name);
	if (!ab || sb_skip_path(ab)) {
		kfree(ab);
		sb_put(ctx);
		return real_do_filp_open(dfd, pathname, op);
	}

	flags = op ? op->open_flag : 0;
	atomic_long_inc(&ctx->n_open);

	/*
	 * Раскрутка цепочки песочных симлинков: если open идёт с follow и по пути
	 * лежит теневой симлинк — резолвим его цель через песочницу (иначе ядро
	 * резолвило бы её в реальной ФС, мимо нас). resolved=true → дальше
	 * открывать надо разрешённый ab, а не исходный pathname (это сам симлинк).
	 */
	if (!(flags & O_NOFOLLOW)) {
		char *tgt;
		int depth;

		for (depth = 0; depth < 8; depth++) {
			tgt = sb_resolve_shadow_link(ctx, ab);
			if (!tgt)
				break;
			kfree(ab);
			ab = tgt;
			resolved = true;
			if (sb_skip_path(ab))
				break;
		}
	}

	if (resolved && sb_skip_path(ab))
		goto open_target;		/* цель в псевдо-ФС */

	if (sb_is_whiteout(ctx, ab)) {
		if (flags & O_CREAT) {
			sb_clear_whiteout(ctx, ab);	/* воссоздаём */
		} else {
			kfree(ab);
			sb_put(ctx);
			return ERR_PTR(-ENOENT);
		}
	} else if (sb_path_kind(ab) == 2) {
		/* существующее не-regular (каталог/устройство/fifo) - не песочим */
		goto open_target;
	}

	if (sb_write_intent(flags)) {
		sb_copy_up(ctx, ab, flags);
		data = sb_data_path(ctx, ab);
		if (data) {
			redir = getname_kernel(data);
			if (!IS_ERR(redir)) {
				ret = real_do_filp_open(dfd, redir, op);
				putname(redir);
				kfree(data);
				kfree(ab);
				sb_put(ctx);
				return ret;
			}
			kfree(data);
		}
	} else {
		data = sb_data_path(ctx, ab);
		if (data && sb_exists(data)) {
			redir = getname_kernel(data);
			if (!IS_ERR(redir)) {
				ret = real_do_filp_open(dfd, redir, op);
				putname(redir);
				kfree(data);
				kfree(ab);
				sb_put(ctx);
				return ret;
			}
		}
		kfree(data);
	}

open_target:
	/*
	 * Теневой версии нет. Если раскрутили симлинк — открыть РЕАЛЬНУЮ цель по
	 * абсолютному пути (исходный pathname — это сам симлинк). Иначе обычный
	 * passthrough исходного пути.
	 */
	if (resolved) {
		redir = getname_kernel(ab);
		if (!IS_ERR(redir)) {
			ret = real_do_filp_open(dfd, redir, op);
			putname(redir);
			kfree(ab);
			sb_put(ctx);
			return ret;
		}
	}
	kfree(ab);
	sb_put(ctx);
	return real_do_filp_open(dfd, pathname, op);
}

/* ---- unlink / rmdir (общая логика whiteout) ---- */
static int sb_delete_common(struct sb_ctx *ctx, int dfd, struct filename *name)
{
	char *ab, *data;
	bool exists;

	ab = sb_abspath(dfd, name->name);
	if (!ab || sb_skip_path(ab)) {
		kfree(ab);
		return -ERESTARTSYS;	/* сигнал "вызвать оригинал" */
	}

	if (sb_is_whiteout(ctx, ab)) {
		kfree(ab);
		return -ENOENT;
	}

	data = sb_data_path(ctx, ab);
	/* lexists: видим и теневые симлинки (sb_exists шёл бы по ссылке и падал) */
	exists = (data && sb_lexists(data)) || sb_lexists(ab);
	if (!exists) {
		kfree(data);
		kfree(ab);
		return -ENOENT;
	}
	kfree(data);

	sb_make_whiteout(ctx, ab);
	atomic_long_inc(&ctx->n_unlink);
	kfree(ab);
	return 0;	/* "удаление" успешно, реальный объект не тронут */
}

static int fh_do_unlinkat(int dfd, struct filename *name)
{
	struct sb_ctx *ctx;
	int ret;

	ctx = sb_enter();
	if (!ctx)
		return real_do_unlinkat(dfd, name);

	ret = sb_delete_common(ctx, dfd, name);
	sb_put(ctx);
	if (ret == -ERESTARTSYS)
		return real_do_unlinkat(dfd, name);
	return ret;
}

static int fh_do_rmdir(int dfd, struct filename *name)
{
	struct sb_ctx *ctx;
	int ret;

	ctx = sb_enter();
	if (!ctx)
		return real_do_rmdir(dfd, name);

	ret = sb_delete_common(ctx, dfd, name);
	sb_put(ctx);
	if (ret == -ERESTARTSYS)
		return real_do_rmdir(dfd, name);
	return ret;
}

/* ---- mkdir ---- */
static int fh_do_mkdirat(int dfd, struct filename *name, umode_t mode)
{
	struct sb_ctx *ctx;
	char *ab, *data;
	int ret = 0;

	ctx = sb_enter();
	if (!ctx)
		return real_do_mkdirat(dfd, name, mode);

	ab = sb_abspath(dfd, name->name);
	if (!ab || sb_skip_path(ab)) {
		kfree(ab);
		sb_put(ctx);
		return real_do_mkdirat(dfd, name, mode);
	}

	data = sb_data_path(ctx, ab);
	if (data) {
		sb_clear_whiteout(ctx, ab);
		ret = sb_mkdir_p(data);		/* создаём каталог в тени */
		ret = (ret == -EEXIST) ? -EEXIST : 0;
		kfree(data);
	} else {
		ret = -ENOMEM;
	}
	atomic_long_inc(&ctx->n_other);

	kfree(ab);
	sb_put(ctx);
	return ret;
}

/* ---- mknod (устройства/fifo/сокеты/спец-файлы) ---- */
static int fh_do_mknodat(int dfd, struct filename *name, umode_t mode,
			 unsigned int dev)
{
	struct sb_ctx *ctx;
	char *ab, *data;
	struct filename *redir;
	int ret;

	ctx = sb_enter();
	if (!ctx)
		return real_do_mknodat(dfd, name, mode, dev);

	ab = sb_abspath(dfd, name->name);
	if (!ab || sb_skip_path(ab)) {
		kfree(ab);
		sb_put(ctx);
		return real_do_mknodat(dfd, name, mode, dev);
	}

	/* создаём узел в теневом дереве, реальную ФС не трогаем */
	data = sb_data_path(ctx, ab);
	if (data) {
		sb_clear_whiteout(ctx, ab);
		sb_mkdir_parent(data);
		redir = getname_kernel(data);
		if (!IS_ERR(redir)) {
			ret = real_do_mknodat(dfd, redir, mode, dev);
			putname(redir);
			atomic_long_inc(&ctx->n_other);
			kfree(data);
			kfree(ab);
			sb_put(ctx);
			return ret;
		}
		kfree(data);
	}
	kfree(ab);
	sb_put(ctx);
	return real_do_mknodat(dfd, name, mode, dev);
}

/* ---- symlink: создать симлинк в тени ---- */
static int fh_do_symlinkat(struct filename *from, int newdfd,
			   struct filename *to)
{
	struct sb_ctx *ctx;
	char *ab, *data;
	struct filename *redir;
	int ret;

	ctx = sb_enter();
	if (!ctx)
		return real_do_symlinkat(from, newdfd, to);

	/* to = путь создаваемой ссылки; from = её текст (цель), не трогаем */
	ab = sb_abspath(newdfd, to->name);
	if (!ab || sb_skip_path(ab)) {
		kfree(ab);
		sb_put(ctx);
		return real_do_symlinkat(from, newdfd, to);
	}

	data = sb_data_path(ctx, ab);
	if (data) {
		sb_clear_whiteout(ctx, ab);
		sb_mkdir_parent(data);
		redir = getname_kernel(data);
		if (!IS_ERR(redir)) {
			ret = real_do_symlinkat(from, newdfd, redir);
			putname(redir);
			atomic_long_inc(&ctx->n_other);
			kfree(data);
			kfree(ab);
			sb_put(ctx);
			return ret;
		}
		kfree(data);
	}
	kfree(ab);
	sb_put(ctx);
	return real_do_symlinkat(from, newdfd, to);
}

/* ---- hardlink: материализовать оригинал в тень и линковать там же ---- */
static int fh_do_linkat(int olddfd, struct filename *old, int newdfd,
			struct filename *new, int flags)
{
	struct sb_ctx *ctx;
	char *oa, *na, *od, *nd;
	int ret = -ENOMEM;

	ctx = sb_enter();
	if (!ctx)
		return real_do_linkat(olddfd, old, newdfd, new, flags);

	oa = sb_abspath(olddfd, old->name);
	na = sb_abspath(newdfd, new->name);
	if (!oa || !na || sb_skip_path(oa) || sb_skip_path(na)) {
		kfree(oa);
		kfree(na);
		sb_put(ctx);
		return real_do_linkat(olddfd, old, newdfd, new, flags);
	}

	/* hardlink не может пересекать ФС → линкуем на теневую копию источника */
	sb_copy_up(ctx, oa, 0);
	od = sb_data_path(ctx, oa);
	nd = sb_data_path(ctx, na);
	if (od && nd) {
		struct filename *rold = getname_kernel(od);
		struct filename *rnew = getname_kernel(nd);

		if (!IS_ERR(rold) && !IS_ERR(rnew)) {
			sb_clear_whiteout(ctx, na);
			sb_mkdir_parent(nd);
			ret = real_do_linkat(olddfd, rold, newdfd, rnew, flags);
			atomic_long_inc(&ctx->n_other);
		}
		if (!IS_ERR(rold))
			putname(rold);
		if (!IS_ERR(rnew))
			putname(rnew);
	}
	kfree(od);
	kfree(nd);
	kfree(oa);
	kfree(na);
	sb_put(ctx);
	return ret;
}

/* ---- readlink: вернуть цель теневого симлинка ---- */
static int fh_do_readlinkat(int dfd, const char __user *pathname,
			    char __user *buf, int bufsiz)
{
	struct sb_ctx *ctx;
	char *kpath, *ab, *data;
	struct path p;
	int ret;

	ctx = sb_enter();
	if (!ctx)
		return real_do_readlinkat(dfd, pathname, buf, bufsiz);

	kpath = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!kpath) {
		sb_put(ctx);
		return real_do_readlinkat(dfd, pathname, buf, bufsiz);
	}
	if (strncpy_from_user(kpath, pathname, PATH_MAX) < 0) {
		kfree(kpath);
		sb_put(ctx);
		return real_do_readlinkat(dfd, pathname, buf, bufsiz);
	}

	ab = sb_abspath(dfd, kpath);
	kfree(kpath);
	if (!ab || sb_skip_path(ab)) {
		kfree(ab);
		sb_put(ctx);
		return real_do_readlinkat(dfd, pathname, buf, bufsiz);
	}

	if (sb_is_whiteout(ctx, ab)) {
		kfree(ab);
		sb_put(ctx);
		return -ENOENT;
	}

	data = sb_data_path(ctx, ab);
	/* flags=0 -> не следовать по финальному симлинку (нужен сам симлинк) */
	if (data && !kern_path(data, 0, &p)) {
		ret = vfs_readlink(p.dentry, buf, bufsiz);
		path_put(&p);
		kfree(data);
		kfree(ab);
		atomic_long_inc(&ctx->n_stat);
		sb_put(ctx);
		return ret;
	}
	kfree(data);
	kfree(ab);
	sb_put(ctx);
	return real_do_readlinkat(dfd, pathname, buf, bufsiz);
}

/* ---- faccessat: проверка доступа по тени (rm/cp/mv делают access перед операцией) ---- */
static long fh_do_faccessat(int dfd, const char __user *filename, int mode,
			    int flags)
{
	struct sb_ctx *ctx;
	char *kpath, *ab, *data;
	long ret;

	ctx = sb_enter();
	if (!ctx)
		return real_do_faccessat(dfd, filename, mode, flags);

	kpath = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!kpath) {
		sb_put(ctx);
		return real_do_faccessat(dfd, filename, mode, flags);
	}
	if (strncpy_from_user(kpath, filename, PATH_MAX) < 0) {
		kfree(kpath);
		sb_put(ctx);
		return real_do_faccessat(dfd, filename, mode, flags);
	}

	ab = sb_abspath(dfd, kpath);
	kfree(kpath);
	if (!ab || sb_skip_path(ab)) {
		kfree(ab);
		sb_put(ctx);
		return real_do_faccessat(dfd, filename, mode, flags);
	}
	if (sb_is_whiteout(ctx, ab)) {
		kfree(ab);
		sb_put(ctx);
		return -ENOENT;
	}

	data = sb_data_path(ctx, ab);
	if (data && sb_exists(data)) {
		ret = sb_check_access(data, mode);	/* проверяем теневой файл */
		kfree(data);
		kfree(ab);
		sb_put(ctx);
		return ret;
	}
	kfree(data);
	kfree(ab);
	sb_put(ctx);
	return real_do_faccessat(dfd, filename, mode, flags);
}

/* ---- getxattr: у теневого файла нет xattr (ls дёргает security.selinux) ---- */
static ssize_t fh_filename_getxattr(int dfd, struct filename *filename,
				    unsigned int at_flags, void *xctx)
{
	struct sb_ctx *ctx;
	char *ab, *data;

	ctx = sb_enter();
	if (!ctx)
		return real_filename_getxattr(dfd, filename, at_flags, xctx);

	ab = sb_abspath(dfd, filename->name);
	if (!ab || sb_skip_path(ab)) {
		kfree(ab);
		sb_put(ctx);
		return real_filename_getxattr(dfd, filename, at_flags, xctx);
	}
	if (sb_is_whiteout(ctx, ab)) {
		kfree(ab);
		sb_put(ctx);
		return -ENOENT;
	}
	data = sb_data_path(ctx, ab);
	if (data && sb_lexists(data)) {
		/*
		 * Теневой файл есть, но xattr (security.selinux и пр.) у него нет.
		 * Возвращаем -ENODATA («атрибут отсутствует») вместо ENOENT, чтобы
		 * ls/cp не считали путь несуществующим и не сыпали «cannot access».
		 */
		kfree(data);
		kfree(ab);
		sb_put(ctx);
		return -ENODATA;
	}
	kfree(data);
	kfree(ab);
	sb_put(ctx);
	return real_filename_getxattr(dfd, filename, at_flags, xctx);
}

/* Логический путь из разрешённого struct path (kmalloc'd; caller kfree). */
static char *sb_path_str(const struct path *path)
{
	char *buf, *p, *res = NULL;

	buf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!buf)
		return NULL;
	p = d_path(path, buf, PATH_MAX);
	if (!IS_ERR(p))
		res = kstrdup(p, GFP_KERNEL);
	kfree(buf);
	return res;
}

/* ---- chmod: менять права теневой копии, не реального файла ---- */
static int fh_chmod_common(const struct path *path, umode_t mode)
{
	struct sb_ctx *ctx;
	char *ab, *data;
	int ret;

	ctx = sb_enter();
	if (!ctx)
		return real_chmod_common(path, mode);

	ab = sb_path_str(path);
	if (!ab || sb_skip_path(ab)) {
		kfree(ab);
		sb_put(ctx);
		return real_chmod_common(path, mode);
	}

	data = sb_materialize(ctx, ab);		/* copy-up реального файла в тень */
	ret = data ? sb_chmod(data, mode) : -ENOMEM;
	atomic_long_inc(&ctx->n_other);
	kfree(data);
	kfree(ab);
	sb_put(ctx);
	return ret;
}

/* ---- chown: владелец теневой копии ---- */
static int fh_chown_common(const struct path *path, uid_t user, gid_t group)
{
	struct sb_ctx *ctx;
	char *ab, *data;
	int ret;

	ctx = sb_enter();
	if (!ctx)
		return real_chown_common(path, user, group);

	ab = sb_path_str(path);
	if (!ab || sb_skip_path(ab)) {
		kfree(ab);
		sb_put(ctx);
		return real_chown_common(path, user, group);
	}

	data = sb_materialize(ctx, ab);
	ret = data ? sb_chown(data, user, group) : -ENOMEM;
	atomic_long_inc(&ctx->n_other);
	kfree(data);
	kfree(ab);
	sb_put(ctx);
	return ret;
}

/* ---- utimensat: время теневой копии, ядро vfs_utimes ---- */
static int fh_vfs_utimes(const struct path *path, struct timespec64 *times)
{
	struct sb_ctx *ctx;
	char *ab, *data;
	int ret;

	ctx = sb_enter();
	if (!ctx)
		return real_vfs_utimes(path, times);

	ab = sb_path_str(path);
	if (!ab || sb_skip_path(ab)) {
		kfree(ab);
		sb_put(ctx);
		return real_vfs_utimes(path, times);
	}

	data = sb_materialize(ctx, ab);
	ret = data ? sb_utimes(data, times) : -ENOMEM;
	atomic_long_inc(&ctx->n_other);
	kfree(data);
	kfree(ab);
	sb_put(ctx);
	return ret;
}

/* ---- listxattr: у теневого файла нет xattr (убирает '?' в ls -l) ---- */
static ssize_t fh_path_listxattrat(int dfd, const char __user *pathname,
				   unsigned int at_flags, char __user *list,
				   size_t size)
{
	struct sb_ctx *ctx;
	char *kpath, *ab, *data;

	ctx = sb_enter();
	if (!ctx)
		return real_path_listxattrat(dfd, pathname, at_flags, list, size);

	kpath = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!kpath) {
		sb_put(ctx);
		return real_path_listxattrat(dfd, pathname, at_flags, list, size);
	}
	if (strncpy_from_user(kpath, pathname, PATH_MAX) < 0) {
		kfree(kpath);
		sb_put(ctx);
		return real_path_listxattrat(dfd, pathname, at_flags, list, size);
	}
	ab = sb_abspath(dfd, kpath);
	kfree(kpath);
	if (!ab || sb_skip_path(ab)) {
		kfree(ab);
		sb_put(ctx);
		return real_path_listxattrat(dfd, pathname, at_flags, list, size);
	}
	data = sb_data_path(ctx, ab);
	if (data && sb_lexists(data)) {
		kfree(data);
		kfree(ab);
		sb_put(ctx);
		return 0;		/* пустой список xattr → нет '?' в ls */
	}
	kfree(data);
	kfree(ab);
	sb_put(ctx);
	return real_path_listxattrat(dfd, pathname, at_flags, list, size);
}

/* ---- rename ---- */
static int fh_do_renameat2(int olddfd, struct filename *from,
			   int newdfd, struct filename *to, unsigned int flags)
{
	struct sb_ctx *ctx;
	char *oa, *na, *sd, *dd;
	int ret = 0;

	ctx = sb_enter();
	if (!ctx)
		return real_do_renameat2(olddfd, from, newdfd, to, flags);

	oa = sb_abspath(olddfd, from->name);
	na = sb_abspath(newdfd, to->name);
	if (!oa || !na || sb_skip_path(oa) || sb_skip_path(na)) {
		kfree(oa);
		kfree(na);
		sb_put(ctx);
		return real_do_renameat2(olddfd, from, newdfd, to, flags);
	}

	if (sb_is_whiteout(ctx, oa)) {
		ret = -ENOENT;
		goto out;
	}

	/* материализуем источник в тени, копируем под новым именем */
	sb_copy_up(ctx, oa, 0);
	sd = sb_data_path(ctx, oa);
	dd = sb_data_path(ctx, na);
	if (sd && dd)
		sb_copy_file(sd, dd);
	kfree(sd);
	kfree(dd);

	sb_clear_whiteout(ctx, na);
	sb_make_whiteout(ctx, oa);	/* старое имя "исчезает" */
	atomic_long_inc(&ctx->n_other);
out:
	kfree(oa);
	kfree(na);
	sb_put(ctx);
	return ret;
}

/* ---- statx (метаданные пути) ---- */
static int fh_vfs_statx(int dfd, struct filename *name, int flags,
			struct kstat *stat, u32 request_mask)
{
	struct sb_ctx *ctx;
	char *ab, *data = NULL;
	struct filename *redir;
	int ret;
	bool resolved = false;

	ctx = sb_enter();
	if (!ctx)
		return real_vfs_statx(dfd, name, flags, stat, request_mask);

	ab = sb_abspath(dfd, name->name);
	if (!ab || sb_skip_path(ab)) {
		kfree(ab);
		sb_put(ctx);
		return real_vfs_statx(dfd, name, flags, stat, request_mask);
	}

	if (sb_is_whiteout(ctx, ab)) {
		kfree(ab);
		sb_put(ctx);
		return -ENOENT;
	}

	/*
	 * Follow-stat (без AT_SYMLINK_NOFOLLOW): раскрутить цепочку песочных
	 * симлинков через песочницу, иначе цель резолвится в реальной ФС → ENOENT
	 * (ls красит ссылку красным и пишет "cannot access"). lstat (NOFOLLOW)
	 * раскрутку не делает — отдаёт сам симлинк.
	 */
	if (!(flags & AT_SYMLINK_NOFOLLOW)) {
		char *tgt;
		int depth;

		for (depth = 0; depth < 8; depth++) {
			tgt = sb_resolve_shadow_link(ctx, ab);
			if (!tgt)
				break;
			kfree(ab);
			ab = tgt;
			resolved = true;
			if (sb_skip_path(ab))
				break;
		}
	}

	if (resolved && sb_skip_path(ab))
		goto stat_target;

	data = sb_data_path(ctx, ab);
	/* lexists: детектируем и теневые симлинки (lstat не должен идти по ним) */
	if (data && sb_lexists(data)) {
		redir = getname_kernel(data);
		if (!IS_ERR(redir)) {
			ret = real_vfs_statx(dfd, redir, flags, stat,
					     request_mask);
			putname(redir);
			atomic_long_inc(&ctx->n_stat);
			kfree(data);
			kfree(ab);
			sb_put(ctx);
			return ret;
		}
	}
	kfree(data);

stat_target:
	/* раскрутили симлинк, но тени у цели нет — stat реальной цели по абс. пути */
	if (resolved) {
		redir = getname_kernel(ab);
		if (!IS_ERR(redir)) {
			ret = real_vfs_statx(dfd, redir, flags, stat,
					     request_mask);
			putname(redir);
			kfree(ab);
			sb_put(ctx);
			return ret;
		}
	}
	kfree(ab);
	sb_put(ctx);
	return real_vfs_statx(dfd, name, flags, stat, request_mask);
}

/*
 * ---- chdir: зайти в созданный в песочнице каталог ----
 * chdir идёт мимо do_filp_open (резолвит путь сам), поэтому теневой каталог
 * ему не виден. Если реального каталога нет, а теневой есть — переставляем cwd
 * на физический теневой каталог. Дальше относительные операции внутри него
 * работают сами (попадают прямо в тень).
 */
static long fh_sys_chdir(const struct pt_regs *regs)
{
	struct sb_ctx *ctx;
	const char __user *upath = (const char __user *)regs->di;
	char *kpath, *ab, *data;
	struct path p;

	ctx = sb_enter();
	if (!ctx)
		return real_sys_chdir(regs);

	kpath = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!kpath) {
		sb_put(ctx);
		return real_sys_chdir(regs);
	}
	if (strncpy_from_user(kpath, upath, PATH_MAX) < 0) {
		kfree(kpath);
		sb_put(ctx);
		return real_sys_chdir(regs);
	}

	ab = sb_abspath(AT_FDCWD, kpath);
	kfree(kpath);
	/* cwd уже в тени (физический путь) или псевдо-ФС → обычный chdir */
	if (!ab || sb_skip_path(ab)) {
		kfree(ab);
		sb_put(ctx);
		return real_sys_chdir(regs);
	}
	if (sb_is_whiteout(ctx, ab)) {
		kfree(ab);
		sb_put(ctx);
		return -ENOENT;
	}
	/* реальный каталог существует → обычный chdir в него */
	if (sb_path_kind(ab) == 2) {
		kfree(ab);
		sb_put(ctx);
		return real_sys_chdir(regs);
	}

	/* реального нет — пробуем теневой каталог */
	data = sb_data_path(ctx, ab);
	if (real_set_fs_pwd && data &&
	    !kern_path(data, LOOKUP_DIRECTORY, &p)) {
		real_set_fs_pwd(current->fs, &p);
		path_put(&p);
		kfree(data);
		kfree(ab);
		atomic_long_inc(&ctx->n_other);
		sb_put(ctx);
		return 0;
	}
	kfree(data);
	kfree(ab);
	sb_put(ctx);
	return real_sys_chdir(regs);	/* пусть упадёт штатно (ENOENT) */
}

/*
 * ---- readdir-merge (#1) ----
 * При листинге реального каталога: прячем записи, помеченные whiteout (удалённые
 * в песочнице), и подмешиваем записи из теневого каталога (созданные в песочнице).
 * Реальную запись в пользовательский буфер делает штатный filldir (через
 * dir_emit на исходный контекст) — мы лишь фильтруем/добавляем.
 *
 * Позиция-маркер: getdents может звать iterate_dir много раз. После того как
 * подмешали теневые записи, ставим f_pos в SB_DIR_DONE, чтобы следующий вызов
 * сразу завершился (иначе теневые задублируются).
 */
#define SB_DIR_DONE	((loff_t)0x7000000000000000LL)
#define SB_NAME_MAX	8192

struct sb_name {
	struct list_head node;
	int len;
	char name[];
};

struct sb_rd_ctx {
	struct dir_context ctx;		/* наш actor для реальной итерации */
	struct dir_context *orig;	/* контекст вызывающего (его actor + буфер) */
	struct sb_ctx *sb;
	const char *dir;		/* логический путь каталога */
	struct list_head names;		/* уже выданные имена (дедуп) */
	int count;
	bool full;			/* буфер вызывающего заполнился */
};

static bool sb_is_dot(const char *n, int len)
{
	return (len == 1 && n[0] == '.') ||
	       (len == 2 && n[0] == '.' && n[1] == '.');
}

static bool sb_name_seen(struct sb_rd_ctx *r, const char *n, int len)
{
	struct sb_name *e;

	list_for_each_entry(e, &r->names, node)
		if (e->len == len && !memcmp(e->name, n, len))
			return true;
	return false;
}

static void sb_name_add(struct sb_rd_ctx *r, const char *n, int len)
{
	struct sb_name *e;

	if (r->count >= SB_NAME_MAX)
		return;
	e = kmalloc(sizeof(*e) + len, GFP_KERNEL);
	if (!e)
		return;
	e->len = len;
	memcpy(e->name, n, len);
	list_add(&e->node, &r->names);
	r->count++;
}

static void sb_names_free(struct sb_rd_ctx *r)
{
	struct sb_name *e, *t;

	list_for_each_entry_safe(e, t, &r->names, node) {
		list_del(&e->node);
		kfree(e);
	}
}

/* whiteout по паре (каталог, имя) */
static bool sb_entry_wh(struct sb_ctx *sb, const char *dir,
			const char *n, int len)
{
	char *ab;
	int dl = strlen(dir);
	bool r;

	ab = kmalloc(dl + 1 + len + 1, GFP_KERNEL);
	if (!ab)
		return false;
	memcpy(ab, dir, dl);
	ab[dl] = '/';
	memcpy(ab + dl + 1, n, len);
	ab[dl + 1 + len] = '\0';
	r = sb_is_whiteout(sb, ab);
	kfree(ab);
	return r;
}

/* actor реальной итерации: прячем whiteout, остальное форвардим вызывающему */
static bool sb_rd_actor(struct dir_context *ctx, const char *name, int namlen,
			loff_t off, u64 ino, unsigned int d_type)
{
	struct sb_rd_ctx *r = container_of(ctx, struct sb_rd_ctx, ctx);

	if (!sb_is_dot(name, namlen) &&
	    sb_entry_wh(r->sb, r->dir, name, namlen))
		return true;		/* удалён в песочнице → скрыть */

	sb_name_add(r, name, namlen);
	r->orig->pos = ctx->pos;
	if (!dir_emit(r->orig, name, namlen, ino, d_type)) {
		r->full = true;
		return false;
	}
	return true;
}

/* actor итерации теневого каталога: подмешиваем созданное в песочнице */
struct sb_inj_ctx {
	struct dir_context ctx;
	struct sb_rd_ctx *r;
	loff_t pos;
};

static bool sb_inj_actor(struct dir_context *ctx, const char *name, int namlen,
			 loff_t off, u64 ino, unsigned int d_type)
{
	struct sb_inj_ctx *i = container_of(ctx, struct sb_inj_ctx, ctx);
	struct sb_rd_ctx *r = i->r;

	if (sb_is_dot(name, namlen))
		return true;
	if (sb_name_seen(r, name, namlen))
		return true;		/* уже выдан как реальный */
	if (sb_entry_wh(r->sb, r->dir, name, namlen))
		return true;
	r->orig->pos = i->pos++;
	if (!dir_emit(r->orig, name, namlen, ino, d_type)) {
		r->full = true;
		return false;
	}
	return true;
}

static void sb_inject_shadow(struct sb_rd_ctx *r)
{
	char *shdir = sb_data_path(r->sb, r->dir);
	struct file *d;
	struct sb_inj_ctx ic = {
		.ctx.actor = sb_inj_actor,
		.ctx.pos = 0,
		.r = r,
		.pos = SB_DIR_DONE - SB_NAME_MAX,
	};

	if (!shdir)
		return;
	/* путь в теневой базе → open пройдёт мимо песочницы (passthrough) */
	d = filp_open(shdir, O_RDONLY | O_DIRECTORY, 0);
	if (!IS_ERR(d)) {
		real_iterate_dir(d, &ic.ctx);
		filp_close(d, NULL);
	}
	kfree(shdir);
}

static int fh_iterate_dir(struct file *file, struct dir_context *ctx)
{
	struct sb_ctx *sb;
	char *buf, *dir;
	struct sb_rd_ctx r;
	int ret;

	sb = sb_enter();
	if (!sb)
		return real_iterate_dir(file, ctx);

	buf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!buf) {
		sb_put(sb);
		return real_iterate_dir(file, ctx);
	}
	dir = d_path(&file->f_path, buf, PATH_MAX);
	/* не наш каталог / псевдо-ФС / уже теневой → обычный листинг */
	if (IS_ERR(dir) || sb_skip_path(dir)) {
		kfree(buf);
		sb_put(sb);
		return real_iterate_dir(file, ctx);
	}
	/*
	 * Маркер «уже подмешали теневое» храним в file->f_pos (он персистентен
	 * между вызовами getdents; ctx->pos каждый вызов заводится с 0).
	 */
	if (file->f_pos >= SB_DIR_DONE) {
		kfree(buf);
		sb_put(sb);
		return 0;
	}

	/* копируем весь контекст (сохранив pos/count и пр.), меняем только actor */
	r.ctx = *ctx;
	r.ctx.actor = sb_rd_actor;
	r.orig = ctx;
	r.sb = sb;
	r.dir = dir;
	r.count = 0;
	r.full = false;
	INIT_LIST_HEAD(&r.names);

	ret = real_iterate_dir(file, &r.ctx);
	ctx->pos = r.ctx.pos;

	/* реальный каталог исчерпан и буфер не полон → подмешать теневые */
	if (ret == 0 && !r.full) {
		sb_inject_shadow(&r);
		ctx->pos = SB_DIR_DONE;
		file->f_pos = SB_DIR_DONE;
	}

	sb_names_free(&r);
	kfree(buf);
	sb_put(sb);
	return ret;
}

static struct ftrace_hook hooks[] = {
	HOOK("do_filp_open",  fh_do_filp_open,  &real_do_filp_open),
	HOOK("do_unlinkat",   fh_do_unlinkat,   &real_do_unlinkat),
	HOOK("do_rmdir",      fh_do_rmdir,      &real_do_rmdir),
	HOOK("do_mkdirat",    fh_do_mkdirat,    &real_do_mkdirat),
	HOOK("do_mknodat",    fh_do_mknodat,    &real_do_mknodat),
	HOOK("do_symlinkat",  fh_do_symlinkat,  &real_do_symlinkat),
	HOOK("do_linkat",     fh_do_linkat,     &real_do_linkat),
	HOOK("do_readlinkat", fh_do_readlinkat, &real_do_readlinkat),
	HOOK("do_faccessat",  fh_do_faccessat,  &real_do_faccessat),
	HOOK("chmod_common",  fh_chmod_common,  &real_chmod_common),
	HOOK("chown_common",  fh_chown_common,  &real_chown_common),
	HOOK("vfs_utimes",    fh_vfs_utimes,    &real_vfs_utimes),
	HOOK("do_renameat2",  fh_do_renameat2,  &real_do_renameat2),
	HOOK("vfs_statx",     fh_vfs_statx,     &real_vfs_statx),
	HOOK("__x64_sys_chdir", fh_sys_chdir,   &real_sys_chdir),
	HOOK("iterate_dir",   fh_iterate_dir,   &real_iterate_dir),
};

/*
 * Опциональный хук: filename_getxattr появился с рефактором xattr (~6.13).
 * Ставим отдельно и НЕ роняем модуль, если символа нет на старом ядре.
 */
static struct ftrace_hook xattr_hook =
	HOOK("filename_getxattr", fh_filename_getxattr, &real_filename_getxattr);
static struct ftrace_hook listxattr_hook =
	HOOK("path_listxattrat", fh_path_listxattrat, &real_path_listxattrat);

int sb_hooks_install(void)
{
	int err = fh_install_all(hooks, ARRAY_SIZE(hooks));

	if (err)
		return err;

	/* set_fs_pwd не экспортируется — резолвим адрес для смены cwd на тень */
	real_set_fs_pwd = (void *)fh_lookup_name("set_fs_pwd");

	/* xattr-хуки опциональны: на старых ядрах символов может не быть */
	if (fh_install(&xattr_hook))
		pr_info("sandbox: filename_getxattr не перехвачен (не критично)\n");
	if (fh_install(&listxattr_hook))
		pr_info("sandbox: path_listxattrat не перехвачен (не критично)\n");

	return 0;
}

void sb_hooks_remove(void)
{
	fh_remove(&listxattr_hook);
	fh_remove(&xattr_hook);
	fh_remove_all(hooks, ARRAY_SIZE(hooks));
}
