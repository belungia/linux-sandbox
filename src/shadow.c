/*
 * Теневое хранилище песочницы: copy-up, whiteout, построение путей и каталогов.
 *
 * Раскладка для песочницы с gid=G:
 *   SB_SHADOW_BASE/G/data/<abspath>   - теневые данные (copy-up и созданные)
 *   SB_SHADOW_BASE/G/wh/<abspath>     - whiteout-маркер ("удалён в песочнице")
 */
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/file.h>
#include <linux/fs_struct.h>
#include <linux/dcache.h>
#include <linux/fcntl.h>
#include <linux/limits.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/delayed_call.h>
#include <linux/cred.h>
#include <linux/uidgid.h>

#include "sandbox.h"

/*
 * include/linux/mnt_idmap.h не поставляется в linux-headers, а struct mnt_idmap
 * для модулей непрозрачна (forward-declared в fs.h). nop_mnt_idmap экспортирован
 * (EXPORT_SYMBOL_GPL) - объявляем его сами и берём адрес для vfs_*-операций.
 */
extern struct mnt_idmap nop_mnt_idmap;

#define SB_COPY_BUF 8192

/* vfs_mkdir сменил тип возврата в 6.15 (int -> struct dentry *). */
static int sb_vfs_mkdir_one(struct inode *dir, struct dentry *dentry, umode_t mode)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 15, 0)
	struct dentry *r = vfs_mkdir(&nop_mnt_idmap, dir, dentry, mode);

	if (IS_ERR(r))
		return PTR_ERR(r);
	if (r && r != dentry)
		dput(r);
	return 0;
#else
	return vfs_mkdir(&nop_mnt_idmap, dir, dentry, mode);
#endif
}

/*
 * lookup_one_len() удалён в 6.16, а lookup_one() сменил сигнатуру на qstr-форму.
 * Под parent должен быть взят inode_lock (как того требует lookup).
 */
static struct dentry *sb_lookup_child(struct dentry *parent, const char *base)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 16, 0)
	struct qstr q = QSTR_INIT(base, strlen(base));

	return lookup_one(&nop_mnt_idmap, &q, parent);
#else
	return lookup_one_len(base, parent, strlen(base));
#endif
}

bool sb_in_shadow_base(const char *abspath)
{
	return abspath &&
	       strncmp(abspath, SB_SHADOW_BASE, sizeof(SB_SHADOW_BASE) - 1) == 0;
}

/* root + "/" + sub + abspath  (abspath начинается с '/') */
static char *join3(const char *root, const char *sub, const char *abspath)
{
	size_t lr = strlen(root), ls = strlen(sub), la = strlen(abspath);
	char *r = kmalloc(lr + 1 + ls + la + 1, GFP_KERNEL);

	if (!r)
		return NULL;
	memcpy(r, root, lr);
	r[lr] = '/';
	memcpy(r + lr + 1, sub, ls);
	memcpy(r + lr + 1 + ls, abspath, la);
	r[lr + 1 + ls + la] = '\0';
	return r;
}

char *sb_data_path(struct sb_ctx *ctx, const char *abspath)
{
	return join3(ctx->shadow, "data", abspath);
}

char *sb_wh_path(struct sb_ctx *ctx, const char *abspath)
{
	return join3(ctx->shadow, "wh", abspath);
}

/*
 * Абсолютный путь из (dfd, name). Поддержаны абсолютные пути и AT_FDCWD-
 * относительные; прочие dfd и нормализация "." / ".." в базовой версии не
 * обрабатываются (вернётся NULL -> passthrough без песочницы).
 */
char *sb_abspath(int dfd, const char *name)
{
	struct path base;
	char *buf, *p, *res;
	size_t lp, ln;
	bool got = false;

	if (!name)
		return NULL;
	if (name[0] == '/')
		return kstrdup(name, GFP_KERNEL);

	/*
	 * Относительный путь — нужен базовый каталог. AT_FDCWD: берём cwd.
	 * Иначе dirfd-относительный путь (так делают coreutils через fts:
	 * unlinkat/fstatat по dirfd) — берём путь каталога из дескриптора.
	 */
	if (dfd == AT_FDCWD) {
		get_fs_pwd(current->fs, &base);
		got = true;
	} else {
		struct fd f = fdget(dfd);

		if (fd_file(f)) {
			base = fd_file(f)->f_path;
			path_get(&base);
			got = true;
		}
		fdput(f);
	}
	if (!got)
		return NULL;

	buf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!buf) {
		path_put(&base);
		return NULL;
	}
	p = d_path(&base, buf, PATH_MAX);
	path_put(&base);
	if (IS_ERR(p)) {
		kfree(buf);
		return NULL;
	}

	lp = strlen(p);
	ln = strlen(name);
	res = kmalloc(lp + 1 + ln + 1, GFP_KERNEL);
	if (res) {
		memcpy(res, p, lp);
		res[lp] = '/';
		memcpy(res + lp + 1, name, ln);
		res[lp + 1 + ln] = '\0';
	}
	kfree(buf);
	return res;
}

bool sb_exists(const char *path)
{
	struct path p;

	if (kern_path(path, LOOKUP_FOLLOW, &p))
		return false;
	path_put(&p);
	return true;
}

/*
 * Существование БЕЗ перехода по финальному симлинку (lstat-семантика): нужно,
 * чтобы детектировать саму теневую ссылку, даже если она «битая»/относительная.
 */
bool sb_lexists(const char *path)
{
	struct path p;

	if (kern_path(path, 0, &p))
		return false;
	path_put(&p);
	return true;
}

/*
 * Псевдо-ФС и устройства не песочим: их перенаправление в обычный теневой файл
 * ломает программы (например, перехват /dev/tty убивает интерактивный shell),
 * а copy-up fifo/устройства может заблокироваться.
 */
bool sb_skip_path(const char *abspath)
{
	static const char *const skip[] = { "/dev", "/proc", "/sys", "/run" };
	size_t i, n;

	if (sb_in_shadow_base(abspath))
		return true;
	for (i = 0; i < ARRAY_SIZE(skip); i++) {
		n = strlen(skip[i]);
		if (!strncmp(abspath, skip[i], n) &&
		    (abspath[n] == '/' || abspath[n] == '\0'))
			return true;
	}
	return false;
}

/*
 * Проверка доступа к пути (для перехвата faccessat). mode — биты R_OK/W_OK/X_OK,
 * которые численно совпадают с MAY_READ/MAY_WRITE/MAY_EXEC. Возвращает 0 при
 * успехе или -errno (-ENOENT, -EACCES). F_OK (mode==0) — только существование.
 */
int sb_check_access(const char *path, int mode)
{
	struct path p;
	int mask, err;

	err = kern_path(path, LOOKUP_FOLLOW, &p);
	if (err)
		return err;
	mask = mode & (MAY_READ | MAY_WRITE | MAY_EXEC);
	err = mask ? inode_permission(&nop_mnt_idmap, d_inode(p.dentry), mask) : 0;
	path_put(&p);
	return err;
}

/* 0 - не существует, 1 - обычный файл, 2 - иное (каталог/устройство/fifo/...). */
int sb_path_kind(const char *abspath)
{
	struct path p;
	umode_t mode;

	if (kern_path(abspath, LOOKUP_FOLLOW, &p))
		return 0;
	mode = d_inode(p.dentry)->i_mode;
	path_put(&p);
	return S_ISREG(mode) ? 1 : 2;
}

/*
 * Если по abspath в тени лежит СИМЛИНК — вернуть его цель абсолютным путём
 * (kmalloc'd; caller kfree). Иначе NULL. Нужно, чтобы переход по песочной
 * ссылке резолвился через песочницу, а не в реальной ФС.
 */
char *sb_resolve_shadow_link(struct sb_ctx *ctx, const char *abspath)
{
	char *data = sb_data_path(ctx, abspath);
	struct path p;
	const char *link;
	char *res = NULL;
	DEFINE_DELAYED_CALL(done);

	if (!data)
		return NULL;
	if (kern_path(data, 0, &p)) {		/* flags=0: не идём по симлинку */
		kfree(data);
		return NULL;
	}
	if (!d_is_symlink(p.dentry))
		goto out;

	link = vfs_get_link(p.dentry, &done);
	if (IS_ERR_OR_NULL(link)) {
		do_delayed_call(&done);
		goto out;
	}

	if (link[0] == '/') {
		res = kstrdup(link, GFP_KERNEL);
	} else {
		/* относительная цель — относительно каталога самого симлинка */
		char *dir = kstrdup(abspath, GFP_KERNEL);

		if (dir) {
			char *sl = strrchr(dir, '/');
			size_t need;

			if (sl && sl != dir)
				*sl = '\0';
			else
				dir[0] = '\0';		/* корень */
			need = strlen(dir) + 1 + strlen(link) + 1;
			res = kmalloc(need, GFP_KERNEL);
			if (res)
				snprintf(res, need, "%s/%s", dir, link);
			kfree(dir);
		}
	}
	do_delayed_call(&done);
out:
	path_put(&p);
	kfree(data);
	return res;
}

static int sb_mkdir_one(const char *path)
{
	struct dentry *dentry;
	struct path parent;
	int err;

	dentry = kern_path_create(AT_FDCWD, path, &parent, LOOKUP_DIRECTORY);
	if (IS_ERR(dentry)) {
		err = PTR_ERR(dentry);
		return err;	/* -EEXIST трактуется вызывающим как успех */
	}
	err = sb_vfs_mkdir_one(d_inode(parent.dentry), dentry, 0777);
	done_path_create(&parent, dentry);
	return err;
}

/* Рекурсивно создать все каталоги пути dir. */
int sb_mkdir_p(const char *dir)
{
	char *tmp;
	size_t i, len;
	int err = 0;

	tmp = kstrdup(dir, GFP_KERNEL);
	if (!tmp)
		return -ENOMEM;
	len = strlen(tmp);

	for (i = 1; i <= len; i++) {
		if (tmp[i] == '/' || tmp[i] == '\0') {
			char c = tmp[i];

			tmp[i] = '\0';
			err = sb_mkdir_one(tmp);
			tmp[i] = c;
			if (err && err != -EEXIST)
				break;
			err = 0;
		}
	}
	kfree(tmp);
	return err;
}

/*
 * Установить права на путь. Нужно, чтобы базовый каталог теневого хранилища
 * был world-writable + sticky (01777, как /tmp): тогда песочницу может
 * запускать любой пользователь, а не только root.
 */
int sb_chmod(const char *path, umode_t mode)
{
	struct path p;
	struct iattr ia;
	int err;

	err = kern_path(path, LOOKUP_FOLLOW, &p);
	if (err)
		return err;
	/* сохраняем биты ТИПА файла (S_IFMT), меняем только права — иначе
	 * notify_change затрёт тип в 0 и stat покажет «weird file» / '?' */
	ia.ia_valid = ATTR_MODE;
	ia.ia_mode = (mode & 07777) | (d_inode(p.dentry)->i_mode & S_IFMT);
	inode_lock(d_inode(p.dentry));
	err = notify_change(&nop_mnt_idmap, p.dentry, &ia, NULL);
	inode_unlock(d_inode(p.dentry));
	path_put(&p);
	return err;
}

/* chown теневого файла (uid/gid == (типа)-1 → не менять соответствующее поле). */
int sb_chown(const char *path, uid_t uid, gid_t gid)
{
	struct path p;
	struct iattr ia;
	int err;

	err = kern_path(path, LOOKUP_FOLLOW, &p);
	if (err)
		return err;
	ia.ia_valid = 0;
	if (uid != (uid_t)-1) {
		ia.ia_valid |= ATTR_UID;
		ia.ia_uid = make_kuid(current_user_ns(), uid);
	}
	if (gid != (gid_t)-1) {
		ia.ia_valid |= ATTR_GID;
		ia.ia_gid = make_kgid(current_user_ns(), gid);
	}
	err = 0;
	if (ia.ia_valid) {
		inode_lock(d_inode(p.dentry));
		err = notify_change(&nop_mnt_idmap, p.dentry, &ia, NULL);
		inode_unlock(d_inode(p.dentry));
	}
	path_put(&p);
	return err;
}

/* Сменить время доступа/модификации теневого файла (utimensat). */
int sb_utimes(const char *path, struct timespec64 *times)
{
	struct path p;
	struct iattr ia;
	int err;

	err = kern_path(path, LOOKUP_FOLLOW, &p);
	if (err)
		return err;
	if (times) {
		ia.ia_valid = ATTR_ATIME | ATTR_ATIME_SET |
			      ATTR_MTIME | ATTR_MTIME_SET;
		ia.ia_atime = times[0];
		ia.ia_mtime = times[1];
	} else {
		ia.ia_valid = ATTR_ATIME | ATTR_MTIME;	/* текущее время */
	}
	inode_lock(d_inode(p.dentry));
	err = notify_change(&nop_mnt_idmap, p.dentry, &ia, NULL);
	inode_unlock(d_inode(p.dentry));
	path_put(&p);
	return err;
}

/*
 * Гарантировать теневую версию объекта (для смены атрибутов): для обычного
 * файла — copy-up, для каталога — создать в тени. Возвращает data-путь
 * (kmalloc'd; caller kfree) или NULL.
 */
char *sb_materialize(struct sb_ctx *ctx, const char *abspath)
{
	char *data = sb_data_path(ctx, abspath);

	if (!data)
		return NULL;
	if (sb_lexists(data))
		return data;			/* уже есть в тени */
	if (sb_path_kind(abspath) == 2)
		sb_mkdir_p(data);		/* каталог/иное — создать в тени */
	else
		sb_copy_up(ctx, abspath, 0);	/* обычный файл — поднять копию */
	return data;
}

int sb_make_shadow_dirs(struct sb_ctx *ctx)
{
	char *data, *wh;
	int err;

	err = sb_mkdir_p(ctx->shadow);
	data = sb_data_path(ctx, "/");	/* ".../data/" */
	wh = sb_wh_path(ctx, "/");
	if (data)
		sb_mkdir_p(data);
	if (wh)
		sb_mkdir_p(wh);
	kfree(data);
	kfree(wh);
	return err;
}

/* Создать родительские каталоги для файла path. */
void sb_mkdir_parent(const char *path)
{
	char *parent = kstrdup(path, GFP_KERNEL);
	char *sl;

	if (!parent)
		return;
	sl = strrchr(parent, '/');
	if (sl && sl != parent) {
		*sl = '\0';
		sb_mkdir_p(parent);
	}
	kfree(parent);
}

/* Скопировать содержимое файла src -> dst (оба пути доступны напрямую). */
int sb_copy_file(const char *src, const char *dst)
{
	struct file *fs, *fd;
	char *buf;
	loff_t rp = 0, wp = 0;
	ssize_t n;
	int err = 0;

	sb_mkdir_parent(dst);

	fd = filp_open(dst, O_CREAT | O_WRONLY | O_TRUNC, 0666);
	if (IS_ERR(fd))
		return PTR_ERR(fd);

	fs = filp_open(src, O_RDONLY, 0);
	if (IS_ERR(fs)) {
		filp_close(fd, NULL);
		return PTR_ERR(fs);
	}

	buf = kmalloc(SB_COPY_BUF, GFP_KERNEL);
	if (!buf) {
		err = -ENOMEM;
		goto out;
	}
	while ((n = kernel_read(fs, buf, SB_COPY_BUF, &rp)) > 0) {
		if (kernel_write(fd, buf, n, &wp) < 0) {
			err = -EIO;
			break;
		}
	}
	kfree(buf);
out:
	filp_close(fs, NULL);
	filp_close(fd, NULL);
	return err;
}

/*
 * Copy-up: гарантировать наличие теневой копии данных для abspath.
 * Если файл уже скопирован/создан - ничего не делает. Чтение оригинала
 * выполняется под bypass, чтобы хук do_filp_open не перенаправил его в тень.
 */
int sb_copy_up(struct sb_ctx *ctx, const char *abspath, int open_flags)
{
	char *data;
	int err = 0;

	data = sb_data_path(ctx, abspath);
	if (!data)
		return -ENOMEM;
	if (sb_exists(data)) {
		kfree(data);
		return 0;
	}

	mutex_lock(&ctx->lock);
	if (sb_exists(data))
		goto out;

	ctx->bypass = current;

	sb_mkdir_parent(data);

	/*
	 * Теневую копию создаём ТОЛЬКО если есть оригинал (его надо «поднять»).
	 * Для нового файла НЕ создаём — иначе редиректнутый open с O_EXCL увидит
	 * уже существующий теневой файл и вернёт EEXIST, ломая атомарное создание
	 * temp-файлов (vim, редакторы, lock-файлы). Новый файл создаст сам
	 * редиректнутый open с нужными флагами.
	 */
	{
		struct file *src = filp_open(abspath, O_RDONLY, 0);

		if (!IS_ERR(src)) {
			/* переносим режим оригинала на тень (umask временно в 0) */
			umode_t omode = file_inode(src)->i_mode & 07777;
			int ou = current->fs->umask;
			struct file *dst;

			current->fs->umask = 0;
			dst = filp_open(data, O_CREAT | O_WRONLY | O_TRUNC,
					omode ? omode : 0644);
			current->fs->umask = ou;

			if (IS_ERR(dst)) {
				err = PTR_ERR(dst);
			} else {
				/* при O_TRUNC контент не нужен — будет обнулён */
				if (!(open_flags & O_TRUNC)) {
					char *buf = kmalloc(SB_COPY_BUF, GFP_KERNEL);
					loff_t rp = 0, wp = 0;
					ssize_t n;

					if (buf) {
						while ((n = kernel_read(src, buf,
									SB_COPY_BUF, &rp)) > 0)
							kernel_write(dst, buf, n, &wp);
						kfree(buf);
					}
				}
				filp_close(dst, NULL);
				/*
				 * Права/владельца оригинала на тень НЕ переносим:
				 * notify_change на свежесозданной теневой копии
				 * давал EINVAL на последующем open. Теневой файл
				 * остаётся за создателем — этого достаточно.
				 */
			}
			filp_close(src, NULL);
		}
	}

	ctx->bypass = NULL;
out:
	mutex_unlock(&ctx->lock);
	kfree(data);
	return err;
}

/* Удалить файл по абсолютному пути (используется для shadow/wh файлов). */
int sb_unlink_path(const char *path)
{
	struct path parent;
	struct dentry *dentry;
	const char *base;
	char *dir;
	int err;
	const char *sl = strrchr(path, '/');

	if (!sl)
		return -EINVAL;
	base = sl + 1;
	if (*base == '\0')
		return -EINVAL;

	dir = kstrndup(path, (sl == path) ? 1 : (size_t)(sl - path), GFP_KERNEL);
	if (!dir)
		return -ENOMEM;
	if (sl == path)
		dir[0] = '/';

	err = kern_path(dir, LOOKUP_DIRECTORY, &parent);
	kfree(dir);
	if (err)
		return err;

	inode_lock_nested(d_inode(parent.dentry), I_MUTEX_PARENT);
	dentry = sb_lookup_child(parent.dentry, base);
	if (IS_ERR(dentry)) {
		err = PTR_ERR(dentry);
		goto unlock;
	}
	if (d_really_is_negative(dentry)) {
		err = -ENOENT;
		dput(dentry);
		goto unlock;
	}
	err = vfs_unlink(&nop_mnt_idmap, d_inode(parent.dentry), dentry, NULL);
	dput(dentry);
unlock:
	inode_unlock(d_inode(parent.dentry));
	path_put(&parent);
	return err;
}

bool sb_is_whiteout(struct sb_ctx *ctx, const char *abspath)
{
	char *wh = sb_wh_path(ctx, abspath);
	bool r;

	if (!wh)
		return false;
	/*
	 * Маркер whiteout - это обычный ФАЙЛ. Промежуточные каталоги в wh/
	 * (родители маркеров) - это директории, и они НЕ означают удаление.
	 * Иначе stat("/home") после удаления "/home/.../x" ложно даёт ENOENT.
	 */
	r = (sb_path_kind(wh) == 1);
	kfree(wh);
	return r;
}

int sb_make_whiteout(struct sb_ctx *ctx, const char *abspath)
{
	char *wh = sb_wh_path(ctx, abspath);
	char *data;
	struct file *f;
	int err;

	if (!wh)
		return -ENOMEM;

	/* убрать теневые данные, если были (lexists — чтобы снять и симлинк) */
	data = sb_data_path(ctx, abspath);
	if (data) {
		if (sb_lexists(data))
			sb_unlink_path(data);
		kfree(data);
	}

	sb_mkdir_parent(wh);
	f = filp_open(wh, O_CREAT | O_WRONLY, 0600);
	if (IS_ERR(f)) {
		err = PTR_ERR(f);
		err = (err == -EEXIST) ? 0 : err;
	} else {
		filp_close(f, NULL);
		err = 0;
	}
	kfree(wh);
	return err;
}

int sb_clear_whiteout(struct sb_ctx *ctx, const char *abspath)
{
	char *wh = sb_wh_path(ctx, abspath);
	int err;

	if (!wh)
		return -ENOMEM;
	err = sb_exists(wh) ? sb_unlink_path(wh) : 0;
	kfree(wh);
	return err;
}
