/*
 * Интерфейс управления через procfs:
 *   echo "add <pid>" > /proc/sandbox/control   - начать эмулировать процесс
 *   echo "del <pid>" > /proc/sandbox/control   - прекратить
 *   cat /proc/sandbox/status                    - список песочниц и счётчики
 */
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

#include "sandbox.h"

static struct proc_dir_entry *sb_dir;

static ssize_t sb_ctrl_write(struct file *file, const char __user *ubuf,
			     size_t len, loff_t *ppos)
{
	char buf[64];
	char cmd[8];
	int pid;
	int n;

	if (len == 0 || len >= sizeof(buf))
		return -EINVAL;
	if (copy_from_user(buf, ubuf, len))
		return -EFAULT;
	buf[len] = '\0';

	n = sscanf(buf, "%7s %d", cmd, &pid);
	if (n != 2 || pid <= 0)
		return -EINVAL;

	if (!strcmp(cmd, "add")) {
		int err = sb_add((pid_t)pid);

		if (err && err != -EEXIST)
			return err;
	} else if (!strcmp(cmd, "del")) {
		int err = sb_del((pid_t)pid);

		if (err && err != -ENOENT)
			return err;
	} else {
		return -EINVAL;
	}
	return len;
}

static void sb_status_line(struct sb_ctx *ctx, void *arg)
{
	struct seq_file *m = arg;

	seq_printf(m, "pid=%d gid=%d open=%ld unlink=%ld stat=%ld other=%ld shadow=%s\n",
		   ctx->pid, ctx->gid,
		   atomic_long_read(&ctx->n_open),
		   atomic_long_read(&ctx->n_unlink),
		   atomic_long_read(&ctx->n_stat),
		   atomic_long_read(&ctx->n_other),
		   ctx->shadow);
}

static int sb_status_show(struct seq_file *m, void *v)
{
	seq_puts(m, "# sandboxed processes\n");
	sb_for_each(sb_status_line, m);
	return 0;
}

static int sb_status_open(struct inode *inode, struct file *file)
{
	return single_open(file, sb_status_show, NULL);
}

static const struct proc_ops sb_ctrl_ops = {
	.proc_write = sb_ctrl_write,
	.proc_lseek = noop_llseek,
};

static const struct proc_ops sb_status_ops = {
	.proc_open = sb_status_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

int sb_proc_init(void)
{
	sb_dir = proc_mkdir("sandbox", NULL);
	if (!sb_dir)
		return -ENOMEM;

	if (!proc_create("control", 0777, sb_dir, &sb_ctrl_ops))
		goto fail;
	if (!proc_create("status", 0777, sb_dir, &sb_status_ops))
		goto fail;
	return 0;

fail:
	remove_proc_subtree("sandbox", NULL);
	sb_dir = NULL;
	return -ENOMEM;
}

void sb_proc_exit(void)
{
	if (sb_dir) {
		remove_proc_subtree("sandbox", NULL);
		sb_dir = NULL;
	}
}
