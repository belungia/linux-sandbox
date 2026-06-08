/*
 * Модуль перехватывает VFS-операции записи песочных процессов и перенаправляет
 * их в теневое хранилище (copy-up / whiteout), создавая иллюзию изменений ФС
 * без реальных модификаций. Управление - через /proc/sandbox.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>

#include "sandbox.h"

/* Очистка реестра при завершении процесса (последний поток группы). */
static int sb_exit_pre(struct kprobe *p, struct pt_regs *regs)
{
	if (thread_group_empty(current))
		sb_del(current->tgid);
	return 0;
}

static struct kprobe sb_exit_kp = {
	.symbol_name = "do_exit",
	.pre_handler = sb_exit_pre,
};

/*
 * Наследование песочницы при fork (доп.задание - группы): если родитель
 * (current) песочный, новый процесс добавляется в ту же группу с общим
 * shadow-хранилищем, поэтому родственные процессы видят одно состояние.
 * Контекст атомарный (preempt off) - sb_add_member использует GFP_ATOMIC и
 * не трогает VFS.
 */
static int sb_fork_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct task_struct *child;
	struct sb_ctx *parent;

	/* wake_up_new_task(struct task_struct *p): первый аргумент - новый таск */
	child = (struct task_struct *)regs_get_kernel_argument(regs, 0);
	if (!child)
		return 0;

	parent = sb_get(current->tgid);
	if (parent) {
		/* только новый процесс (новый tgid); новый поток уже покрыт tgid */
		if (child->tgid != current->tgid)
			sb_add_member(child->tgid, parent->gid, parent->shadow);
		sb_put(parent);
	}
	return 0;
}

static struct kprobe sb_fork_kp = {
	.symbol_name = "wake_up_new_task",
	.pre_handler = sb_fork_pre,
};

static int __init sandbox_init(void)
{
	int err;
	sb_mkdir_p(SB_SHADOW_BASE);
	sb_chmod(SB_SHADOW_BASE, 01777);

	err = sb_registry_init();
	if (err)
		return err;

	err = sb_proc_init();
	if (err)
		goto err_proc;

	err = sb_hooks_install();
	if (err)
		goto err_hooks;

	err = register_kprobe(&sb_exit_kp);
	if (err)
		goto err_exit_kp;

	err = register_kprobe(&sb_fork_kp);
	if (err)
		goto err_fork_kp;

	pr_info("sandbox: загружен (interface: /proc/sandbox)\n");
	return 0;

err_fork_kp:
	unregister_kprobe(&sb_exit_kp);
err_exit_kp:
	sb_hooks_remove();
err_hooks:
	sb_proc_exit();
err_proc:
	sb_registry_exit();
	return err;
}

static void __exit sandbox_exit(void)
{
	unregister_kprobe(&sb_fork_kp);
	unregister_kprobe(&sb_exit_kp);
	sb_hooks_remove();
	sb_proc_exit();
	sb_registry_exit();
	pr_info("sandbox: выгружен\n");
}

module_init(sandbox_init);
module_exit(sandbox_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("task8");
MODULE_DESCRIPTION("Per-process filesystem sandbox via ftrace VFS hooks + copy-up shadow");
MODULE_VERSION("0.1");
