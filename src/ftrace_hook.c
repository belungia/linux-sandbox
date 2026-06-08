#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/ftrace.h>
#include <linux/kernel.h>

#include "ftrace_hook.h"

/*
 * Разрешение адреса символа по имени через временный kprobe
 * Работает для любых символов в kallsyms (KALLSYMS_ALL=y), включая
 * неэкспортируемые (do_filp_open, vfs_statx, ...).
 */
unsigned long fh_lookup_name(const char *name)
{
	struct kprobe kp = { .symbol_name = name };
	unsigned long addr;

	if (register_kprobe(&kp) < 0)
		return 0;
	addr = (unsigned long)kp.addr;
	unregister_kprobe(&kp);
	return addr;
}

/* ftrace-коллбэк: подменяем точку возврата только для вызовов извне модуля. */
static void notrace fh_callback(unsigned long ip, unsigned long parent_ip,
				struct ftrace_ops *ops,
				struct ftrace_regs *fregs)
{
	struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);
	struct pt_regs *regs = ftrace_get_regs(fregs);

	if (!regs)
		return;
	/*
	 * Если вызов пришёл из нашего модуля (через указатель original) -
	 * не трогаем ip: исполняется оригинальная функция. Иначе перенаправляем
	 * на replacement.
	 */
	if (!within_module(parent_ip, THIS_MODULE))
		regs->ip = (unsigned long)hook->function;
}

int fh_install(struct ftrace_hook *hook)
{
	int err;

	hook->address = fh_lookup_name(hook->name);
	if (!hook->address) {
		pr_err("sandbox: символ не найден: %s\n", hook->name);
		return -ENOENT;
	}

	/* original -> адрес функции (трамплин для вызова оригинала) */
	*((unsigned long *)hook->original) = hook->address;

	hook->ops.func = fh_callback;
	hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS |
			  FTRACE_OPS_FL_RECURSION |
			  FTRACE_OPS_FL_IPMODIFY;

	err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
	if (err) {
		pr_err("sandbox: ftrace_set_filter_ip(%s) = %d\n",
		       hook->name, err);
		return err;
	}

	err = register_ftrace_function(&hook->ops);
	if (err) {
		pr_err("sandbox: register_ftrace_function(%s) = %d\n",
		       hook->name, err);
		ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
		return err;
	}

	pr_info("sandbox: хук установлен: %s @ %px\n",
		hook->name, (void *)hook->address);
	return 0;
}

void fh_remove(struct ftrace_hook *hook)
{
	if (!hook->address)
		return;
	unregister_ftrace_function(&hook->ops);
	ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
	hook->address = 0;
}

int fh_install_all(struct ftrace_hook *hooks, size_t count)
{
	size_t i;
	int err;

	for (i = 0; i < count; i++) {
		err = fh_install(&hooks[i]);
		if (err)
			goto rollback;
	}
	return 0;

rollback:
	while (i-- > 0)
		fh_remove(&hooks[i]);
	return err;
}

void fh_remove_all(struct ftrace_hook *hooks, size_t count)
{
	size_t i;

	for (i = 0; i < count; i++)
		fh_remove(&hooks[i]);
}
