/*
 * Типовой ftrace-хелпер: перехват функций ядра без подмены sys_call_table.
 * Адрес символа резолвится через временный kprobe (kallsyms_lookup_name
 * не экспортируется с 5.7). В коллбэке переписываем regs->ip на нашу
 * replacement-функцию; вызов оригинала идёт через сохранённый указатель.
 */
#ifndef _SANDBOX_FTRACE_HOOK_H
#define _SANDBOX_FTRACE_HOOK_H

#include <linux/ftrace.h>

struct ftrace_hook {
	const char *name;	/* имя перехватываемой функции в kallsyms */
	void *function;		/* наша замена */
	void *original;		/* &указатель-на-оригинал (туда запишем адрес) */

	unsigned long address;	/* разрешённый адрес функции */
	struct ftrace_ops ops;
};

#define HOOK(_name, _func, _orig) \
	{ .name = (_name), .function = (_func), .original = (_orig) }

unsigned long fh_lookup_name(const char *name);
int  fh_install(struct ftrace_hook *hook);
void fh_remove(struct ftrace_hook *hook);
int  fh_install_all(struct ftrace_hook *hooks, size_t count);
void fh_remove_all(struct ftrace_hook *hooks, size_t count);

#endif /* _SANDBOX_FTRACE_HOOK_H */
