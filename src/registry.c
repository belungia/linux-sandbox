/*
 * Реестр песочниц: хеш-таблица tgid -> sb_ctx.
 * Неограниченное число независимых процессов: таблица динамическая,
 * у каждого tgid свой shadow-root
 */
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/hashtable.h>

#include "sandbox.h"

static DEFINE_HASHTABLE(sb_table, SB_HASH_BITS);
static DEFINE_SPINLOCK(sb_table_lock);

int sb_registry_init(void)
{
	hash_init(sb_table);
	return 0;
}

struct sb_ctx *sb_get(pid_t tgid)
{
	struct sb_ctx *c, *found = NULL;
	unsigned long flags;

	spin_lock_irqsave(&sb_table_lock, flags);
	hash_for_each_possible(sb_table, c, hnode, tgid) {
		if (c->pid == tgid) {
			refcount_inc(&c->ref);
			found = c;
			break;
		}
	}
	spin_unlock_irqrestore(&sb_table_lock, flags);
	return found;
}

struct sb_ctx *sb_get_current(void)
{
	return sb_get(current->tgid);
}

void sb_put(struct sb_ctx *ctx)
{
	if (ctx && refcount_dec_and_test(&ctx->ref)) {
		mutex_destroy(&ctx->lock);
		kfree(ctx);
	}
}

/*
 * Общая логика добавления. mkdirs=true и GFP_KERNEL - для пути из procfs
 * (sleepable). Для наследования при fork (атомарный контекст kprobe) - gfp
 * GFP_ATOMIC, mkdirs=false (каталоги уже созданы родителем-группой).
 */
static int __sb_add(pid_t tgid, pid_t gid, const char *shadow,
		    gfp_t gfp, bool mkdirs)
{
	struct sb_ctx *c, *ex, *it;
	unsigned long flags;

	ex = sb_get(tgid);
	if (ex) {
		sb_put(ex);
		return -EEXIST;
	}

	c = kzalloc(sizeof(*c), gfp);
	if (!c)
		return -ENOMEM;

	c->pid = tgid;
	c->gid = gid;
	if (shadow)
		strscpy(c->shadow, shadow, sizeof(c->shadow));
	else
		snprintf(c->shadow, sizeof(c->shadow), "%s/%d",
			 SB_SHADOW_BASE, gid);
	mutex_init(&c->lock);
	refcount_set(&c->ref, 1);
	c->bypass = NULL;
	atomic_long_set(&c->n_open, 0);
	atomic_long_set(&c->n_unlink, 0);
	atomic_long_set(&c->n_stat, 0);
	atomic_long_set(&c->n_other, 0);

	if (mkdirs)
		sb_make_shadow_dirs(c);

	spin_lock_irqsave(&sb_table_lock, flags);
	hash_for_each_possible(sb_table, it, hnode, tgid) {
		if (it->pid == tgid) {
			spin_unlock_irqrestore(&sb_table_lock, flags);
			sb_put(c);
			return -EEXIST;
		}
	}
	hash_add(sb_table, &c->hnode, tgid);
	spin_unlock_irqrestore(&sb_table_lock, flags);

	pr_info("sandbox: + tgid=%d gid=%d shadow=%s\n", tgid, gid, c->shadow);
	return 0;
}

int sb_add(pid_t tgid)
{
	return __sb_add(tgid, tgid, NULL, GFP_KERNEL, true);
}

/* Добавить ребёнка в существующую группу (общий shadow). Атомарный контекст. */
int sb_add_member(pid_t tgid, pid_t gid, const char *shadow)
{
	return __sb_add(tgid, gid, shadow, GFP_ATOMIC, false);
}

int sb_del(pid_t tgid)
{
	struct sb_ctx *c = NULL, *it;
	unsigned long flags;

	spin_lock_irqsave(&sb_table_lock, flags);
	hash_for_each_possible(sb_table, it, hnode, tgid) {
		if (it->pid == tgid) {
			c = it;
			hash_del(&c->hnode);
			break;
		}
	}
	spin_unlock_irqrestore(&sb_table_lock, flags);

	if (!c)
		return -ENOENT;

	pr_info("sandbox: - tgid=%d\n", tgid);
	sb_put(c);	/* снять ссылку таблицы */
	return 0;
}

void sb_for_each(void (*fn)(struct sb_ctx *, void *), void *arg)
{
	struct sb_ctx *c;
	unsigned long flags;
	int bkt;

	spin_lock_irqsave(&sb_table_lock, flags);
	hash_for_each(sb_table, bkt, c, hnode)
		fn(c, arg);
	spin_unlock_irqrestore(&sb_table_lock, flags);
}

void sb_registry_exit(void)
{
	struct sb_ctx *c;
	struct hlist_node *tmp;
	unsigned long flags;
	int bkt;

	spin_lock_irqsave(&sb_table_lock, flags);
	hash_for_each_safe(sb_table, bkt, tmp, c, hnode) {
		hash_del(&c->hnode);
		sb_put(c);
	}
	spin_unlock_irqrestore(&sb_table_lock, flags);
}
