/*
 * Copyright (C) 2014 Seth Jennings <sjenning@redhat.com>
 * Copyright (C) 2013-2014 Josh Poimboeuf <jpoimboe@redhat.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/*
 * kpatch core module for RHEL6
 *
 * Patch modules register with this module to redirect old functions to new
 * functions.
 *
 * For each function patched by the module we must:
 * - Call stop_machine
 * - Ensure that no task has the old function in its call stack
 * - Hard code the jmp rel32 instruction at function entry point
 *
 * After that, each call to the old function jumps to the new, patched version
 * of the function.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/stop_machine.h>
#include <linux/ftrace.h>
#include <linux/hashtable.h>
#include <linux/hardirq.h>
#include <linux/uaccess.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include <linux/string.h>
#include <asm/stacktrace.h>
#include <asm/cacheflush.h>
#include <linux/utsrelease.h>
#include "kpatch.h"

#ifndef UTS_UBUNTU_RELEASE_ABI
#define UTS_UBUNTU_RELEASE_ABI 0
#endif

#if	!defined(CONFIG_MODULES) || \
	!defined(CONFIG_SYSFS) || \
	!defined(CONFIG_KALLSYMS_ALL)
#error "CONFIG_MODULES, CONFIG_SYSFS, CONFIG_KALLSYMS_ALL kernel config options are required"
#endif

#define KPATCH_HASH_BITS 8
static DEFINE_HASHTABLE(kpatch_func_hash, KPATCH_HASH_BITS);

static DECLARE_MUTEX(kpatch_mutex);

static LIST_HEAD(kpmod_list);

static struct kobject *kpatch_root_kobj;
struct kobject *kpatch_patches_kobj;
EXPORT_SYMBOL_GPL(kpatch_patches_kobj);

struct kpatch_backtrace_args {
	struct kpatch_module *kpmod;
	int ret;
};

struct kpatch_kallsyms_args {
	const char *objname;
	const char *name;
	unsigned long addr;
	unsigned long count;
	unsigned long pos;
};

void (*kpatch_set_kernel_text_ro)(void);
void (*kpatch_set_kernel_text_rw)(void);

/* this is a double loop, use goto instead of break */
#define do_for_each_linked_func(kpmod, func) {				\
	struct kpatch_object *_object;					\
	list_for_each_entry(_object, &kpmod->objects, list) {		\
		if (!kpatch_object_linked(_object))			\
			continue;					\
		list_for_each_entry(func, &_object->funcs, list) {

#define while_for_each_linked_func()					\
		}							\
	}								\
}

/* provides access to object if needed. object is cursor */
#define do_for_each_linked_obj_func(kpmod, object, func) {		\
	list_for_each_entry(object, &kpmod->objects, list) {		\
		if (!kpatch_object_linked(object))			\
			continue;					\
		list_for_each_entry(func, &object->funcs, list) {

#define while_for_each_linked_func()					\
		}							\
	}								\
}

/*
 * The kpatch core module has a state machine which allows for proper
 * synchronization with kpatch_ftrace_handler() when it runs in NMI context.
 *
 *         +-----------------------------------------------------+
 *         |                                                     |
 *         |                                                     +
 *         v                                     +---> KPATCH_STATE_SUCCESS
 * KPATCH_STATE_IDLE +---> KPATCH_STATE_UPDATING |
 *         ^                                     +---> KPATCH_STATE_FAILURE
 *         |                                                     +
 *         |                                                     |
 *         +-----------------------------------------------------+
 *
 * KPATCH_STATE_IDLE: No updates are pending.  The func hash is valid, and the
 * reader doesn't need to check func->op.
 *
 * KPATCH_STATE_UPDATING: An update is in progress.  The reader must call
 * kpatch_state_finish(KPATCH_STATE_FAILURE) before accessing the func hash.
 *
 * KPATCH_STATE_FAILURE: An update failed, and the func hash might be
 * inconsistent (pending patched funcs might not have been removed yet).  If
 * func->op is KPATCH_OP_PATCH, then rollback to the previous version of the
 * func.
 *
 * KPATCH_STATE_SUCCESS: An update succeeded, but the func hash might be
 * inconsistent (pending unpatched funcs might not have been removed yet).  If
 * func->op is KPATCH_OP_UNPATCH, then rollback to the previous version of the
 * func.
 */
enum {
	KPATCH_STATE_IDLE,
	KPATCH_STATE_UPDATING,
	KPATCH_STATE_SUCCESS,
	KPATCH_STATE_FAILURE,
};
static atomic_t kpatch_state;

static inline void kpatch_state_idle(void)
{
	int state = atomic_read(&kpatch_state);

	WARN_ON(state != KPATCH_STATE_SUCCESS && state != KPATCH_STATE_FAILURE);
	atomic_set(&kpatch_state, KPATCH_STATE_IDLE);
}

static inline void kpatch_state_updating(void)
{
	WARN_ON(atomic_read(&kpatch_state) != KPATCH_STATE_IDLE);
	atomic_set(&kpatch_state, KPATCH_STATE_UPDATING);
}

/* If state is updating, change it to success or failure and return new state */
static inline int kpatch_state_finish(int state)
{
	int result;

	WARN_ON(state != KPATCH_STATE_SUCCESS && state != KPATCH_STATE_FAILURE);
	result = atomic_cmpxchg(&kpatch_state, KPATCH_STATE_UPDATING, state);
	return result == KPATCH_STATE_UPDATING ? state : result;
}

static struct kpatch_func *kpatch_get_func(unsigned long ip)
{
	struct kpatch_func *f;
	struct hlist_node *list;

	/* Here, we have to use rcu safe hlist because of NMI concurrency */
	hash_for_each_possible_rcu(kpatch_func_hash, f, list, node, ip) {
		if (f->old_addr == ip)
			return f;
	}

	return NULL;
}

static inline bool kpatch_object_linked(struct kpatch_object *object)
{
	return object->mod || !strcmp(object->name, "vmlinux");
}

static inline int kpatch_compare_addresses(unsigned long stack_addr,
					   unsigned long func_addr,
					   unsigned long func_size,
					   const char *func_name)
{
	if (stack_addr >= func_addr && stack_addr < func_addr + func_size) {
		pr_err("activeness safety check failed for %s\n", func_name);
		return -EBUSY;
	}
	return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 6, 0)
#define BACKTRACE_ADDRESS_VERIFY_RETURN_TYPE void
#define BACKTRACE_ADDRESS_VERIFY_RETURN_ARG
#else
#define BACKTRACE_ADDRESS_VERIFY_RETURN_TYPE int
#define BACKTRACE_ADDRESS_VERIFY_RETURN_ARG args->ret
#endif

static BACKTRACE_ADDRESS_VERIFY_RETURN_TYPE
kpatch_backtrace_address_verify(void *data, unsigned long address, int reliable)
{
	struct kpatch_backtrace_args *args = data;
	struct kpatch_module *kpmod = args->kpmod;
	struct kpatch_func *func;
	struct hlist_node *list;
	int i;

	if (args->ret)
		return BACKTRACE_ADDRESS_VERIFY_RETURN_ARG;

	/* check kpmod funcs */
	do_for_each_linked_func(kpmod, func) {
		unsigned long func_addr, func_size;
		const char *func_name;
		struct kpatch_func *active_func;

		if (func->force)
			continue;

		active_func = kpatch_get_func(func->old_addr);
		if (!active_func) {
			/* patching an unpatched func */
			func_addr = func->old_addr;
			func_size = func->old_size;
			func_name = func->name;
		} else {
			/* repatching or unpatching */
			func_addr = active_func->new_addr;
			func_size = active_func->new_size;
			func_name = active_func->name;
		}

		args->ret = kpatch_compare_addresses(address, func_addr,
						     func_size, func_name);
		if (args->ret)
			return BACKTRACE_ADDRESS_VERIFY_RETURN_ARG;
	} while_for_each_linked_func();

	/* in the replace case, need to check the func hash as well */
	hash_for_each_rcu(kpatch_func_hash, i, list, func, node) {
		if (func->op == KPATCH_OP_UNPATCH && !func->force) {
			args->ret = kpatch_compare_addresses(address,
							     func->new_addr,
							     func->new_size,
							     func->name);
			if (args->ret)
				return BACKTRACE_ADDRESS_VERIFY_RETURN_ARG;
		}
	}

	return BACKTRACE_ADDRESS_VERIFY_RETURN_ARG;
}

static int kpatch_backtrace_stack(void *data, char *name)
{
	return 0;
}

static const struct stacktrace_ops kpatch_backtrace_ops = {
	.address	= kpatch_backtrace_address_verify,
	.stack		= kpatch_backtrace_stack,
	.walk_stack	= print_context_stack_bp,
};

static int kpatch_print_trace_stack(void *data, char *name)
{
	pr_cont(" <%s> ", name);
	return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 6, 0)
static void kpatch_print_trace_address(void *data, unsigned long addr,
				       int reliable)
{
	if (reliable)
		pr_info("[<%p>] %pB\n", (void *)addr, (void *)addr);
}
#else
static int kpatch_print_trace_address(void *data, unsigned long addr,
				       int reliable)
{
	if (reliable)
		pr_info("[<%p>] %pB\n", (void *)addr, (void *)addr);

	return 0;
}
#endif

static const struct stacktrace_ops kpatch_print_trace_ops = {
	.stack		= kpatch_print_trace_stack,
	.address	= kpatch_print_trace_address,
	.walk_stack	= print_context_stack,
};

/*
 * Verify activeness safety, i.e. that none of the to-be-patched functions are
 * on the stack of any task.
 *
 * This function is called from stop_machine() context.
 */
static int kpatch_verify_activeness_safety(struct kpatch_module *kpmod)
{
	struct task_struct *g, *t;
	int ret = 0;

	struct kpatch_backtrace_args args = {
		.kpmod = kpmod,
		.ret = 0
	};

	/* Check the stacks of all tasks. */
	do_each_thread(g, t) {
		dump_trace(t, NULL, NULL, &kpatch_backtrace_ops, (void *)&args);
		if (args.ret) {
			ret = args.ret;
			pr_info("PID: %d Comm: %.20s\n", t->pid, t->comm);
			dump_trace(t, NULL, (unsigned long *)t->thread.sp,
				   &kpatch_print_trace_ops, (void *)NULL);
			goto out;
		}
	} while_each_thread(g, t);

out:
	return ret;
}

static int kpatch_insert_jmpinstr(struct kpatch_object *object,
				  struct kpatch_func *func)
{
	char jmpinstr[5];
	signed int target;
	unsigned long loc;
	bool vmlinux;
	int numpages;

	vmlinux = !strcmp(object->name, "vmlinux");

	if (probe_kernel_read((void *)func->oldinstr, (void *)func->old_addr, 5))
		return -EFAULT;

	/*
	 * If originally unpatched, prologue starts with
	 *    push %rbp (0x55)
	 * If already patched, prologue starts with
	 *    jmp <offset> (0xe9)
	 */
	if (!func->oldinstr[0] == 0x55 || !func->oldinstr[0] == 0xe9) {
		pr_err("Not at a function entry point?\n");
		return -EINVAL;
	}

	/* jmp rel32 offset */
	target = func->new_addr - (func->old_addr + 5);

	jmpinstr[0] = 0xe9;
	jmpinstr[1] = (char) (target & 0xff);
	jmpinstr[2] = (char) ((target >> 8) & 0xff);
	jmpinstr[3] = (char) ((target >> 16) & 0xff);
	jmpinstr[4] = (char) ((target >> 24) & 0xff);

	numpages = (PAGE_SIZE - (func->old_addr & ~PAGE_MASK) >= sizeof(jmpinstr)) ? 1 : 2;

	/*
	 * On x86_64, kernel text mappings are mapped read-only, so we use
	 * the kernel identity mapping instead of the kernel text mapping
	 * to modify the kernel text.
	 *
	 * Modify code directly, similar to how ftrace does it.
	 */
	if (vmlinux)
		loc = (unsigned long)__va(__pa(func->old_addr));
	else
		loc = func->old_addr;

        if (probe_kernel_write((void *)loc, (void *)jmpinstr, sizeof(jmpinstr)))
                return -EPERM;

	return 0;
}

static int kpatch_restore_oldinstr(struct kpatch_object *object,
				   struct kpatch_func *func)
{
	unsigned long loc;
	bool vmlinux;
	int numpages;

	vmlinux = !strcmp(object->name, "vmlinux");
	numpages = (PAGE_SIZE - (func->old_addr & ~PAGE_MASK) >= sizeof(func->oldinstr)) ? 1 : 2;

	if (vmlinux)
		loc = (unsigned long)__va(__pa(func->old_addr));
	else
		loc = func->old_addr;

	if (probe_kernel_write((void *)loc, (void *)func->oldinstr, sizeof(func->oldinstr)))
		return -EPERM;

	return 0;
}

/* Called from stop_machine */
static int kpatch_apply_patch(void *data)
{
	struct kpatch_module *kpmod = data;
	struct kpatch_func *func;
	struct kpatch_hook *hook;
	struct kpatch_object *object;
	int ret;

	ret = kpatch_verify_activeness_safety(kpmod);
	if (ret) {
		kpatch_state_finish(KPATCH_STATE_FAILURE);
		return ret;
	}

	/* tentatively add the new funcs to the global func hash */
	do_for_each_linked_obj_func(kpmod, object, func) {
		ret = kpatch_insert_jmpinstr(object, func);
		if (ret)
			return ret;
		hash_add_rcu(kpatch_func_hash, &func->node, func->old_addr);
	} while_for_each_linked_func();

	/* memory barrier between func hash add and state change */
	smp_wmb();

	/*
	 * Check if any inconsistent NMI has happened while updating.  If not,
	 * move to success state.
	 */
	ret = kpatch_state_finish(KPATCH_STATE_SUCCESS);
	if (ret == KPATCH_STATE_FAILURE) {
		pr_err("NMI activeness safety check failed\n");

		/* Failed, we have to rollback patching process */
		do_for_each_linked_obj_func(kpmod, object, func) {
			ret = kpatch_restore_oldinstr(object, func);
			if (ret)
				return ret;
			hash_del_rcu(&func->node);
		} while_for_each_linked_func();

		return -EBUSY;
	}

	/* run any user-defined load hooks */
	list_for_each_entry(object, &kpmod->objects, list) {
		if (!kpatch_object_linked(object))
			continue;
		list_for_each_entry(hook, &object->hooks_load, list)
			(*hook->hook)();
	}

	return 0;
}

static int kpatch_kallsyms_callback(void *data, const char *name,
					 struct module *mod,
					 unsigned long addr)
{
	struct kpatch_kallsyms_args *args = data;
	bool vmlinux = !strcmp(args->objname, "vmlinux");

	if ((mod && vmlinux) || (!mod && !vmlinux))
		return 0;

	if (strcmp(args->name, name))
		return 0;

	if (!vmlinux && strcmp(args->objname, mod->name))
		return 0;

	args->addr = addr;
	args->count++;

	/*
	 * Finish the search when the symbol is found for the desired position
	 * or the position is not defined for a non-unique symbol.
	 */
	if ((args->pos && (args->count == args->pos)) ||
	    (!args->pos && (args->count > 1))) {
		return 1;
	}

	return 0;
}

static int kpatch_find_object_symbol(const char *objname, const char *name,
				     unsigned long sympos, unsigned long *addr)
{
	struct kpatch_kallsyms_args args = {
		.objname = objname,
		.name = name,
		.addr = 0,
		.count = 0,
		.pos = sympos,
	};

	mutex_lock(&module_mutex);
	kallsyms_on_each_symbol(kpatch_kallsyms_callback, &args);
	mutex_unlock(&module_mutex);

	/*
	 * Ensure an address was found. If sympos is 0, ensure symbol is unique;
	 * otherwise ensure the symbol position count matches sympos.
	 */
	if (args.addr == 0)
		pr_err("symbol '%s' not found in symbol table\n", name);
	else if (args.count > 1 && sympos == 0) {
		pr_err("unresolvable ambiguity for symbol '%s' in object '%s'\n",
		       name, objname);
	} else if (sympos != args.count && sympos > 0) {
		pr_err("symbol position %lu for symbol '%s' in object '%s' not found\n",
		       sympos, name, objname);
	} else {
		*addr = args.addr;
		return 0;
	}

	*addr = 0;
	return -EINVAL;
}

/*
 * External symbols are located outside the parent object (where the parent
 * object is either vmlinux or the kmod being patched).
 */
static int kpatch_find_external_symbol(const char *objname, const char *name,
				       unsigned long sympos, unsigned long *addr)

{
	const struct kernel_symbol *sym;

	/* first, check if it's an exported symbol */
	preempt_disable();
	sym = find_symbol(name, NULL, NULL, true, true);
	preempt_enable();
	if (sym) {
		*addr = sym->value;
		return 0;
	}

	/* otherwise check if it's in another .o within the patch module */
	return kpatch_find_object_symbol(objname, name, sympos, addr);
}

static int kpatch_write_relocations(struct kpatch_module *kpmod,
				    struct kpatch_object *object)
{
	int ret, size, readonly = 0, numpages;
	struct kpatch_dynrela *dynrela;
	u64 loc, val;
#if (( LINUX_VERSION_CODE >= KERNEL_VERSION(4, 5, 0) ) || \
     ( LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0) && \
      UTS_UBUNTU_RELEASE_ABI >= 7 ) \
    )
	unsigned long core = (unsigned long)kpmod->mod->core_layout.base;
	unsigned long core_size = kpmod->mod->core_layout.size;
#else
	unsigned long core = (unsigned long)kpmod->mod->module_core;
	unsigned long core_size = kpmod->mod->core_size;
#endif

	list_for_each_entry(dynrela, &object->dynrelas, list) {
		if (dynrela->external)
			ret = kpatch_find_external_symbol(kpmod->mod->name,
							  dynrela->name,
							  dynrela->sympos,
							  &dynrela->src);
		else
			ret = kpatch_find_object_symbol(object->name,
							dynrela->name,
							dynrela->sympos,
							&dynrela->src);
		if (ret) {
			pr_err("unable to find symbol '%s'\n", dynrela->name);
			return ret;
		}

		switch (dynrela->type) {
		case R_X86_64_NONE:
			continue;
		case R_X86_64_PC32:
			loc = dynrela->dest;
			val = (u32)(dynrela->src + dynrela->addend -
				    dynrela->dest);
			size = 4;
			break;
		case R_X86_64_32S:
			loc = dynrela->dest;
			val = (s32)dynrela->src + dynrela->addend;
			size = 4;
			break;
		case R_X86_64_64:
			loc = dynrela->dest;
			val = dynrela->src;
			size = 8;
			break;
		default:
			pr_err("unsupported rela type %ld for source %s (0x%lx <- 0x%lx)\n",
			       dynrela->type, dynrela->name, dynrela->dest,
			       dynrela->src);
			return -EINVAL;
		}

		if (loc < core || loc >= core + core_size) {
			pr_err("bad dynrela location 0x%llx for symbol %s\n",
			       loc, dynrela->name);
			return -EINVAL;
		}

		/*
		 * Skip it if the instruction to be relocated has been
		 * changed already (paravirt or alternatives may do this).
		 */
		if (memchr_inv((void *)loc, 0, size)) {
			pr_notice("Skipped dynrela for %s (0x%lx <- 0x%lx): the instruction has been changed already.\n",
				  dynrela->name, dynrela->dest, dynrela->src);
			pr_notice_once(
"This is not necessarily a bug but it may indicate in some cases "
"that the binary patch does not handle paravirt operations, alternatives or the like properly.\n");
			continue;
		}

#ifdef CONFIG_DEBUG_SET_MODULE_RONX
#if (( LINUX_VERSION_CODE >= KERNEL_VERSION(4, 5, 0) ) || \
     ( LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0) && \
      UTS_UBUNTU_RELEASE_ABI >= 7 ) \
    )
               if (loc < core + kpmod->mod->core_layout.ro_size)
#else
               if (loc < core + kpmod->mod->core_ro_size)
#endif
			readonly = 1;
#endif

		numpages = (PAGE_SIZE - (loc & ~PAGE_MASK) >= size) ? 1 : 2;

		if (readonly)
			set_memory_rw(loc & PAGE_MASK, numpages);

		ret = probe_kernel_write((void *)loc, &val, size);

		if (readonly)
			set_memory_ro(loc & PAGE_MASK, numpages);

		if (ret) {
			pr_err("write to 0x%llx failed for symbol %s\n",
			       loc, dynrela->name);
			return ret;
		}
	}

	return 0;
}

static int kpatch_unlink_object(struct kpatch_object *object)
{
	if (object->mod)
		module_put(object->mod);

	return 0;
}

/*
 * Link to a to-be-patched object in preparation for patching it.
 *
 * - Find the object module
 * - Write patch module relocations which reference the object
 * - Calculate the patched functions' addresses
 * - Register them with ftrace
 */
static int kpatch_link_object(struct kpatch_module *kpmod,
			      struct kpatch_object *object)
{
	struct module *mod = NULL;
	struct kpatch_func *func, *func_err = NULL;
	int ret;
	bool vmlinux = !strcmp(object->name, "vmlinux");

	if (!vmlinux) {
		mutex_lock(&module_mutex);
		mod = find_module(object->name);
		if (!mod) {
			/*
			 * The module hasn't been loaded yet.  We can patch it
			 * later in kpatch_module_notify().
			 */
			mutex_unlock(&module_mutex);
			return 0;
		}

		/* should never fail because we have the mutex */
		WARN_ON(!try_module_get(mod));
		mutex_unlock(&module_mutex);
		object->mod = mod;
	}

	ret = kpatch_write_relocations(kpmod, object);
	if (ret)
		goto err_put;

	list_for_each_entry(func, &object->funcs, list) {

		/* lookup the old location */
		ret = kpatch_find_object_symbol(object->name,
						func->name,
						func->sympos,
						&func->old_addr);
		if (ret) {
			func_err = func;
			goto err_put;
		}
	}

	return 0;

err_put:
	if (!vmlinux)
		module_put(mod);
	return ret;
}

static int kpatch_module_notify(struct notifier_block *nb, unsigned long action,
				void *data)
{
	struct module *mod = data;
	struct kpatch_module *kpmod;
	struct kpatch_object *object;
	struct kpatch_func *func;
	struct kpatch_hook *hook;
	int ret = 0;
	bool found = false;

	if (action != MODULE_STATE_COMING)
		return 0;

	down(&kpatch_mutex);

	list_for_each_entry(kpmod, &kpmod_list, list) {
		list_for_each_entry(object, &kpmod->objects, list) {
			if (kpatch_object_linked(object))
				continue;
			if (!strcmp(object->name, mod->name)) {
				found = true;
				goto done;
			}
		}
	}
done:
	if (!found)
		goto out;

	ret = kpatch_link_object(kpmod, object);
	if (ret)
		goto out;

	BUG_ON(!object->mod);

	pr_notice("patching newly loaded module '%s'\n", object->name);

	/* run any user-defined load hooks */
	list_for_each_entry(hook, &object->hooks_load, list)
		(*hook->hook)();

	/* add to the global func hash */
	list_for_each_entry(func, &object->funcs, list) {
		ret = kpatch_insert_jmpinstr(object, func);
		if (ret)
			goto out;
		hash_add_rcu(kpatch_func_hash, &func->node, func->old_addr);
	}

out:
	up(&kpatch_mutex);

	/* no way to stop the module load on error */
	WARN(ret, "error (%d) patching newly loaded module '%s'\n", ret,
	     object->name);
	return 0;
}

int kpatch_register(struct kpatch_module *kpmod)
{
	int ret;
	struct kpatch_object *object, *object_err = NULL;
	struct kpatch_func *func;

	if (!kpmod->mod || list_empty(&kpmod->objects))
		return -EINVAL;

	down(&kpatch_mutex);

	if (kpmod->enabled) {
		ret = -EINVAL;
		goto err_up;
	}

	list_add_tail(&kpmod->list, &kpmod_list);

	if (!try_module_get(kpmod->mod)) {
		ret = -ENODEV;
		goto err_list;
	}

	list_for_each_entry(object, &kpmod->objects, list) {

		ret = kpatch_link_object(kpmod, object);
		if (ret) {
			object_err = object;
			goto err_unlink;
		}

		if (!kpatch_object_linked(object)) {
			pr_notice("delaying patch of unloaded module '%s'\n",
				  object->name);
			continue;
		}

		if (strcmp(object->name, "vmlinux"))
			pr_notice("patching module '%s'\n", object->name);

		list_for_each_entry(func, &object->funcs, list)
			func->op = KPATCH_OP_PATCH;
	}

	/* memory barrier between func hash and state write */
	smp_wmb();

	kpatch_state_updating();

	/*
	 * Idle the CPUs, verify activeness safety, and atomically make the new
	 * functions visible to the ftrace handler.
	 */

	(*kpatch_set_kernel_text_rw)();
	ret = stop_machine(kpatch_apply_patch, kpmod, NULL);
	(*kpatch_set_kernel_text_ro)();

	/* memory barrier between func hash and state write */
	smp_wmb();

	/* NMI handlers can return to normal now */
	kpatch_state_idle();

	/*
	 * Wait for all existing NMI handlers to complete so that they don't
	 * see any changes to funcs or funcs->op that might occur after this
	 * point.
	 *
	 * Any NMI handlers starting after this point will see the IDLE state.
	 */
	synchronize_rcu();

	if (ret)
		goto err_unlink;

	do_for_each_linked_func(kpmod, func) {
		func->op = KPATCH_OP_NONE;
	} while_for_each_linked_func();

/* HAS_MODULE_TAINT - upstream 2992ef29ae01 "livepatch/module: make TAINT_LIVEPATCH module-specific" */
#ifdef RHEL_RELEASE_CODE
# if RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7, 4)
#  define HAS_MODULE_TAINT
# endif
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
# define HAS_MODULE_TAINT
#endif

#ifdef TAINT_LIVEPATCH
# ifdef HAS_MODULE_TAINT
	/* kernel will add TAINT_LIVEPATCH on module load. */
# else
	pr_notice_once("tainting kernel with TAINT_LIVEPATCH\n");
	add_taint(TAINT_LIVEPATCH);
# endif
#else
	pr_notice_once("tainting kernel with TAINT_USER\n");
	add_taint(TAINT_USER);
#endif

	pr_notice("loaded patch module '%s'\n", kpmod->mod->name);

	kpmod->enabled = true;

	up(&kpatch_mutex);
	return 0;

err_unlink:
	list_for_each_entry(object, &kpmod->objects, list) {
		if (object == object_err)
			break;
		if (!kpatch_object_linked(object))
			continue;
		WARN_ON(kpatch_unlink_object(object));
	}
	module_put(kpmod->mod);
err_list:
	list_del(&kpmod->list);
err_up:
	up(&kpatch_mutex);
	return ret;
}
EXPORT_SYMBOL(kpatch_register);

/* No kpatch_unregister for now */

static struct notifier_block kpatch_module_nb = {
	.notifier_call = kpatch_module_notify,
	.priority = INT_MIN, /* called last */
};

static int kpatch_init(void)
{
	int ret;

	struct kpatch_kallsyms_args args = {
		.objname = NULL,
		.name = NULL,
		.addr = 0,
		.count = 0,
		.pos = 0,
	};

	/* set_kernel_text_{ro,rw} aren't exported to modules, and for good reason ;-) */
	args.name = "set_kernel_text_ro";
	mutex_lock(&module_mutex);
	kallsyms_on_each_symbol(kpatch_kallsyms_callback, &args);
	mutex_unlock(&module_mutex);

	kpatch_set_kernel_text_ro = (void *)args.addr;
	if (!kpatch_set_kernel_text_ro)
		return -ENXIO;

	args.name = "set_kernel_text_rw";
	mutex_lock(&module_mutex);
	kallsyms_on_each_symbol(kpatch_kallsyms_callback, &args);
	mutex_unlock(&module_mutex);

	kpatch_set_kernel_text_rw = (void *)args.addr;
	if (!kpatch_set_kernel_text_rw)
		return -ENXIO;

	kpatch_root_kobj = kobject_create_and_add("kpatch", kernel_kobj);
	if (!kpatch_root_kobj)
		return -ENOMEM;

	kpatch_patches_kobj = kobject_create_and_add("patches",
						     kpatch_root_kobj);
	if (!kpatch_patches_kobj) {
		ret = -ENOMEM;
		goto err_root_kobj;
	}

	ret = register_module_notifier(&kpatch_module_nb);
	if (ret)
		goto err_patches_kobj;

	return 0;

err_patches_kobj:
	kobject_put(kpatch_patches_kobj);
err_root_kobj:
	kobject_put(kpatch_root_kobj);
	return ret;
}

static void kpatch_exit(void)
{
	rcu_barrier();

	WARN_ON(unregister_module_notifier(&kpatch_module_nb));
	kobject_put(kpatch_patches_kobj);
	kobject_put(kpatch_root_kobj);
}

module_init(kpatch_init);
module_exit(kpatch_exit);
MODULE_LICENSE("GPL");
