#ifndef __KPATCH_MACROS_H_
#define __KPATCH_MACROS_H_

#include <linux/compiler.h>
#include <linux/jiffies.h>
#include <linux/version.h>

/*
 * KPATCH_IGNORE_SECTION macro
 *
 * This macro is for ignoring sections that may change as a side effect of
 * another change or might be a non-bundlable section; that is one that does
 * not honor -ffunction-section and create a one-to-one relation from function
 * symbol to section.
 */
#define KPATCH_IGNORE_SECTION(_sec) \
	char *__UNIQUE_ID(kpatch_ignore_section_) __section(.kpatch.ignore.sections) = _sec;

/*
 * KPATCH_IGNORE_FUNCTION macro
 *
 * This macro is for ignoring functions that may change as a side effect of a
 * change in another function.  The WARN class of macros, for example, embed
 * the line number in an instruction, which will cause the function to be
 * detected as changed when, in fact, there has been no functional change.
 */
#define KPATCH_IGNORE_FUNCTION(_fn) \
	void *__kpatch_ignore_func_##_fn __section(.kpatch.ignore.functions) = _fn;


/* Support for livepatch callbacks */
#if IS_ENABLED(CONFIG_LIVEPATCH)
# if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 15, 0)
#  define HAS_LIVEPATCH_CALLBACKS
# endif
#endif

#ifdef HAS_LIVEPATCH_CALLBACKS

#include <linux/livepatch.h>

typedef int (*kpatch_pre_patchcall_t)(struct klp_object *obj);
typedef void (*kpatch_post_patchcall_t)(struct klp_object *obj);
typedef void (*kpatch_pre_unpatchcall_t)(struct klp_object *obj);
typedef void (*kpatch_post_unpatchcall_t)(struct klp_object *obj);

struct kpatch_pre_patch {
	kpatch_pre_patchcall_t fn;
	char *objname; /* filled in by create-diff-object */
};

struct kpatch_post_patch {
	kpatch_post_patchcall_t fn;
	char *objname; /* filled in by create-diff-object */
};

struct kpatch_pre_unpatch {
	kpatch_pre_unpatchcall_t fn;
	char *objname; /* filled in by create-diff-object */
};

struct kpatch_post_unpatch {
	kpatch_post_unpatchcall_t fn;
	char *objname; /* filled in by create-diff-object */
};


#define KPATCH_PRE_PATCH_CALLBACK(_fn) \
	static inline kpatch_pre_patchcall_t __pre_patchtest(void) { return _fn; } \
	static struct kpatch_pre_patch kpatch_pre_patch_data __section(.kpatch.callbacks.pre_patch) __used = { \
		.fn = _fn, \
		.objname = NULL \
	};
#define KPATCH_POST_PATCH_CALLBACK(_fn) \
	static inline kpatch_post_patchcall_t __post_patchtest(void) { return _fn; } \
	static struct kpatch_post_patch kpatch_post_patch_data __section(.kpatch.callbacks.post_patch) __used = { \
		.fn = _fn, \
		.objname = NULL \
	};
#define KPATCH_PRE_UNPATCH_CALLBACK(_fn) \
	static inline kpatch_pre_unpatchcall_t __pre_unpatchtest(void) { return _fn; } \
	static struct kpatch_pre_unpatch kpatch_pre_unpatch_data __section(.kpatch.callbacks.pre_unpatch) __used = { \
		.fn = _fn, \
		.objname = NULL \
	};
#define KPATCH_POST_UNPATCH_CALLBACK(_fn) \
	static inline kpatch_post_unpatchcall_t __post_unpatchtest(void) { return _fn; } \
	static struct kpatch_post_unpatch kpatch_post_unpatch_data __section(.kpatch.callbacks.post_unpatch) __used = { \
		.fn = _fn, \
		.objname = NULL \
	};

#else /* HAS_LIVEPATCH_CALLBACKS */

typedef void (*kpatch_loadcall_t)(void);
typedef void (*kpatch_unloadcall_t)(void);

struct kpatch_load {
	kpatch_loadcall_t fn;
	char *objname; /* filled in by create-diff-object */
};

struct kpatch_unload {
	kpatch_unloadcall_t fn;
	char *objname; /* filled in by create-diff-object */
};

/*
 * KPATCH_LOAD_HOOK macro
 *
 * The first line only ensures that the hook being registered has the required
 * function signature.  If not, there is compile error on this line.
 *
 * The section line declares a struct kpatch_load to be allocated in a new
 * .kpatch.hook.load section.  This kpatch_load_data symbol is later stripped
 * by create-diff-object so that it can be declared in multiple objects that
 * are later linked together, avoiding global symbol collision.  Since multiple
 * hooks can be registered, the .kpatch.hook.load section is a table of struct
 * kpatch_load elements that will be executed in series by the kpatch core
 * module at load time, assuming the kernel object (module) is currently
 * loaded; otherwise, the hook is called when module to be patched is loaded
 * via the module load notifier.
 */
#define KPATCH_LOAD_HOOK(_fn) \
	static inline kpatch_loadcall_t __loadtest(void) { return _fn; } \
	struct kpatch_load kpatch_load_data __section(.kpatch.hooks.load) = { \
		.fn = _fn, \
		.objname = NULL \
	};

/*
 * KPATCH_UNLOAD_HOOK macro
 *
 * Same as LOAD hook with s/load/unload/
 */
#define KPATCH_UNLOAD_HOOK(_fn) \
	static inline kpatch_unloadcall_t __unloadtest(void) { return _fn; } \
	struct kpatch_unload kpatch_unload_data __section(.kpatch.hooks.unload) = { \
		.fn = _fn, \
		.objname = NULL \
	};

#endif /* HAS_LIVEPATCH_CALLBACKS */

/*
 * KPATCH_FORCE_UNSAFE macro
 *
 * USE WITH EXTREME CAUTION!
 *
 * Allows patch authors to bypass the activeness safety check at patch load
 * time. Do this ONLY IF 1) the patch application will always/likely fail due
 * to the function being on the stack of at least one thread at all times and
 * 2) it is safe for both the original and patched versions of the function to
 * run concurrently.
 */
#define KPATCH_FORCE_UNSAFE(_fn) \
	void *__kpatch_force_func_##_fn __section(.kpatch.force) = _fn;

/*
 * KPATCH_PRINTK macro
 *
 * Use this instead of calling printk to avoid unwanted compiler optimizations
 * which cause kpatch-build errors.
 *
 * The printk function is annotated with the __cold attribute, which tells gcc
 * that the function is unlikely to be called.  A side effect of this is that
 * code paths containing calls to printk might also be marked cold, leading to
 * other functions called in those code paths getting moved into .text.unlikely
 * or being uninlined.
 *
 * This macro places printk in its own code path so as not to make the
 * surrounding code path cold.
 */
#define KPATCH_PRINTK(_fmt, ...) \
({ \
	if (jiffies) \
		printk(_fmt, ## __VA_ARGS__); \
})

#endif /* __KPATCH_MACROS_H_ */
