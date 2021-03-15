/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2016 Josh Poimboeuf <jpoimboe@redhat.com>
 * Copyright (C) 2017 Joao Moreira   <jmoreira@suse.de>
 *
 */

#define SHN_LIVEPATCH		0xff20
#define SHF_RELA_LIVEPATCH	0x00100000
#define MODULE_NAME_LEN		(64 - sizeof(GElf_Addr))
#define WARN(format, ...) \
	fprintf(stderr, "klp-convert: " format "\n", ##__VA_ARGS__)

struct symbol_entry {
	struct list_head list;
	char *symbol_name;
	char *object_name;
};

struct sympos {
	struct list_head list;
	char *symbol_name;
	char *object_name;
	int pos;
};

/*
 * klp-convert uses macros and structures defined in the linux sources
 * package (see include/uapi/linux/livepatch.h). To prevent the
 * dependency when building locally, they are defined below. Also notice
 * that these should match the definitions from the targeted kernel.
 */

#define KLP_RELA_PREFIX		".klp.rela."
#define KLP_SYM_PREFIX		".klp.sym."

#ifndef __packed
#define __packed        __attribute__((packed))
#endif

struct klp_module_reloc {
	void *sym;
	unsigned int sympos;
} __packed;
