/*
 * This code is based on bpf.c from:
 * https://github.com/torvalds/linux/blob/master/tools/lib/bpf/bpf.c
 *
 * As opposed to libbpf.c it does not have a dependency on libelf.
 */
#include <linux/bpf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tbpf.h"

/* Fixup a relocation in ebpf bpf_insn table. */
int tbpf_fill_symbol(struct bpf_insn *insns, struct tbpf_reloc *relocs,
		     const char *symbol, int32_t value)
{
	int c = 0;
	while (relocs && relocs->name && relocs->name[0] != '\x00') {
		if (strcmp(relocs->name, symbol) == 0) {
			switch (relocs->type) {
			case 1:
				insns[relocs->offset].src_reg = 1;
				insns[relocs->offset].imm = value;
				c += 1;
				break;
			default:
				fprintf(stderr,
					"FATAL: unknown relocation %d\n",
					relocs->type);
				abort();
			}
		}
		relocs++;
	}
	return c;
}
