/* See https://lkml.org/lkml/2014/8/13/116 and
 * https://patchwork.ozlabs.org/patch/930413/ for the reocation type
 * BPF_PSEUDO_MAP_FD or R_BPF_MAP_FD with value 1 */

/* Relocations, as exposed in format consumeable by C */
struct tbpf_reloc {
	char *name; /* Name of the symbol */
	int type;   /* Type of relocation, expected 1 */
	int offset; /* Offset: ebpf instruction number */
};

int tbpf_fill_symbol(struct bpf_insn *insns, struct tbpf_reloc *relocs,
		     const char *symbol, int32_t value);
