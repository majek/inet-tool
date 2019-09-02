struct bpf_map_def SEC("maps") redir_map = {
	.type = BPF_MAP_TYPE_REUSEPORT_SOCKARRAY,
	.max_entries = 512,
	.key_size = sizeof(uint32_t),
	.value_size = sizeof(uint64_t),
};

struct bpf_map_def SEC("maps") bind_map = {
	.type = BPF_MAP_TYPE_LPM_TRIE,
	.max_entries = 4096,
	.key_size = sizeof(struct addr),
	.value_size = sizeof(struct srvname),
	.map_flags = BPF_F_NO_PREALLOC,
};

struct bpf_map_def SEC("maps") srvname_map = {
	.type = BPF_MAP_TYPE_HASH,
	.max_entries = 512,
	.key_size = sizeof(struct srvname),
	.value_size = sizeof(uint32_t),
	.map_flags = BPF_F_NO_PREALLOC,
};
