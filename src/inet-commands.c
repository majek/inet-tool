#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "libbpf.h"
#include "libbpf_ebpf.h"
#include "linux_bpf.h"

#include "../ebpf/inet-kern-shared.h"
#include "inet.h"
#include "tbpf.h"

#define SEC(a)
#include "../ebpf/inet-kern-shared.c"

struct bpf_map_def *ebpf_maps[] = {
	&redir_map,
	&bind_map,
	&srvname_map,
};
int ebpf_maps_sz = ARRAY_SIZE(ebpf_maps);

char *ebpf_maps_names[] = {
	"redir_map",
	"bind_map",
	"srvname_map",
};

extern size_t bpf_insn_inet_program_cnt;
extern struct bpf_insn bpf_insn_inet_program[];
extern struct tbpf_reloc bpf_reloc_inet_program[];

struct {
	char *name;
	struct bpf_insn *insn;
	size_t *insn_cnt;
	struct tbpf_reloc *reloc;
} ebpf_program = {
	INET_PROGRAM_VERSION,
	bpf_insn_inet_program,
	&bpf_insn_inet_program_cnt,
	bpf_reloc_inet_program,
};

void inet_load(struct state *state)
{
	int map_pos;
	for (map_pos = 0; map_pos < ebpf_maps_sz; map_pos++) {
		struct bpf_map_def *def = ebpf_maps[map_pos];
		char map_name[PATH_MAX];
		snprintf(map_name, sizeof(map_name), "%s%s",
			 state->sys_fs_map_prefix, ebpf_maps_names[map_pos]);

		int map_fd = state->map_fds[map_pos];
		if (map_fd == 0) {
			map_fd = bpf_create_map(
				def->type, def->key_size, def->value_size,
				def->max_entries, def->map_flags);
			if (map_fd < 0) {
				if (errno == EPERM) {
					fprintf(stderr,
						"[!] Are you root? Do you have "
						"enough memlock "
						"resources?\n");
					fprintf(stderr,
						"[!] Try running \"ulimit -l "
						"unlimited\" before\n");
				}
				PFATAL("bpf(BPF_MAP_CREATE, %d)", def->type);
			}

			int r = bpf_obj_pin(map_fd, map_name);
			if (r < 0) {
				PFATAL("BPF_OBJ_PIN(%s)", map_name);
			}
			state->map_fds[map_pos] = map_fd;
			fprintf(stderr, "[+] Created map %s\n", map_name);
		} else {
			fprintf(stderr, "[+] Reused map %s\n", map_name);
		}

		char *obj_name = ebpf_maps_names[map_pos];

		tbpf_fill_symbol(ebpf_program.insn, ebpf_program.reloc,
				 obj_name, map_fd);
	}

	/* prog load */
	char log_buf[16 * 1024];
	struct bpf_load_program_attr load_attr = {
		.prog_type = BPF_PROG_TYPE_INET_LOOKUP,
		.insns = ebpf_program.insn,
		.insns_cnt = *ebpf_program.insn_cnt,
		.license = "Dual BSD/GPL",
		.name = ebpf_program.name,
		.kern_version = KERNEL_VERSION(5, 2, 0),
	};

	int bpf_prog =
		bpf_load_program_xattr(&load_attr, log_buf, sizeof(log_buf));

	if (bpf_prog < 0) {
		if (errno == EPERM) {
			fprintf(stderr,
				"[!] Are you root? Do you have enough memlock "
				"resources?\n");
			fprintf(stderr,
				"[!] Try running \"ulimit -l unlimited\" "
				"before\n");
		}
		PFATAL("Bpf Log:\n%s\n bpf(BPF_PROG_LOAD)", log_buf);
	}

	int r = bpf_prog_attach(bpf_prog, 0, BPF_INET_LOOKUP, 0);
	if (r) {
		if (errno == EEXIST) {
			fprintf(stderr,
				"[-] Unloading previous INET LOOKUP "
				"program\n");
			// BPF_F_ALLOW_OVERRIDE doesn't work
			bpf_prog_detach2(0, 0, BPF_INET_LOOKUP);

			/* Try again */
			r = bpf_prog_attach(bpf_prog, 0, BPF_INET_LOOKUP, 0);
		}
		if (r) {
			PFATAL("bpf(BPF_ATTACH, BPF_INET_LOOKUP)");
		}
	}
	printf("INET_LOOKUP program loaded\n");
}

void inet_open_verify_maps(struct state *state, int all_needed)
{
	int map_pos;
	for (map_pos = 0; map_pos < ebpf_maps_sz; map_pos++) {
		struct bpf_map_def *def = ebpf_maps[map_pos];
		char map_name[PATH_MAX];
		snprintf(map_name, sizeof(map_name), "%s%s",
			 state->sys_fs_map_prefix, ebpf_maps_names[map_pos]);

		/* 1. try to reuse already opened maps */
		int map_fd = state->map_fds[map_pos];

		if (map_fd == 0) {
			/* 2. otherwise try to open the map */
			map_fd = bpf_obj_get(map_name);

			/* 3. any error other than ENOTFOUND is fatal */
			if (map_fd < 0 && errno != ENOENT) {
				PFATAL("bpf_obj_get(%s)", map_name);
			}

			/* 4. Got ENOTFOUND? Two options. Either
			 * ignore it (we will create it during program
			 * "load" anyway). */
			if (map_fd < 0 && all_needed == 0) {
				continue;
			}
			/* 5. Or fatal. We need all maps for other actions. */
			if (map_fd < 0 && all_needed == 1) {
				PFATAL("Failed to open map %s", map_name);
			}
		}

		{
			/* 6. Verify map parameters */
			struct bpf_map_info info = {};
			uint32_t info_sz = sizeof(struct bpf_map_info);
			int r = bpf_obj_get_info_by_fd(map_fd, &info, &info_sz);
			if (r) {
				PFATAL("bpf_obj_get_info_by_fd");
			}
			if (info.type != def->type ||
			    info.key_size != def->key_size ||
			    info.value_size != def->value_size ||
			    info.max_entries != def->max_entries) {
				fprintf(stderr,
					"[!] Map %s parameters don't match. "
					"Run "
					"\"inet_tool unload\" first\n",
					map_name);
				exit(-2);
			}
		}
		state->map_fds[map_pos] = map_fd;
	}
}

struct prog_info {
	uint32_t map_ids[128];
	struct bpf_prog_info bpi;
};

static int get_prog_info(struct prog_info *prog_info)
{
	int ns_fd = open("/proc/self/ns/net", O_RDONLY);
	if (ns_fd < 0) {
		PFATAL("open(/proc/self/ns/net)");
	}

	uint32_t attach_flags = 0;
	uint32_t prog_ids[1] = {0};
	uint32_t prog_cnt = 1;

	int r = bpf_prog_query(ns_fd, BPF_INET_LOOKUP, 0, &attach_flags,
			       prog_ids, &prog_cnt);
	if (r) {
		PFATAL("bpf(PROG_QUERY, BPF_INET_LOOKUP)");
	}
	close(ns_fd);

	int i;
	for (i = 0; i < (int)prog_cnt; i++) {
		int bpf_fd = bpf_prog_get_fd_by_id(prog_ids[i]);
		if (bpf_fd < 0) {
			PFATAL("bpf_prog_get_fd_by_id()");
		}

		prog_info->bpi = (struct bpf_prog_info){
			.nr_map_ids = 128,
			.map_ids = (uint64_t)&prog_info->map_ids,
		};
		uint32_t bpi_sz = sizeof(struct bpf_prog_info);
		r = bpf_obj_get_info_by_fd(bpf_fd, &prog_info->bpi, &bpi_sz);
		if (r) {
			PFATAL("bpf_obj_get_info_by_fd()");
		}
		close(bpf_fd);
	}
	return i;
}

int inet_prog_info(struct state *state)
{
	struct prog_info prog_info;
	int i = get_prog_info(&prog_info);

	if (i == 1) {
		printf("[+] INET_LOOKUP program present\n");
		int recognized =
			strcmp(prog_info.bpi.name, ebpf_program.name) == 0;
		printf("[+] name: %s  (%s)\n", prog_info.bpi.name,
		       recognized ? "recognized" : "unknown");
		uint8_t *tag = prog_info.bpi.tag;
		printf("[+] tag:  %02x%02x%02x%02x%02x%02x%02x%02x\n", tag[0],
		       tag[1], tag[2], tag[3], tag[4], tag[5], tag[6], tag[7]);
		printf("[+] prog maps:  ");

		int j;
		for (j = 0; j < (int)prog_info.bpi.nr_map_ids; j++) {
			printf("%s%u", j > 0 ? "," : "", prog_info.map_ids[j]);
		}
		printf("\n");
		printf("[+] /sys maps:  ");
		for (j = 0; j < ebpf_maps_sz; j++) {
			int map_fd = state->map_fds[j];
			struct bpf_map_info info = {};
			uint32_t info_sz = sizeof(struct bpf_map_info);
			int r = bpf_obj_get_info_by_fd(map_fd, &info, &info_sz);
			if (r) {
				PFATAL("bpf_obj_get_info_by_fd");
			}
			printf("%s%u", j > 0 ? "," : "", info.id);
		}
		printf("\n");
		printf("[+] run_cnt=%llu  run_time_ns=%llu\n",
		       prog_info.bpi.run_cnt, prog_info.bpi.run_time_ns);
	}
	if (i == 0) {
		printf("INET_LOOKUP program absent\n");
		return 1;
	}
	return 0;
}

int inet_prog_verify()
{
	struct prog_info prog_info;
	int i = get_prog_info(&prog_info);
	if (i == 1) {
		int recognized =
			strcmp(prog_info.bpi.name, ebpf_program.name) == 0;
		return recognized;
	}
	return -1;
}

int inet_unload(struct state *state)
{
	int return_code = 0;
	int fd = open("/proc/self/ns/net", O_RDONLY);
	if (fd < 0) {
		PFATAL("open(/proc/self/ns/net)");
	}

	uint32_t attach_flags = 0;
	uint32_t prog_ids[1] = {0};
	uint32_t prog_cnt = 1;

	int r = bpf_prog_query(fd, BPF_INET_LOOKUP, 0, &attach_flags, prog_ids,
			       &prog_cnt);
	if (r) {
		PFATAL("bpf(PROG_QUERY, BPF_INET_LOOKUP)");
	}
	close(fd);

	// BPF_F_ALLOW_OVERRIDE doesn't work
	r = bpf_prog_detach2(0, 0, BPF_INET_LOOKUP);
	if (r == 0) {
		printf("[+] INET_LOOKUP program unloaded\n");
	} else {
		printf("[-] Failed to unload INET_LOOKUP: %s\n",
		       strerror(errno));
		return_code = 1;
	}
	int map_pos;
	for (map_pos = 0; map_pos < ebpf_maps_sz; map_pos++) {
		char map_name[PATH_MAX];
		snprintf(map_name, sizeof(map_name), "%s%s",
			 state->sys_fs_map_prefix, ebpf_maps_names[map_pos]);

		r = unlink(map_name);
		if (r == 0) {
			printf("[+] Unpinned map %s\n", map_name);
		} else {
			printf("[-] Failed to unlink map %s: %s\n", map_name,
			       strerror(errno));
		}
	}
	return return_code;
}

void inet_list(struct state *state)
{
	{
		printf("List of services:\n");
		struct srvname k = {};
		uint32_t v;
		while (1) {
			int r = bpf_map_get_next_key(
				state->map_fds[SRVNAME_MAP], &k, &k);
			if (r) {
				if (errno == ENOENT) {
					break;
				}
				PFATAL("get_next_key");
			}
			r = bpf_map_lookup_elem(state->map_fds[SRVNAME_MAP], &k,
						&v);
			if (r) {
				PFATAL("map_lookup_elem");
			}

			uint32_t redir_k = v;
			char sk[32] = "sk:(nil)";
			uint64_t redir_v;

			r = bpf_map_lookup_elem(state->map_fds[REDIR_MAP],
						&redir_k, &redir_v);
			if (r) {
				if (errno != ENOENT) {
					PFATAL("map_lookup_elem");
				}
			} else {
				snprintf(sk, sizeof(sk), "sk:%lx", redir_v);
			}
			printf("\t%.*s\t= #%d %s\n", 32, k.name, v, sk);
		}
	}

	{
		printf("List of bindings:\n");
		struct addr k = {};
		struct srvname v;
		while (1) {
			int r = bpf_map_get_next_key(state->map_fds[BIND_MAP],
						     &k, &k);
			if (r) {
				if (errno == ENOENT) {
					break;
				}
				PFATAL("get_next_key");
			}
			r = bpf_map_lookup_elem(state->map_fds[BIND_MAP], &k,
						&v);
			if (r) {
				PFATAL("map_lookup_elem");
			}
			printf("\t%s -> %.*s\n", sprint_addr(&k), 32, v.name);
		}
	}
}

void inet_register(struct state *state, char **fdnames, char **srvnames)
{
	int fd = -1;
	int skip_fds[] = {0, 1, 2, -1};
	while (1) {
		int domain, sock_type, protocol;
		fd = find_inherited_fd(fd, skip_fds, &domain, &sock_type,
				       &protocol);
		if (fd < 0) {
			break;
		}

		if (domain == AF_INET || domain == AF_INET6) {
			char *name = NULL;
			if (fdnames && fdnames[0]) {
				name = fdnames[0];
				fdnames++;
			} else if (srvnames && srvnames[0]) {
				name = srvnames[0];
				srvnames++;
			} else {
				name = "@";
			}

			int r = inet_register_socket(state, fd, name);
			if (r == -1) {
				fprintf(stderr,
					"[!] Socket must have SO_REUSEPORT "
					"set!\n");
			}
			if (r == -2) {
				fprintf(stderr, "[!] redir_map full!\n");
			}

			uint64_t sk = 0;
			socklen_t l = sizeof(sk);
			getsockopt(fd, SOL_SOCKET, SO_COOKIE, &sk, &l);

			fprintf(stderr, "[+] %.*s -> #%d (sk:%lx)\n",
				(int)sizeof(struct srvname), name, r, sk);
		}
	}

	/* Sockets absent but labels are still present.  */

	while (srvnames && srvnames[0]) {
		char *name = srvnames[0];
		srvnames++;

		int r = inet_register_socket(state, -1, name);
		fprintf(stderr, "[+] %.*s -> #%d (sk:nil)\n",
			(int)sizeof(struct srvname), name, r);
	}
}

void inet_unregister(struct state *state, char *service)
{
	struct srvname srvname;
	strncpy(srvname.name, service, sizeof(srvname.name));

	int r = bpf_map_delete_elem(state->map_fds[SRVNAME_MAP], &srvname);
	if (r) {
		PFATAL("map_delete(srvname_map)");
	}
	fprintf(stderr, "[-] %.*s -> \n", (int)sizeof(srvname.name),
		srvname.name);
}

int inet_register_socket(struct state *state, int fd, char *fdname)
{
	if (fd >= 0) {
		int o = 0;
		socklen_t l = sizeof(int);
		getsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &o, &l);
		if (o != 1) {
			return -1;
		}
	}

	struct srvname srvname = {};
	strncpy(srvname.name, fdname, sizeof(srvname.name));

	/* lookup already present service */
	uint32_t redir_index = UINT_MAX;
	{
		uint32_t v;
		int r = bpf_map_lookup_elem(state->map_fds[SRVNAME_MAP],
					    &srvname, &v);
		if (r) {
			if (errno != ENOENT) {
				PFATAL("map_lookup_elem(srvname_map)");
			}
		} else {
			redir_index = v;
		}
	}

	if (redir_index == UINT_MAX) {
		char redir_index_used[32] = {};
		struct srvname k = {};
		uint32_t v;
		while (1) {
			int r = bpf_map_get_next_key(
				state->map_fds[SRVNAME_MAP], &k, &k);
			if (r) {
				if (errno == ENOENT) {
					break;
				}
				PFATAL("get_next_key");
			}
			r = bpf_map_lookup_elem(state->map_fds[SRVNAME_MAP], &k,
						&v);
			if (r) {
				PFATAL("map_lookup_elem");
			}
			if (v > 32) {
				PFATAL("");
			}
			redir_index_used[v] = 1;
		}
		int i;
		for (i = 0; i < 32; i++) {
			if (redir_index_used[i] == 0) {
				redir_index = i;
				break;
			}
		}
	}

	if (redir_index == UINT_MAX) {
		return -2;
	}

	if (fd >= 0) {
		uint64_t val = fd;
		int r = bpf_map_update_elem(state->map_fds[REDIR_MAP],
					    &redir_index, &val, 0);
		if (r) {
			if (errno != EEXIST) {
				PFATAL("map_update");
			}
		}
	}

	/* Insert srvname int */
	{
		struct srvname srvname = {};
		strncpy(srvname.name, fdname, sizeof(srvname.name));
		int r = bpf_map_update_elem(state->map_fds[SRVNAME_MAP],
					    &srvname, &redir_index, 0);
		if (r) {
			PFATAL("map_update(srvname_map)");
		}
	}
	return redir_index;
}

struct addr addr_from_inetaddr(struct inet_addr *ia)
{
	int prefixlen = (sizeof(struct addr) - 4) * 8;
	int bottombits = get_bottombits(&ia->ss, ia->subnet);

	struct addr ad = {
		.prefixlen = prefixlen - bottombits,
		.protocol = ia->protocol,
	};

	{
		struct sockaddr_in *sin = (struct sockaddr_in *)&ia->ss;
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ia->ss;
		if (ia->ss.ss_family == AF_INET) {
			ad.addr.ip_as_w[2] = htonl(0x0000ffff);
			memcpy(&ad.addr.ip_as_w[3], &sin->sin_addr, 4);
			ad.port = htons(sin->sin_port);
		}
		if (ia->ss.ss_family == AF_INET6) {
			memcpy(&ad.addr, &sin6->sin6_addr, 16);
			ad.port = htons(sin6->sin6_port);
		}
	}
	return ad;
}

void inet_bind(struct state *state, struct inet_addr *iaddr, char *service)
{
	struct addr localaddr = addr_from_inetaddr(iaddr);

	struct srvname srvname;
	strncpy(srvname.name, service, sizeof(srvname.name));

	int r = bpf_map_update_elem(state->map_fds[BIND_MAP], &localaddr,
				    &srvname, 0);
	if (r) {
		PFATAL("map_update(bind_map)");
	}
	printf("[+]  %s -> %.*s\n", sprint_addr(&localaddr),
	       (int)sizeof(srvname.name), srvname.name);
}

void inet_unbind(struct state *state, struct inet_addr *iaddr)
{
	struct addr localaddr = addr_from_inetaddr(iaddr);

	int r = bpf_map_delete_elem(state->map_fds[BIND_MAP], &localaddr);
	if (r) {
		PFATAL("map_update(bind_map)");
	}
	printf("[-]  %s\n", sprint_addr(&localaddr));
}
