#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>

#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "inet-kern-shared.h"

#include "inet-kern-shared.c"

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

SEC("inet_program")
int _inet_program(struct bpf_inet_lookup *ctx)
{
	/* Force 32 bit loads from context, to avoid eBPF "ctx modified"
	 * messages */
	volatile uint32_t protocol = ctx->protocol;
	volatile uint32_t local_port = ctx->local_port;

	/* /32 and /128 */
	struct ip laddr_full = {};
	if (ctx->family == AF_INET) {
		laddr_full.ip_as_w[2] = bpf_htonl(0x0000ffff);
		laddr_full.ip_as_w[3] = ctx->local_ip4;
	}
	if (ctx->family == AF_INET6) {
		/* eBPF voodoo. Must be unordered otherwise some
		 * optimization breaks the generated bpf. */
		laddr_full.ip_as_w[3] = ctx->local_ip6[3];
		laddr_full.ip_as_w[0] = ctx->local_ip6[0];
		laddr_full.ip_as_w[1] = ctx->local_ip6[1];
		laddr_full.ip_as_w[2] = ctx->local_ip6[2];
	}

	struct addr lookup_keys[] = {
		{
			.protocol = protocol,
			.port = local_port,
			.addr = laddr_full,
		},
		{
			.protocol = protocol,
			.port = 0,
			.addr = laddr_full,
		},
	};

	int i = 0;
#pragma clang loop unroll(full)
	for (i = 0; i < (int)ARRAY_SIZE(lookup_keys); i++) {
		struct srvname *srvname = NULL;
		/* eBPF voodoo. For some reason key = lookup_keys[i] aint work.
		 */
		struct addr key = {
			.protocol = lookup_keys[i].protocol,
			.port = lookup_keys[i].port,
		};
		key.prefixlen = (sizeof(struct addr) - 4) * 8;
		key.addr = lookup_keys[i].addr;

		srvname =
			(struct srvname *)bpf_map_lookup_elem(&bind_map, &key);
		if (srvname != NULL) {
			uint32_t *index = (uint32_t *)bpf_map_lookup_elem(
				&srvname_map, srvname);
			if (index != NULL) {
				int r = bpf_redirect_lookup(ctx, &redir_map,
							    index, 0);
				if (r == BPF_REDIRECT) {
					return BPF_REDIRECT;
				}
			}
		}
	}
	return BPF_OK;
}
