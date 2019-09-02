#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../ebpf/inet-kern-shared.h"

#include "inet.h"

char *terminating_strncpy(char *dest, const char *src, size_t n)
{
	char *r = strncpy(dest, src, n);
	dest[n - 1] = '\0';
	return r;
}

static void net_addr_from_name(struct sockaddr_storage *ss,
			       const char *src_host)
{
	char buf[256];
	terminating_strncpy(buf, src_host, sizeof(buf));
	char *host = buf;

	struct sockaddr_in *sin = (struct sockaddr_in *)ss;
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;

	if (inet_pton(AF_INET, host, &sin->sin_addr) == 1) {
		sin->sin_family = AF_INET;
		return;
	}

	if (*host && host[0] == '[' && host[strlen(host) - 1] == ']') {
		host[strlen(host) - 1] = '\x0';
		host += 1;
	}

	if (inet_pton(AF_INET6, host, &sin6->sin6_addr) == 1) {
		sin6->sin6_family = AF_INET6;
		return;
	}

	PFATAL("Neither INET nor INET6 address %s", host);
}

int net_parse_sockaddr(struct sockaddr_storage *ss, const char *src_addr,
		       int *subnet_ptr)
{
	char addr[256];
	terminating_strncpy(addr, src_addr, sizeof(addr));

	long subnet = -1;
	*ss = (struct sockaddr_storage){};

	char *colon = strrchr(addr, ':');
	if (colon == NULL || colon[1] == '\0') {
		PFATAL("%s doesn't contain a port number.", addr);
	}
	*colon = '\0';

	char *endptr;
	long port = strtol(&colon[1], &endptr, 10);
	if (port < 0 || port > 65535 || *endptr != '\0') {
		PFATAL("Invalid port number %s", &colon[1]);
	}

	char *slash = strrchr(addr, '/');
	if (slash) {
		*slash = '\0';
		char *endptr;
		subnet = strtol(&slash[1], &endptr, 10);
		if (*endptr != '\0') {
			subnet = -2;
		} else if (subnet < 0 || subnet > 128) {
			subnet = -2;
		}
	}
	net_addr_from_name(ss, addr);

	struct sockaddr_in *sin = (struct sockaddr_in *)ss;
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;

	switch (ss->ss_family) {
	case AF_INET:
		sin->sin_port = htons(port);
		if (subnet > 32) {
			subnet = -2;
		}
		break;
	case AF_INET6:
		sin6->sin6_port = htons(port);
		if (subnet > 128) {
			subnet = -2;
		}
		break;
	default:
		PFATAL("");
	}
	*subnet_ptr = subnet;
	return -1;
}

const char *net_ntop(struct sockaddr_storage *ss)
{
	char s[INET6_ADDRSTRLEN + 1];
	static char a[INET6_ADDRSTRLEN + 32];
	struct sockaddr_in *sin = (struct sockaddr_in *)ss;
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;
	int port;
	const char *r;
	switch (ss->ss_family) {
	case AF_INET:
		port = htons(sin->sin_port);
		r = inet_ntop(sin->sin_family, &sin->sin_addr, s, sizeof(s));
		if (r == NULL) {
			PFATAL("inet_ntop()");
		}
		snprintf(a, sizeof(a), "%s:%i", s, port);
		break;
	case AF_INET6:
		r = inet_ntop(sin6->sin6_family, &sin6->sin6_addr, s,
			      sizeof(s));
		if (r == NULL) {
			PFATAL("inet_ntop()");
		}
		port = htons(sin6->sin6_port);
		snprintf(a, sizeof(a), "[%s]:%i", s, port);
		break;
	default:
		PFATAL("");
	}
	return a;
}

const char *sprint_addr(struct addr *k)
{
	int do_subnet = 1;
	int subnet;
	char raw_ip[128];
	if (k->addr.ip_as_w[0] == 0 && k->addr.ip_as_w[1] == 0 &&
	    k->addr.ip_as_w[2] == htonl(0x0000ffff)) {
		inet_ntop(AF_INET, &k->addr.ip_as_w[3], raw_ip, sizeof(raw_ip));
		subnet = 32 - ((sizeof(struct addr) - 4) * 8 - k->prefixlen);
		if (subnet == 32) {
			do_subnet = 0;
		}
	} else {
		char c[128];
		inet_ntop(AF_INET6, &k->addr.ip_as_w[0], c, sizeof(c));
		snprintf(raw_ip, sizeof(raw_ip), "[%s]", c);
		subnet = 128 - ((sizeof(struct addr) - 4) * 8 - k->prefixlen);
		if (subnet == 128) {
			do_subnet = 0;
		}
	}

	static char buf[128];
	if (do_subnet) {
		snprintf(buf, sizeof(buf), "%d %s/%d:%d", k->protocol, raw_ip,
			 subnet, k->port);
	} else {
		snprintf(buf, sizeof(buf), "%d %s:%d", k->protocol, raw_ip,
			 k->port);
	}
	return buf;
}

const char *optstring_from_long_options(const struct option *opt)
{
	static char optstring[256] = {0};
	char *osp = optstring;

	for (; opt->name != NULL; opt++) {
		if (opt->flag == 0 && opt->val > 0 && opt->val < 256) {
			*osp++ = opt->val;
			switch (opt->has_arg) {
			case optional_argument:
				*osp++ = ':';
				*osp++ = ':';
				break;
			case required_argument:
				*osp++ = ':';
				break;
			}
		}
	}
	*osp++ = '\0';

	if (osp - optstring >= (int)sizeof(optstring)) {
		abort();
	}
	return optstring;
}

char ***argv_split(char **argv, const char *delimiter, int upper_bound, int max)
{
	upper_bound += 1;

	int child_no = 0;
	char ***child_argv = malloc(upper_bound * sizeof(char *));

	while (*argv) {
		int pos = 0;
		child_argv[child_no] = malloc(upper_bound * sizeof(char *));
		for (; *argv; argv++) {
			if (strcmp(*argv, delimiter) == 0 && max > 1) {
				argv++;
				break;
			} else {
				child_argv[child_no][pos++] = *argv;
			}
		}
		max -= 1;
		child_argv[child_no][pos++] = NULL;
		child_argv[child_no] =
			realloc(child_argv[child_no], pos * sizeof(char *));
		child_no += 1;
	}
	child_argv[child_no] = NULL;
	child_no += 1;
	return realloc(child_argv, child_no * sizeof(char *));
}

int argv_len(char **argv)
{
	if (argv == NULL) {
		return 0;
	}
	int i;
	for (i = 0; argv[i]; i++) {
	}
	return i;
}

char **parse_argv(const char *str, char delim)
{
	int str_len = strlen(str);
	int i, items = 1;
	for (i = 0; i < str_len; i++) {
		if (str[i] == delim) {
			items += 1;
		}
	}

	char **argv = malloc(sizeof(char *) * (items + 1) + str_len + 1);
	char *nstr = (char *)&argv[items + 1];
	memcpy(nstr, str, str_len + 1);

	char delim_s[2] = {delim, '\x00'};
	char *s = nstr, *saveptr = NULL, **a = argv;

	for (;; s = NULL) {
		char *token = strtok_r(s, delim_s, &saveptr);
		if (token == NULL)
			break;

		a[0] = token;
		a += 1;
	}
	*a = NULL;

	return argv;
}

/* Returns malloced memory */
char *argv_join(char **argv, const char *delim)
{
	int len = 0, delim_len = strlen(delim);
	char **a;
	for (a = argv; *a; a++) {
		len += strlen(*a) + delim_len;
	}
	if (len)
		len -= delim_len;
	char *s = malloc(len + 1), *p = s;
	for (a = argv; *a; a++) {
		if (a != argv)
			p = stpcpy(p, delim);
		p = stpcpy(p, *a);
	}
	*p = '\0';
	return s;
}

uint64_t get_net_ns_inode()
{
	int ns_fd = open("/proc/self/ns/net", O_RDONLY);
	if (ns_fd < 0) {
		return 0;
	}
	struct stat stat;
	int r = fstat(ns_fd, &stat);
	close(ns_fd);
	if (r != 0) {
		return 0;
	}

	return stat.st_ino;
}

int find_inherited_fd(int last_fd, int *skip_fds, int *domain, int *sock_type,
		      int *protocol)
{
	int ebadf_errors_allowed = 32;
	int fd;
	for (fd = last_fd + 1; ebadf_errors_allowed > 0; fd++) {
		int *s;

		for (s = skip_fds; *s != -1; s++) {
			if (fd == *s) {
				goto again;
			}
		}
		socklen_t len = sizeof(*domain);
		errno = 0;
		int r = getsockopt(fd, SOL_SOCKET, SO_DOMAIN, domain, &len);
		if (r) {
			if (errno == EBADF) {
				ebadf_errors_allowed--;
			}
			continue;
		}
		len = sizeof(*sock_type);
		r = getsockopt(fd, SOL_SOCKET, SO_TYPE, sock_type, &len);
		if (r) {
			continue;
		}
		len = sizeof(*protocol);
		r = getsockopt(fd, SOL_SOCKET, SO_PROTOCOL, protocol, &len);
		if (r) {
			continue;
		}
		return fd;
	again:;
	}
	return -1;
}

static void clear_net_bottombits(uint8_t *dst, int dst_sz, int bottombits)
{
	size_t bytes = bottombits / 8;

	if (dst_sz * 8 <= bottombits) {
		memset(dst, 0, dst_sz);
		return;
	}

	memset(dst + dst_sz - bytes, 0, bytes);
	if (bottombits & 7)
		dst[dst_sz - bytes - 1] &= 0xff << (bottombits & 7);
}

int get_bottombits(struct sockaddr_storage *ss, int subnet)
{
	int bottombits = 0;
	if (subnet >= 0) {
		if (ss->ss_family == AF_INET) {
			bottombits = 32 - subnet;
		}
		if (ss->ss_family == AF_INET6) {
			bottombits = 128 - subnet;
		}
	}
	return bottombits;
}

void parse_inet_addr(struct inet_addr *addr, char *protocol, char *host)
{
	addr->protocol = atoi(protocol);

	int subnet = -1;
	net_parse_sockaddr(&addr->ss, host, &subnet);
	if (subnet < 0) {
		if (addr->ss.ss_family == AF_INET) {
			subnet = 32;
		}
		if (addr->ss.ss_family == AF_INET6) {
			subnet = 128;
		}
	}
	addr->subnet = subnet;

	int bottombits = get_bottombits(&addr->ss, subnet);
	if (addr->ss.ss_family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in *)&addr->ss;
		clear_net_bottombits((uint8_t *)&sin->sin_addr,
				     sizeof(sin->sin_addr), bottombits);
	}
	if (addr->ss.ss_family == AF_INET6) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&addr->ss;
		clear_net_bottombits((uint8_t *)&sin6->sin6_addr,
				     sizeof(sin6->sin6_addr), bottombits);
	}
}
