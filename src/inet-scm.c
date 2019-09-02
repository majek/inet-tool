#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "libbpf_ebpf.h"
#include "linux_bpf.h"

#include "inet.h"

#define SOCKADDR_UN_SIZE(sun)                                                  \
	((sun)->sun_path[0] == '\x00' ? 3 + strnlen(&(sun)->sun_path[1], 108)  \
				      : sizeof(struct sockaddr_un))

int recv_fd(int sd, char *buf, int buf_sz)
{
	struct iovec iov = {
		.iov_base = buf,
		.iov_len = buf_sz,
	};
	char ctrl[512];
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = ctrl,
		.msg_controllen = sizeof(ctrl),
	};
	int r = recvmsg(sd, &msg, 0);
	if (r < 0) {
		PFATAL("recvmsg()");
	}
	if (r < buf_sz) {
		buf[r] = '\x00';
	} else {
		buf[buf_sz - 1] = '\x00';
	}

	int fd = -1;
	struct cmsghdr *cmsg;
	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
	     cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level == SOL_SOCKET &&
		    cmsg->cmsg_type == SCM_RIGHTS) {
			int recv_fds_no =
				(cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
			int *recv_fds = (int *)CMSG_DATA(cmsg);
			int i;
			for (i = 0; i < recv_fds_no; i++) {
				if (i == 0) {
					fd = recv_fds[i];
				} else {
					printf("[!] too many fds passed");
					close(recv_fds[i]);
				}
			}
		}
	}
	return fd;
}

void inet_scm_serve(struct state *state)
{
	int sd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (sd < 0) {
		PFATAL("socket()");
	}
	struct sockaddr_un unix_addr = {
		.sun_family = AF_UNIX,
	};
	strncpy(unix_addr.sun_path, state->unix_path,
		sizeof(unix_addr.sun_path));
	/* Abstract socket */
	if (unix_addr.sun_path[0] == '@') {
		unix_addr.sun_path[0] = '\x00';
	}

	int r = bind(sd, (struct sockaddr *)&unix_addr,
		     SOCKADDR_UN_SIZE(&unix_addr));
	if (r != 0) {
		if (errno == EADDRINUSE) {
			char buf[256];
			strncpy(buf, unix_addr.sun_path, sizeof(buf));
			char *dirn = dirname(buf);
			int dirfd = open(dirn, O_DIRECTORY | O_RDONLY);
			if (dirfd < 0) {
				errno = EADDRINUSE;
				PFATAL("bind()");
			}

			strncpy(buf, unix_addr.sun_path, sizeof(buf));
			char *basen = basename(buf);
			struct stat statbuf = {};
			r = fstatat(dirfd, basen, &statbuf, 0);
			if (r) {
				close(dirfd);
				errno = EADDRINUSE;
				PFATAL("bind()");
			}
			if ((statbuf.st_mode & S_IFMT) == S_IFSOCK) {
				unlinkat(dirfd, basen, 0);
			}
			close(dirfd);

			/* try again */
			r = bind(sd, (struct sockaddr *)&unix_addr,
				 SOCKADDR_UN_SIZE(&unix_addr));
		}
		if (r != 0) {
			PFATAL("bind()");
		}
	}

	while (1) {
		__gcov_flush();
		char fdname[32];
		int fd = recv_fd(sd, fdname, sizeof(fdname));
		if (fd < 0) {
			continue;
		}

		int so_domain, so_type, so_protocol;
		socklen_t l = sizeof(int);
		getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &so_domain, &l);
		l = sizeof(int);
		getsockopt(fd, SOL_SOCKET, SO_TYPE, &so_type, &l);
		l = sizeof(int);
		getsockopt(fd, SOL_SOCKET, SO_PROTOCOL, &so_protocol, &l);

		struct sockaddr_storage ss = {};
		l = sizeof(ss);
		r = getsockname(fd, (struct sockaddr *)&ss, &l);
		if (r < 0) {
			PFATAL("getsockname()");
		}
		const char *addr = net_ntop(&ss);

		/* Fill in generic fdname */
		if ((strnlen(fdname, sizeof(fdname)) == 1 &&
		     fdname[0] == '@') ||
		    (strnlen(fdname, sizeof(fdname)) == 0)) {
			strncpy(fdname, addr, sizeof(fdname));
		}

		printf("[+] fd=%d fdname=%s domain=%d type=%d protocol=%d "
		       "sockname=%s\n",
		       fd, fdname, so_domain, so_type, so_protocol, addr);

		r = inet_register_socket(state, fd, fdname);
		if (r == -1) {
			fprintf(stderr,
				"[!] Socket must have SO_REUSEPORT set!\n");
		}
		if (r == -2) {
			fprintf(stderr, "[!] redir_map full!\n");
		}
		close(fd);
	}
	close(sd);
}

void inet_scm_register(struct state *state, char **fdnames, char **srvnames)
{
	int sd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (sd < 0) {
		PFATAL("socket()");
	}
	struct sockaddr_un unix_addr = {
		.sun_family = AF_UNIX,
	};
	strncpy(unix_addr.sun_path, state->unix_path,
		sizeof(unix_addr.sun_path));
	/* Abstract socket */
	if (unix_addr.sun_path[0] == '@') {
		unix_addr.sun_path[0] = '\x00';
	}

	int r = connect(sd, (struct sockaddr *)&unix_addr,
			SOCKADDR_UN_SIZE(&unix_addr));
	if (r != 0) {
		PFATAL("connect()");
	}

	int fd = -1;
	int skip_fds[] = {0, 1, 2, sd, -1};
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

			struct iovec iov = {
				.iov_base = name,
				.iov_len = strlen(name),
			};

			char ctrl[CMSG_SPACE(sizeof(int))] = {};
			struct msghdr msg = {
				.msg_iov = &iov,
				.msg_iovlen = 1,
				.msg_control = ctrl,
				.msg_controllen = sizeof(ctrl),
			};

			struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
			cmsg->cmsg_level = SOL_SOCKET;
			cmsg->cmsg_type = SCM_RIGHTS;
			cmsg->cmsg_len = CMSG_LEN(sizeof(int));
			int *fdptr = (int *)CMSG_DATA(cmsg);
			*fdptr = fd;

			fprintf(stderr,
				"[.] Registering service \"%s\" fd=%d "
				"domain=%d type=%d protocol=%d\n",
				name, fd, domain, sock_type, protocol);
			r = sendmsg(sd, &msg, 0);
			if (r < 0) {
				PFATAL("sendmsg()");
			}
		}
	}

	close(sd);
}
