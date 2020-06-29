/* common */

#define PFATAL(x...)                                                           \
	do {                                                                   \
		fprintf(stderr, "[-] SYSTEM ERROR : " x);                      \
		fprintf(stderr, "\n\tLocation : %s(), %s:%u\n", __FUNCTION__,  \
			__FILE__, __LINE__);                                   \
		perror("      OS message ");                                   \
		fprintf(stderr, "\n");                                         \
		exit(EXIT_FAILURE);                                            \
	} while (0)

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#define KERNEL_VERSION(a, b, c) ((a)*65536 + (b)*256 + (c))

/* inet-tool.c */
struct state {
	char sys_fs_obj_prefix[256];

	int map_fds[128];

	char *unix_path;
};

struct inet_addr {
	int protocol;		    // tcp or udp
	struct sockaddr_storage ss; // inet or inet6, port
	int subnet;		    // 32/128 by default. 0 is valid
};

/* inet-commands.c */
void inet_load(struct state *state);
int inet_unload(struct state *state);
int inet_prog_info(struct state *state);
int inet_prog_verify(void);
void inet_open_verify_maps(struct state *state, int all_needed);

void inet_list(struct state *state);
void inet_register(struct state *state, char **fdnames, char **srvnames);
void inet_unregister(struct state *state, char *service);

int find_inherited_fd(int last_fd, int *skip_fds, int *domain, int *sock_type,
		      int *protocol);
int inet_register_socket(struct state *state, int fd, char *fdname);

void inet_bind(struct state *state, struct inet_addr *addr, char *service);
void inet_unbind(struct state *state, struct inet_addr *addr);

/* inet-scm.c */
void inet_scm_serve(struct state *state);
void inet_scm_register(struct state *state, char **fdnames, char **srvnames);

/* net.c */
int net_parse_sockaddr(struct sockaddr_storage *ss, const char *addr,
		       int *subnet_ptr);
const char *net_ntop(struct sockaddr_storage *ss);

/* utils.c */
struct addr;
struct option;
const char *sprint_addr(struct addr *k);
const char *optstring_from_long_options(const struct option *opt);
char ***argv_split(char **argv, const char *delimiter, int upper_bound,
		   int max);
int argv_len(char **argv);
char **parse_argv(const char *str, char delim);
char *argv_join(char **argv, const char *delim);
uint64_t get_net_ns_inode();
struct addr *parse_addr(char *txt_addr, struct addr *localaddr);

void parse_inet_addr(struct inet_addr *addr, char *protocol, char *host);
int get_bottombits(struct sockaddr_storage *ss, int subnet);

void bump_memlimit();

/* misc */
#ifdef CODE_COVERAGE
void __gcov_flush(void);
#else
inline static void __gcov_flush(void) {}
#endif
