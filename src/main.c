#include <arpa/inet.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "inet.h"

void print_usage()
{
	printf(
#include "help.txt"
	);
}

enum commands {
	CMD_UNLOAD,
	CMD_LOAD,
	CMD_INFO,
	CMD_LIST,
	CMD_BIND,
	CMD_UNBIND,
	CMD_REGISTER,
	CMD_UNREGISTER,
	CMD_SCM_SERVE,
	CMD_SCM_REGISTER,
};

struct {
	char *txt;
	int cmd;
} commands_txt[] = {
	{"unload", CMD_UNLOAD},
	{"load", CMD_LOAD},
	{"info", CMD_INFO},
	{"list", CMD_LIST},
	{"bind", CMD_BIND},
	{"unbind", CMD_UNBIND},
	{"register", CMD_REGISTER},
	{"unregister", CMD_UNREGISTER},
	{"scm_serve", CMD_SCM_SERVE},
	{"scm_register", CMD_SCM_REGISTER},
	{NULL, -1},
};

int main(int argc, char *argv[])
{
	int return_code = 0;

	struct state *state = (struct state *)calloc(sizeof(struct state), 1);
	state->unix_path = "@inet-scm-service";
	uint64_t net_ns_inode = get_net_ns_inode();
	if (net_ns_inode == 0) {
		PFATAL("open(/proc/self/ns/net)");
	}

	snprintf(state->sys_fs_map_prefix, sizeof(state->sys_fs_map_prefix),
		 "/sys/fs/bpf/%lu_", net_ns_inode);

	bump_memlimit();

	/* Split argv into two parts - before and after -- *
	 * getopt_long() does an interesting thing. It removes the
	 * first iteration of "--" argument. The semantics are: on the
	 * first "--" argument, stop parsing others. This is fine, but
	 * we need more - we want to know just where that argument is
	 * present. So we do a hack - we split the ist into two parts,
	 * and getopt parse only first. */
	char ***list_of_argv = argv_split(argv, "--", argc, 2);

	{
		static struct option long_options[] = {
			{"unix", required_argument, 0, 'u'},
			{"help", no_argument, 0, 'h'},
			{NULL, 0, 0, 0}};
		optind = 1;
		while (1) {
			int option_index = 0;
			int arg = getopt_long(
				argv_len(list_of_argv[0]), list_of_argv[0],
				optstring_from_long_options(long_options),
				long_options, &option_index);
			if (arg == -1) {
				break;
			}

			switch (arg) {
			default:
			case 0:
				fprintf(stderr, "Unknown option: %s",
					list_of_argv[0][optind]);
				exit(-1);
				break;
			case '?':
				exit(-1);
				break;
			case 'u':
				state->unix_path = optarg;
				break;
			case 'h':
				print_usage();
				exit(0);
				break;
			}
		}
	}

	char *cmd = list_of_argv[0][optind];

	if (cmd == NULL) {
		fprintf(stderr,
			"[!] Select a command. Perhaps \"inet-tool info\" or "
			"\"inet-tool list\".\n");
		exit(-1);
	}

	int command = -1;
	int i;
	for (i = 0; commands_txt[i].txt != NULL; i++) {
		if (strcmp(cmd, commands_txt[i].txt) == 0) {
			command = commands_txt[i].cmd;
			break;
		}
	}
	if (command < 0) {
		fprintf(stderr,
			"[!] Unknown operation \"%s\", try \"inet-tool "
			"--help\".\n",
			cmd);
		exit(3);
	}

	/* Parsing env needed for "register" and "scm_register" cmds. */
	char **fdnames_argv = NULL;
	const char *listen_fdnames = getenv("LISTEN_FDNAMES");
	if (listen_fdnames != NULL) {
		fdnames_argv = parse_argv(listen_fdnames, ':');
	}

	if (command == CMD_UNLOAD) {
		/* we can unlink maps without opening them. */
		return_code = inet_unload(state);
		goto cleanup;
	}

	if (command == CMD_SCM_REGISTER) {
		/*  SCM_REGISTER is is unpriviledged. run it before
		 *  map operations. */
		inet_scm_register(state, fdnames_argv,
				  &list_of_argv[0][optind + 1]);

		if (list_of_argv[0] && list_of_argv[1]) {
			char **child_argv = list_of_argv[1];
			char *flat_argv = argv_join(child_argv, " ");
			fprintf(stderr, "[+] %i running: %s\n", getpid(),
				flat_argv);
			free(flat_argv);
			__gcov_flush();
			execvp(child_argv[0], child_argv);
			PFATAL("execvp()");
		}
		goto cleanup;
	}

	inet_open_verify_maps(state, 0);

	if (command == CMD_LOAD) {
		inet_load(state);
		goto cleanup;
	}

	if (command == CMD_INFO) {
		return_code = inet_prog_info(state);
		goto cleanup;
	}

	int recognized = inet_prog_verify();
	if (recognized == -1) {
		fprintf(stderr,
			"[!] INET_LOOKUP program not found. "
			"Consdider running \"inet-tool load\".\n");
		exit(-1);
	}

	if (recognized == 0) {
		fprintf(stderr,
			"[!] INET_LOOKUP program version is "
			"unrecognized. "
			"Consdider running \"inet-tool unload; inet-tool "
			"load\"\n");
		exit(-1);
	}

	inet_open_verify_maps(state, 1);

	if (command == CMD_LIST) {
		inet_list(state);
		goto cleanup;
	}

	if (command == CMD_BIND) {
		if (argv_len(&list_of_argv[0][optind + 1]) != 3) {
			PFATAL("bind takes three parameters");
		}

		struct inet_addr addr = {};
		parse_inet_addr(&addr, list_of_argv[0][optind + 1],
				list_of_argv[0][optind + 2]);

		char *service = list_of_argv[0][optind + 3];

		inet_bind(state, &addr, service);
		goto cleanup;
	}

	if (command == CMD_UNBIND) {
		if (argv_len(&list_of_argv[0][optind + 1]) < 2) {
			PFATAL("unbind takes two parameters");
		}
		struct inet_addr addr = {};
		parse_inet_addr(&addr, list_of_argv[0][optind + 1],
				list_of_argv[0][optind + 2]);

		inet_unbind(state, &addr);
		goto cleanup;
	}

	if (command == CMD_REGISTER) {
		inet_register(state, fdnames_argv,
			      &list_of_argv[0][optind + 1]);

		if (list_of_argv[0] && list_of_argv[1]) {
			char **child_argv = list_of_argv[1];
			char *flat_argv = argv_join(child_argv, " ");
			fprintf(stderr, "[+] %i running: %s\n", getpid(),
				flat_argv);
			free(flat_argv);
			__gcov_flush();
			execvp(child_argv[0], child_argv);
			PFATAL("execvp()");
		}
		goto cleanup;
	}

	if (command == CMD_UNREGISTER) {
		if (argv_len(&list_of_argv[0][optind + 1]) != 1) {
			PFATAL("unregister takes one parameter");
		}
		char *service = list_of_argv[0][optind + 1];

		inet_unregister(state, service);
		goto cleanup;
	}

	if (command == CMD_SCM_SERVE) {
		setbuf(stdout, NULL);
		printf("[+] Waiting for SCM_RIGHTS sockets on %s\n",
		       state->unix_path);
		inet_scm_serve(state);
		goto cleanup;
	}

	PFATAL("Unhandled command");
cleanup:
	/* Free memory */
	if (fdnames_argv) {
		free(fdnames_argv);
	}

	{
		char ***child_argv = list_of_argv;
		while (*child_argv) {
			free(*child_argv);
			child_argv++;
		}
		free(list_of_argv);
	}

	free(state);
	return return_code;
}
