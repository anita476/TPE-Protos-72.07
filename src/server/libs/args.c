// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
#include <../include/logger.h> /* to set log level */
#include <errno.h>
#include <getopt.h>
#include <limits.h> /* LONG_MIN et al */
#include <stdint.h> /* for uint8_t */
#include <stdio.h>	/* for printf */
#include <stdlib.h> /* for exit */
#include <string.h> /* memset */

#include "../../shared/include/calsetting_protocol.h"
#include "../include/args.h"

static unsigned short port(const char *s) {
	char *end = 0;
	const long sl = strtol(s, &end, 10);

	if (end == s || '\0' != *end || ((LONG_MIN == sl || LONG_MAX == sl) && ERANGE == errno) || sl < 0 ||
		sl > USHRT_MAX) {
		fprintf(stderr, "Port should be in the range of 1-65536: %s\n", s);
		exit(1);
		return 1;
	}
	return (unsigned short) sl;
}

static void user(char *s, struct user *user) {
	char *p = strchr(s, ':');
	if (p == NULL) {
		fprintf(stderr, "Password not found\n");
		exit(1);
	} else {
		*p = 0;
		p++;
		user->name = s;
		user->pass = p;
		user->type = USER_TYPE_CLIENT;
	}
}

static void admin(char *s, struct user *user) {
	char *p = strchr(s, ':');
	if (p == NULL) {
		fprintf(stderr, "Password not found\n");
		exit(1);
	} else {
		*p = 0;
		p++;
		user->name = s;
		user->pass = p;
		user->type = USER_TYPE_ADMIN;
	}
}

static int username_exists(const char *name, struct user *users, int nusers) {
	for (int i = 0; i < nusers; i++) {
		if (strcmp(users[i].name, name) == 0) {
			return 1;
		}
	}
	return 0;
}

static int validate_and_check_username(const char *optarg, struct user *users, int nusers) {
	char tmp[USERNAME_MAX_SIZE + 1];
	strncpy(tmp, optarg, USERNAME_MAX_SIZE);
	tmp[USERNAME_MAX_SIZE] = '\0';
	char *p = strchr(tmp, ':');
	if (p == NULL) {
		fprintf(stderr, "Password not found\n");
		return 0;
	}
	*p = '\0';
	const char *password = p + 1;
	if (strlen(password) == 0) {
		fprintf(stderr, "Password cannot be empty for user: %s\n", tmp);
		return 0;
	}
	if (username_exists(tmp, users, nusers)) {
		fprintf(stderr, "Duplicate username not allowed: %s\n", tmp);
		return 0;
	}
	return 1;
}

static void version(void) {
	fprintf(stderr, "socks5v version 1.0\n"
					"ITBA Protocolos de Comunicación 2025/1 -- Grupo 04\n"
					"MIT License\n"
					"Copyright (c) 2025 Ana Negre, Matías Leporini, Camila Lee, Juan Amancio Oliva Morroni\n"
					"Permission is hereby granted, free of charge, to any person obtaining a copy"
					"of this software and associated documentation files (the 'Software'), to deal"
					"in the Software without restriction, including without limitation the rights"
					"to use, copy, modify, merge, publish, distribute, sublicense, and/or sell"
					"copies of the Software, and to permit persons to whom the Software is"
					"furnished to do so, subject to the following conditions:\n"
					"The above copyright notice and this permission notice shall be included in all"
					"copies or substantial portions of the Software.\n"

					"THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND, EXPRESS OR"
					"IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,"
					"FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE"
					"AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER"
					"LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,"
					"OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE"
					"SOFTWARE.\n");
}

static void usage(const char *progname) {
	fprintf(stderr,
			"Usage: %s [OPTION]...\n"
			"\n"
			"   -h                    Prints this help and exits.\n"
			"   -l <SOCKS addr>       Address where the SOCKS proxy will serve.\n"
			"   -L <conf addr>        Address where the management service will serve.\n"
			"   -p <SOCKS port>       Incoming port for SOCKS connections.\n"
			"   -P <conf port>        Incoming port for management connections.\n"
			"   -u <name>:<pass>      Username and password for a user allowed to use the proxy. Up to 10 users + administrators total.\n"
			"   -a <name>:<pass>      Username and password for an administrator allowed to use the proxy. Up to 10 users + administrators total.\n"
			"   -v                    Prints version information and exits.\n"
			"   -g/--log <LOG LEVEL>  Sets the log level. Can be DEBUG, INFO, ERROR, or FATAL.\n"
			"   -s                    Disables all logging levels.\n"
			"\n",
			progname);
	exit(1);
}

void parse_args(const int argc, char **argv, struct socks5args *args) {
	memset(args, 0, sizeof(*args)); // Mainly to set the user pointers in null

	args->socks_addr = "::";
	args->socks_port = 1080;

	args->mng_addr = "127.0.0.1";
	args->mng_port = 8080;

	args->disectors_enabled = true;

	int c;
	int nusers = 0;

	while (true) {
		int option_index = 0;
		static struct option long_options[] = {{"log", required_argument, 0, 'g'}, {0, 0, 0, 0}};

		c = getopt_long(argc, argv, "hl:L:Np:P:u:a:vg:s", long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
			case 'h':
				usage(argv[0]);
				break;
			case 'l':
				args->socks_addr = optarg;
				break;
			case 'L':
				args->mng_addr = optarg;
				break;
			case 'N':
				args->disectors_enabled = false;
				break;
			case 'p':
				args->socks_port = port(optarg);
				break;
			case 'P':
				args->mng_port = port(optarg);
				break;
			case 'u':
				if (nusers >= MAX_USERS) {
					fprintf(stderr, "Maximum number of command line users reached: %d.\n", MAX_USERS);
					exit(1);
				} else if (!validate_and_check_username(optarg, args->users, nusers)) {
					exit(1);
				} else {
					user(optarg, args->users + nusers);
					nusers++;
				}
				break;
			case 'a':
				if (nusers >= MAX_USERS) {
					fprintf(stderr, "Maximum number of command line admins reached: %d.\n", MAX_USERS);
					exit(1);
				} else if (!validate_and_check_username(optarg, args->users, nusers)) {
					exit(1);
				} else {
					admin(optarg, args->users + nusers);
					nusers++;
				}
				break;
			case 'v':
				version();
				exit(0);
			case 'g':
				if (optarg) {
					args->log_level = optarg;
					if (strcmp(args->log_level, "DEBUG") == 0)
						setLogLevel(DEBUG);
					else if (strcmp(args->log_level, "INFO") == 0)
						setLogLevel(INFO);
					else if (strcmp(args->log_level, "ERROR") == 0)
						setLogLevel(ERROR);
					else if (strcmp(args->log_level, "FATAL") == 0)
						setLogLevel(FATAL);
					else {
						fprintf(stderr, "Unknown log level: %s\n", args->log_level);
						exit(1); // Could also let it default or smth
					}
				}
				break;
			case 's':
				// silent option
				disableLogging();
				break;
			default:
				fprintf(stderr, "Unknown argument %d.\n", c);
				exit(1);
		}
	}
	if (optind < argc) {
		fprintf(stderr, "Argument not accepted: ");
		while (optind < argc) {
			fprintf(stderr, "%s ", argv[optind++]);
		}
		fprintf(stderr, "\n");
		exit(1);
	}
	args->nusers = nusers;
}
