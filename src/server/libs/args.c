#include <errno.h>
#include <getopt.h>
#include <limits.h> /* LONG_MIN et al */
#include <stdio.h>	/* for printf */
#include <stdlib.h> /* for exit */
#include <string.h> /* memset */

#include "../include/args.h"

static unsigned short port(const char *s) {
	char *end = 0;
	const long sl = strtol(s, &end, 10);

	if (end == s || '\0' != *end || ((LONG_MIN == sl || LONG_MAX == sl) && ERANGE == errno) || sl < 0 ||
		sl > USHRT_MAX) {
		fprintf(stderr, "Port should in in the range of 1-65536: %s\n", s);
		exit(1);
		return 1;
	}
	return (unsigned short) sl;
}

static void user(char *s, struct users *user) {
	char *p = strchr(s, ':');
	if (p == NULL) {
		fprintf(stderr, "Password not found\n");
		exit(1);
	} else {
		*p = 0;
		p++;
		user->name = s;
		user->pass = p;
	}
}

static void version(void) {
	fprintf(stderr, "socks5v version 0.0\n"
					"ITBA Protocolos de Comunicación 2025/1 -- Grupo 04\n"
					"MIT License"
					"Copyright (c) 2025 Ana Negre"
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
			"   -h               Imprime la ayuda y termina.\n"
			"   -l <SOCKS addr>  Dirección donde servirá el proxy SOCKS.\n"
			"   -L <conf  addr>  Dirección donde servirá el servicio de management.\n"
			"   -p <SOCKS port>  Puerto entrante conexiones SOCKS.\n"
			"   -P <conf port>   Puerto entrante conexiones configuracion\n"
			"   -u <name>:<pass> Usuario y contraseña de usuario que puede usar el proxy. Hasta 10.\n"
			"   -v               Imprime información sobre la versión versión y termina.\n"

			"\n",
			progname);
	exit(1);
}

void parse_args(const int argc, char **argv, struct socks5args *args) {
	memset(args, 0, sizeof(*args)); // sobre todo para setear en null los punteros de users

	args->socks_addr = "0.0.0.0";
	args->socks_port = 1080;

	args->mng_addr = "127.0.0.1";
	args->mng_port = 8080;

	args->disectors_enabled = true;

	int c;
	int nusers = 0;

	while (true) {
		int option_index = 0;
		static struct option long_options[] = {{0, 0, 0, 0}};

		c = getopt_long(argc, argv, "hl:L:Np:P:u:v", long_options, &option_index);
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
				} else {
					user(optarg, args->users + nusers);
					nusers++;
				}
				break;
			case 'v':
				version();
				exit(0);
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
