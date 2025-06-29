#include "../include/args.h"
#include <stdio.h>

int main(int argc, char **argv) {
	struct socks5args args;
	printf("Starting server...\n");
	parse_args(argc, argv, &args);
	printf("Im serving\n");
	return 0;
}