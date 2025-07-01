#include "../include/args.h"
#include "../include/logger.h"
#include "../include/selector.h"
#include "../include/metrics.h"
#include "include/socks5.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/signal.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <unistd.h>
static fd_selector selector = NULL;
static bool done = false; // Flag to indicate when the server should stop

static void sigterm_handler(const int signal);
static void exit_error(const char *error_msg, int errnum);

/************* PLACEHOLDER FUNCTIONS CHANGE LATEEER */

static void handle_write(struct selector_key *key) {
	// placeholder for write
	log(INFO, "Write event on fd %d", key->fd);
}
static void handle_close(struct selector_key *key) {
	// Placeholder for close handler
	log(INFO, "Close event on fd %d", key->fd);
	// Clean up any data associated with this fd
    if (key->data) {
        free(key->data);
        key->data = NULL;
    }
    
    // DO NOT call selector_unregister_fd(key->s, key->fd); ← This causes infinite recursion!
    // DO NOT call close(key->fd); ← The selector will handle this
    
    log(DEBUG, "Cleanup complete for fd %d", key->fd)
}

// TODO expand parse args to include log level and eventually log file
int main(int argc, char **argv) {
	/********************************************** SETTING UP THE SERVER  ***********************/
	struct socks5args args;
	printf("Starting server...\n");
	// parse args is in charge of initializing the args struct, all info will be there (already should be rfc compliant)
	parse_args(argc, argv, &args);

	metrics_init();

	unsigned long socksPort = args.socks_port;
	// TODO delete
	log(DEBUG, "Using SOCKS5 port %lu", socksPort);

	close(0); // Close stdin to have one more fd available

	// flags
	const char *error_msg = NULL;
	selector_status selectorStatus = SELECTOR_SUCCESS;

	// TODO must attend to IPv6 addr also
	struct sockaddr_in socksAddr;
	memset(&socksAddr, 0, sizeof(socksAddr));
	socksAddr.sin_family = AF_INET;
	socksAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	socksAddr.sin_port = htons(socksPort);

	// open the socket (first one)
	int socksFd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (socksFd < 0) {
		error_msg = "Error creating SOCKS5 server socket";
		exit_error(error_msg, errno);
	}
	setsockopt(socksFd, SOL_SOCKET, SO_REUSEADDR, &(int) {1}, sizeof(int));
	if (bind(socksFd, (struct sockaddr *) &socksAddr, sizeof(socksAddr)) < 0) {
		error_msg = "Error binding SOCKS5 server socket";
		exit_error(error_msg, errno);
	}
	/*
	** It takes a socket (srv file descriptor)
	** that was previously set up with socket() and bind() and marks it as a passive socket
	** n is the queue max length -> we use SOMAXCONN to set it to the SO dfined max
	*/
	if (listen(socksFd, SOMAXCONN) < 0) {
		error_msg = "Error listening on SOCKS5 server socket";
		exit_error(error_msg, errno);
	}

	// Register the handlers for sigterm and sigint to then exit nicely
	signal(SIGTERM, sigterm_handler);
	signal(SIGINT, sigterm_handler);

	if (selector_fd_set_nio(socksFd) == -1) {
		error_msg = "Error setting flags for SOCKS5 server socket";
		exit_error(error_msg, errno);
	}
	const struct selector_init configuration = {
		.signal = SIGALRM, // TODO: ask what is sigALRM for?
		.select_timeout =
			{
				.tv_sec = 10,
				.tv_nsec = 0,
			},
	};
	if (selector_init(&configuration) != 0) {
		error_msg = "Error initializing selector";
		exit_error(error_msg, errno);
	}
	// maximum number of fds TODO make use of epoll <- is it necessary to use epoll?
	selector = selector_new(1024);
	if (selector == NULL) {
		error_msg = "Error creating selector";
		// todo create error enum
		exit_error(error_msg, 2);
	}

	const struct fd_handler socks5Handler = {// TODO complete the handler on close and so on
											 .handle_read = socks5_handle_new_connection,
											 .handle_write = handle_write,
											 .handle_close = handle_close};
	selectorStatus = selector_register(selector, socksFd, &socks5Handler, OP_READ, NULL);
	if (selectorStatus != SELECTOR_SUCCESS) {
		error_msg = "Error registering SOCKS5 server socket with selector";
		exit_error(error_msg, selectorStatus);
	}

	// Until sigterm or sigint, run server loop
	// TODO: dont close on client disconnect (SELECTOR_IO)
	for (; !done;) {
		error_msg = NULL;
		selectorStatus = selector_select(selector);
		if (selectorStatus != SELECTOR_SUCCESS) {
			error_msg = "Error during serving";
			exit_error(error_msg, selectorStatus);
		}
	}

	metrics_cleanup();

	exit(0);
}

/********************************** helpers *****************************************/
static void sigterm_handler(const int signal) {
	log(INFO, "Received signal %d, shutting down server", signal);
	done = true;
}
static void exit_error(const char *error_msg, int errnum) {
	fprintf(stderr, "Error message: %s\nError code: %s\n", error_msg, strerror(errnum));
	// cleanup
	if (selector != NULL) {
		selector_destroy(selector);
	}
	selector_close();
	exit(errnum);
}