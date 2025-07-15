// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
#include "include/args.h"
#include "include/config.h"
#include "include/logger.h"
#include "include/management.h"
#include "include/metrics.h"
#include "include/selector.h"
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
static bool done = false;  // Flag to indicate when the server should stop
extern struct user *users; // Global users array
extern uint8_t nusers;	   // Number of users

void load_users(struct user *u, uint8_t n) { // Change the parameter type
	users = u;
	nusers = n;
}

static void sigterm_handler(const int signal);
static void exit_error(const char *error_msg, int errnum);

static struct socks5args args;

// For IPv6 addresses -> setup is dual-stack (accepts both IPv4 and IPv6 connections)
// For IPv4 addresses -> setup is IPv4-only (accepts only IPv4 connections)
// If no address is specified, it defaults to "::" (IPv6 wildcard)
int setupServerSocket(const char *service, const char *addr) {
	struct addrinfo addrCriteria;
	memset(&addrCriteria, 0, sizeof(addrCriteria));

	addrCriteria.ai_family = AF_UNSPEC; // Allow IPv4 or IPv6
	addrCriteria.ai_flags = AI_PASSIVE; // For bind()
	addrCriteria.ai_socktype = SOCK_STREAM;
	addrCriteria.ai_protocol = IPPROTO_TCP;

	struct addrinfo *servAddr;
	int rtnVal = getaddrinfo(addr, service, &addrCriteria, &servAddr);
	if (rtnVal != 0) {
		log(ERROR, "getaddrinfo() failed: %s", gai_strerror(rtnVal));
		// Set errno based on getaddrinfo error for consistency
		switch (rtnVal) {
			case EAI_NONAME:
				errno = ENOENT;
				break;
			case EAI_SERVICE:
				errno = EINVAL;
				break;
			case EAI_MEMORY:
				errno = ENOMEM;
				break;
			default:
				errno = EINVAL;
				break;
		}
		return -1;
	}

	int servSock = -1;
	int saved_errno = 0;
	char addrBuffer[INET6_ADDRSTRLEN + 16]; // Extra space for port

	// Try each address until one succeeds
	for (struct addrinfo *ai = servAddr; ai != NULL; ai = ai->ai_next) {
		servSock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (servSock < 0) {
			saved_errno = errno;
			continue;
		}

		// Set SO_REUSEADDR to avoid "Address already in use" errors
		int opt = 1;
		if (setsockopt(servSock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
			saved_errno = errno;
			log(ERROR, "setsockopt(SO_REUSEADDR) failed: %s", strerror(errno));
			close(servSock);
			servSock = -1;
			continue;
		}

		// For IPv6, try to enable dual-stack (accept IPv4 connections too)
		if (ai->ai_family == AF_INET6) {
			int v6only = 0;
			if (setsockopt(servSock, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only)) < 0) {
				// Not fatal - continue with IPv6-only
				log(ERROR, "Cannot enable dual-stack mode: %s", strerror(errno));
			}
		}

		if (bind(servSock, ai->ai_addr, ai->ai_addrlen) == 0) {
			if (listen(servSock, SOMAXCONN) == 0) {
				log(INFO, "Server listening on %s", sockaddr_to_human(addrBuffer, sizeof(addrBuffer), ai->ai_addr));

				// If IPv6 dual-stack is enabled, mention it
				if (ai->ai_family == AF_INET6) {
					int v6only;
					socklen_t optlen = sizeof(v6only);
					if (getsockopt(servSock, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, &optlen) == 0) {
						if (!v6only) {
							log(INFO, "Dual-stack mode enabled (accepts IPv4 and IPv6)");
						}
					}
				}

				freeaddrinfo(servAddr);
				return servSock;
			}
			saved_errno = errno;
			log(FATAL, "listen() failed on %s: %s", sockaddr_to_human(addrBuffer, sizeof(addrBuffer), ai->ai_addr),
				strerror(errno));
		} else {
			saved_errno = errno;
			log(FATAL, "bind() failed on %s: %s", sockaddr_to_human(addrBuffer, sizeof(addrBuffer), ai->ai_addr),
				strerror(errno));
		}

		close(servSock);
		servSock = -1;
	}

	freeaddrinfo(servAddr);
	errno = saved_errno;
	log(ERROR, "Failed to create server socket");
	return -1;
}

int main(int argc, char **argv) {
	/********************************************** SETTING UP THE SERVER  ***********************/

	printf("Starting server...\n");
	parse_args(argc, argv, &args);
	load_users(args.users, args.nusers); //
	metrics_init();

	close(0);
	// flags
	const char *error_msg = NULL;
	selector_status selectorStatus = SELECTOR_SUCCESS;
	selector_status selectorMngStatus = SELECTOR_SUCCESS;

	char portStr[16];
	char mngPortStr[16];
	snprintf(portStr, sizeof(portStr), "%hu", args.socks_port);
	snprintf(mngPortStr, sizeof(mngPortStr), "%hu", args.mng_port);

	int socksFd = setupServerSocket(portStr, args.socks_addr);
	if (socksFd < 0) {
		error_msg = "Failed to setup SOCKS5 server socket";
		exit_error(error_msg, errno);
	};
	int mngFd = setupServerSocket(mngPortStr, args.mng_addr);
	if (mngFd < 0) {
		error_msg = "Failed to setup CalSetting server socket";
		exit_error(error_msg, errno);
	};
	log(INFO, "SOCKS5 socket with fd %d", socksFd);
	log(INFO, "CalSetting socket with fd %d", mngFd);

	/*
	** It takes a socket (srv file descriptor)
	** that was previously set up with socket() and bind() and marks it as a passive socket
	** n is the queue max length -> we use SOMAXCONN to set it to the SO dfined max, probably a bit overkill
	*/

	// Register the handlers for sigterm and sigint to then exit nicely
	signal(SIGTERM, sigterm_handler);
	signal(SIGINT, sigterm_handler);

	if (selector_fd_set_nio(socksFd) == -1) {
		error_msg = "Error setting flags for SOCKS5 server socket";
		exit_error(error_msg, errno);
	}
	if (selector_fd_set_nio(mngFd) == -1) {
		error_msg = "Error setting flags for CalSetting server socket";
		exit_error(error_msg, errno);
	}
	const struct selector_init configuration = {
		.signal = SIGALRM,
		.select_timeout =
			{
				.tv_sec = 10, // default falback timeout
				.tv_nsec = 0,
			},
	};
	if (selector_init(&configuration) != 0) {
		error_msg = "Error initializing selector";
		exit_error(error_msg, errno);
	}
	selector = selector_new(1024);
	if (selector == NULL) {
		error_msg = "Error creating selector";
		exit_error(error_msg, 2);
	}

	const struct fd_handler socks5Handler = {
		.handle_read = socks5_handle_new_connection, .handle_write = NULL, .handle_close = NULL};
	selectorStatus = selector_register(selector, socksFd, &socks5Handler, OP_READ, NULL);

	const struct fd_handler mngHandler = {
		.handle_read = management_handle_new_connection, .handle_write = NULL, .handle_close = NULL};
	selectorMngStatus = selector_register(selector, mngFd, &mngHandler, OP_READ, NULL);

	if (selectorStatus != SELECTOR_SUCCESS) {
		error_msg = "Error registering SOCKS5 server socket with selector";
		exit_error(error_msg, selectorStatus);
	}
	if (selectorMngStatus != SELECTOR_SUCCESS) {
		error_msg = "Error registering management CalSetting server socket with selector";
		exit_error(error_msg, selectorMngStatus);
	}
	// Until sigterm or sigint, run server loop
	for (; !done;) {
		error_msg = NULL;
		selectorStatus = selector_select(selector);
		if (selectorStatus != SELECTOR_SUCCESS) {
			error_msg = "Error during serving";
			exit_error(error_msg, selectorStatus);
		}
	}

	if (selector != NULL) {
		selector_destroy(selector);
	}
	selector_close();

	// cleanup
	metrics_cleanup();

	exit(0);
}

/********************************** helpers *****************************************/
static void sigterm_handler(const int signal) {
	log(INFO, "Received signal %d, shutting down server", signal);
	done = true;
}
static void exit_error(const char *error_msg, int errnum) {
	if (errnum != 0) {
		fprintf(stderr, "Error: %s - %s (errno=%d)\n", error_msg, strerror(errnum), errnum);
	} else {
		fprintf(stderr, "Error: %s\n", error_msg);
	}

	// cleanup
	if (selector != NULL) {
		selector_destroy(selector);
	}
	selector_close();
	metrics_cleanup();

	exit(errnum != 0 ? errnum : 1);
}
