#include "../include/socks5_utils.h"
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <metrics.h>

uint8_t map_getaddrinfo_error_to_socks5(int gai_error) {
	switch (gai_error) {
		case EAI_NONAME: // Name or service not known
		case EAI_AGAIN:	 // Temporary failure in name resolution
		case EAI_FAIL:	 // Non-recoverable failure in name resolution
			return SOCKS5_REPLY_HOST_UNREACHABLE;
		case EAI_FAMILY: // Address family not supported
			return SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED;
		case EAI_SERVICE:  // Service not supported for socket type
		case EAI_SOCKTYPE: // Socket type not supported
		case EAI_MEMORY:   // Memory allocation failure
		case EAI_SYSTEM:   // System error (check errno)
		default:
			return SOCKS5_REPLY_GENERAL_FAILURE;
	}
}

uint8_t map_connect_error_to_socks5(int connect_errno) {
	switch (connect_errno) {
		case ECONNREFUSED:
			return SOCKS5_REPLY_CONNECTION_REFUSED;
		case EHOSTUNREACH:
			return SOCKS5_REPLY_HOST_UNREACHABLE;
		case ENETUNREACH:
			return SOCKS5_REPLY_NETWORK_UNREACHABLE;
		case ETIMEDOUT:
			return SOCKS5_REPLY_TTL_EXPIRED;
		case EACCES:
		case EPERM:
			return SOCKS5_REPLY_CONNECTION_NOT_ALLOWED;
		default:
			return SOCKS5_REPLY_GENERAL_FAILURE;
	}
}

// Helper to create addrinfo from binary IPv6
struct addrinfo *create_ipv6_addrinfo(const uint8_t ip[16], uint16_t port) {
	struct addrinfo *ai = malloc(sizeof(struct addrinfo));
	struct sockaddr_in6 *sa = malloc(sizeof(struct sockaddr_in6));

	if (!ai || !sa) {
		metrics_increment_errors(ERROR_TYPE_MEMORY);
		free(ai);
		free(sa);
		return NULL;
	}

	memset(sa, 0, sizeof(struct sockaddr_in6));
	sa->sin6_family = AF_INET6;
	memcpy(&sa->sin6_addr, ip, 16);
	sa->sin6_port = htons(port);

	memset(ai, 0, sizeof(struct addrinfo));
	ai->ai_family = AF_INET6;
	ai->ai_socktype = SOCK_STREAM;
	ai->ai_protocol = IPPROTO_TCP;
	ai->ai_addr = (struct sockaddr *) sa;
	ai->ai_addrlen = sizeof(struct sockaddr_in6);
	ai->ai_next = NULL;

	return ai;
}

struct addrinfo *create_ipv4_addrinfo(uint32_t ip_host_order, uint16_t port) {
	struct addrinfo *ai = malloc(sizeof(struct addrinfo));
	struct sockaddr_in *sa = malloc(sizeof(struct sockaddr_in));

	if (!ai || !sa) {
		metrics_increment_errors(ERROR_TYPE_MEMORY);
		free(ai);
		free(sa);
		return NULL;
	}

	memset(sa, 0, sizeof(struct sockaddr_in));
	sa->sin_family = AF_INET;
	sa->sin_addr.s_addr = htonl(ip_host_order);
	sa->sin_port = htons(port);

	memset(ai, 0, sizeof(struct addrinfo));
	ai->ai_family = AF_INET;
	ai->ai_socktype = SOCK_STREAM;
	ai->ai_protocol = IPPROTO_TCP;
	ai->ai_addr = (struct sockaddr *) sa;
	ai->ai_addrlen = sizeof(struct sockaddr_in);
	ai->ai_next = NULL;

	return ai;
}