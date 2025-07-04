//
// Created by nep on 7/4/25.
//

#include "include/lib_client.h"
#include "include/buffer.h"

#include <bits/socket.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>

#include <stdlib.h>
#include <string.h>
#include <unistd.h>


#define HELLO_HEADER_FIXED_LEN 3

int setup_tcp_client_Socket(char * address, char * port) {
	struct addrinfo addrCriteria = {0};                   // Criteria for address match
	addrCriteria.ai_family = AF_UNSPEC;             // v4 or v6 is OK
	addrCriteria.ai_socktype = SOCK_STREAM;         // Only streaming sockets
	addrCriteria.ai_protocol = IPPROTO_TCP;         // Only TCP protocol

	// Get address(es)
	struct addrinfo *servAddr; // Holder for returned list of server addrs
	int rtnVal = getaddrinfo(address, port, &addrCriteria, &servAddr);
	if (rtnVal != 0) {
		return -1;
	}
	int sock = -1;
	for (struct addrinfo *addr = servAddr; addr != NULL && sock == -1; addr = addr->ai_next) {
		// Create a reliable, stream socket using TCP
		sock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
		if (sock >= 0) {
			errno = 0;
			// Establish the connection to the server
			if ( connect(sock, addr->ai_addr, addr->ai_addrlen) != 0) {
				close(sock); 	// Socket connection failed; try next address
				sock = -1;
			}
		}
	}

	freeaddrinfo(servAddr);
	return sock;
}

int send_all(int fd, char * msg, size_t len) {
	size_t total_sent = 0;
	while (total_sent < len) {
		ssize_t bytes_sent = send(fd, msg + total_sent, len - total_sent, 0);
		if (bytes_sent < 0) {
			if (errno == EINTR) {
				continue; // Interrupted, try again
			}
			return -1; // Error occurred
		}
		total_sent += bytes_sent;
	}

	return total_sent; // Return total bytes sent
}
int recv_all(int fd, char * buf, size_t len) {
	size_t total_received = 0;
	while (total_received < len) {
		ssize_t bytes_received = recv(fd, buf + total_received, len - total_received, 0);
		if (bytes_received < 0) {
			if (errno == EINTR) {
				continue; // Interrupted, try again
			}
			return -1; // Error occurred
		} else if (bytes_received == 0) {
			return total_received; // Connection closed
		}
		total_received += bytes_received;
	}

	return total_received; // Return total bytes received
}

int hello_send(char * username, char * password, int sock) {
	if (username == NULL || password == NULL || sock < 0) {
		return -1; // Invalid parameters
	}

	// Prepare the hello message
	uint8_t username_len = strlen(username);
	uint8_t password_len = strlen(password);
	uint16_t total_len = HELLO_HEADER_FIXED_LEN + username_len + password_len;
	char msg[HELLO_HEADER_FIXED_LEN + username_len + password_len];
	char * msg_ptr = msg;
	msg_ptr[0] = 0x01;
	msg_ptr[1] = username_len;
	msg_ptr[2] = password_len;
	msg_ptr += 3;
	strcpy(msg_ptr, username);
	msg_ptr += username_len;
	strcpy(msg_ptr, password);

	if (send_all(sock, msg, total_len) < 0) {
		return -1; // Failed to send
	}
	return 0; // success
}
int hello_read(int sock) {
	char buff[2] = {0};
	if (recv_all(sock, buff, 2) < 0) {
		return -1; // Failed to read
	}
	return buff[1]; //returns hello_response code
}

int request_send(uint8_t command_code, uint8_t arg_1, uint8_t arg_2, int sock) {
	if (command_code > COMMAND_CHANGE_TIMEOUT || command_code < COMMAND_LOGS) {
		return RESPONSE_BAD_REQUEST; // Invalid command code
	}
	char request[REQUEST_SIZE];
	request[0] = METRICS_PROTOCOL_VERSION;
	request[1] = command_code;
	request[2] = arg_1;
	request[3] = arg_2;
	if (send_all(sock, request, REQUEST_SIZE) != REQUEST_SIZE) {
		return -1;
	}
	return 0; // success
}

// metrics * handle_metrics(int sock, metrics * m) {
// 	if (sock < 0 || m == NULL) {
// 		return NULL; // Invalid parameters
// 	}
//
// 	char response[sizeof(metrics)];
// 	char * response_ptr = response;
// 	if (recv_all(sock, response, sizeof(metrics)) != sizeof(metrics)) {
// 		return NULL; // Failed to read metrics
// 	}
// 	m->version = response_ptr[0];
// 	response_ptr++;
// 	m->server_state = response_ptr[0];
// 	response_ptr++;
// 	m->n_current_connections = ntohl(response_ptr[0]);
// }
