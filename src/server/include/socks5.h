//
// Created by nep on 6/29/25.
//

#ifndef _SOCKS5_H_
#define _SOCKS5_H_

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "buffer.h"
#include "logger.h"
#include "netutils.h"
#include "selector.h"

/* Since the send, recv etc. are blocking, we can use a state machine to transition between states and ensure no
 * blocking occurs */
// First we define the states for a SOCKS5 connection
typedef enum {
	STATE_HELLO_READ,
	STATE_HELLO_WRITE,
	STATE_HELLO_NO_ACCEPTABLE_METHODS, // o lo llamo HELLO_ERROR?
	STATE_REQUEST_READ,
	STATE_REQUEST_WRITE,

	STATE_REQUEST_RESOLVE, // ATYP == DOMAIN
	STATE_REQUEST_CONNECT,
	STATE_RELAY,
	STATE_ERROR_WRITE, // New state for writing error responses
	// todo others..
	STATE_CLIENT_CLOSE,
	STATE_DONE,
	STATE_ERROR,
} socks5_state;

// REQUEST AND RESPONSE STRUCTURES
typedef struct socks5_request {
	uint8_t cmd;  // command <- not needed
	uint8_t atyp; // not needed
	// char *dstAddress; // destination address
	// struct sockaddr_storage addr; // resolved address (always IPv4 or IPv6)
	// socklen_t addr_len;            // address length for connect()

	// temporary variables to hold the address and port
	uint16_t dst_port;		 // destination port
	char *domain_to_resolve; // temporary domain to resolve if atyp == SOCKS5_ATYP_DOMAIN

	struct addrinfo *dst_address;
} socks5_request;

typedef struct socks5_response {
	uint8_t rep;				   // replyCode
	uint8_t atyp;				   // address type
	struct sockaddr *boundAddress; // bound address
	socklen_t boundLength;
	uint16_t boundPort;		// bound port
	uint8_t remoteSocketFd; // active socket between server and destination
} socks5_response;

// Then we define a struct that holds *all* information for a SINGLE client connection
typedef struct {
	socks5_state current_state;

	socks5_request current_request;
	socks5_response current_response;

	uint8_t raw_read_buffer[256];
	uint8_t raw_write_buffer[256];

	// Buffers to handle reading and writing
	buffer read_buffer;
	buffer write_buffer;

	int remote_fd;
	int client_fd; // socket for CLIENT CONNECTION

	// bool should_close; // TODO: maybe do this instead of STATE_CLIENT_CLOSE (mizrahi does this)
	int clientSocket; // socket for CLIENT CONNECTION

	bool dns_failed; // Add this field
	uint8_t dns_error_code;

	uint8_t raw_destination_read_buffer[256];
	uint8_t raw_destination_write_buffer[256];

	buffer destination_read_buffer;
	buffer destination_write_buffer;

	bool has_error;
	uint8_t error_code;
	bool error_response_sent;

	bool cleaned_up; // to avoid double cleanup

} client_session;

// capaz se le puede agregar el clientSocket aca en vez de en el main pero X

void socks5_handle_new_connection(struct selector_key *key);

#endif // SOCKS5_H
