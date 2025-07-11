//
// Created by nep on 6/29/25.
//

#ifndef _SOCKS5_H_
#define _SOCKS5_H_
#include "constants.h"

#include "../../shared/include/calsetting_protocol.h"
#include "args.h"
#include "buffer.h"
#include "logger.h"
#include "netutils.h"
#include "selector.h"
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

/* Since the send, recv etc. are blocking, we can use a state machine to transition between states and ensure no
 * blocking occurs */
// First we define the states for a SOCKS5 connection
typedef enum {
	STATE_HELLO_READ,
	STATE_HELLO_WRITE,
	STATE_AUTH_READ,
	STATE_AUTH_WRITE,
	STATE_REQUEST_READ,
	STATE_REQUEST_WRITE,
	STATE_REQUEST_RESOLVE, // ATYP == DOMAIN
	STATE_REQUEST_CONNECT,
	STATE_RELAY,
	STATE_ERROR_WRITE, // New state for writing error responses
	STATE_CLIENT_CLOSE,
	STATE_DONE,
	STATE_ERROR,
} socks5_state;

// REQUEST AND RESPONSE STRUCTURES
// typedef struct socks5_request {
// 	uint8_t cmd;  // command <- not needed
// 	uint8_t atyp; // not needed
// 	uint16_t dst_port;		 // destination port
// 	char *domain_to_resolve; // temporary domain to resolve if atyp == SOCKS5_ATYP_DOMAIN, freed after resolution
// 	struct addrinfo *dst_address;
// } socks5_request;

typedef struct {
	uint8_t atyp;
	char *domain_to_resolve;		// Domain name for DNS resolution
	struct addrinfo *dst_addresses; // Chain of addresses to try
	uint16_t dst_port;				// Port for DNS resolution
} connection_data;

typedef struct {
	char client_ip[46]; // INET6_ADDRSTRLEN = 46
	uint16_t client_port;
	char dest_addr[256]; // Max domain name length
	uint16_t dest_port;
	uint8_t dest_atyp;
} log_info;

// Then we define a struct that holds *all* information for a SINGLE client connection
typedef struct {
	SessionType type;
	// Core state
	socks5_state current_state;
	int remote_fd;
	int client_fd; // socket for CLIENT CONNECTION

	// Protocol data
	connection_data connection; // Temporary connection info
	log_info logging;			// Persistent logging info

	// socks5_request current_request;
	// socks5_response current_response;

	// Buffers (client side)
	uint8_t *raw_read_buffer; // make into pointer to allocate at runtime
	uint8_t *raw_write_buffer;
	buffer read_buffer;
	buffer write_buffer;

	// Buffers (remote side)
	// Ful duplex communication, buffer for REMOTE connection
	uint8_t *raw_remote_read_buffer; // make into pointer to allocate at runtime
	uint8_t *raw_remote_write_buffer;
	buffer remote_read_buffer;
	buffer remote_write_buffer;

	size_t buffer_size; // Size for all buffers

	// DNS handling -> is it necessary to separate it?
	bool dns_failed; // Add this field
	uint8_t dns_error_code;

	// Error handling
	bool has_error;
	uint8_t error_code;
	bool error_response_sent;

	// Authentication
	bool authenticated;
	char *username; // TODO: later should point to a struct with more user info
	uint8_t user_type;

	// Lifecycle
	bool cleaned_up;

	// timeout related fields
	time_t connection_start;
	int idle_timeout;
	time_t next_timeout;

	// bool should_close; // TODO: maybe do this instead of STATE_CLIENT_CLOSE (mizrahi does this)
} client_session;

void socks5_handle_new_connection(struct selector_key *key);

#endif

// typedef struct socks5_response {
// 	uint8_t rep;				   // replyCode
// 	uint8_t atyp;				   // address type
// 	struct sockaddr *boundAddress; // bound address
// 	socklen_t boundLength;
// 	uint16_t boundPort;		// bound port
// 	uint8_t remoteSocketFd; // active socket between server and destination
// } socks5_response;