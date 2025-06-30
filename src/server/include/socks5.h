//
// Created by nep on 6/29/25.
//

#ifndef _SOCKS5_H_
#define _SOCKS5_H_

#include <buffer.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include "selector.h"
#include "buffer.h"

/* Since the send, recv etc. are blocking, we can use a state machine to transition between states and ensure no
 * blocking occurs */
// First we define the states for a SOCKS5 connection
typedef enum {
	STATE_HELLO_READ,
	STATE_HELLO_WRITE,
	STATE_REQUEST_READ,
	// todo others..
	STATE_DONE,
	STATE_ERROR,
} socks5_state;

// Then we define a struct that holds *all* information for a SINGLE client connection
typedef struct {
	socks5_state current_state;

	// Buffers to handle reading and writing
	buffer read_buffer;
	buffer write_buffer;

	uint8_t raw_read_buffer[256];
	uint8_t raw_write_buffer[256];
	int clientSocket; // socket for CLIENT CONNECTION
} client_session;

// capaz se le puede agregar el clientSocket aca en vez de en el main pero X

// REQUEST AND RESPONSE STRUCTURES
typedef struct socks5_request {
	uint8_t cmd; // command
	uint8_t atyp;
	char *dstAddress; // destination address
	uint16_t dstPort; // destination port

} socks5_request;

typedef struct socks5_response {
	uint8_t rep;				   // replyCode
	uint8_t atyp;				   // address type
	struct sockaddr *boundAddress; // bound address
	socklen_t boundLength;
	uint16_t boundPort;		// bound port
	uint8_t remoteSocketFd; // active socket between server and destination
} socks5_response;

void socks5_handle_new_connection(struct selector_key *key);

#endif // SOCKS5_H
