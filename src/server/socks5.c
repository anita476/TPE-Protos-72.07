#include "include/socks5.h"
#include "include/selector.h"
#include <stdio.h>

#define SOCKS5_VERSION 0x05
#define SOCKS5_NO_AUTH 0x00
#define SOCKS5_CMD_CONNECT 0x01
#define SOCKS5_ATYP_IPV4 0x01
#define SOCKS5_ATYP_DOMAIN 0x03
#define SOCKS5_NO_ACCEPTABLE_METHODS 0xFF

// remember that the selector key has the selector , the fd we write to and the data itself
// this is the FIRST message, it looks like:
/*
|VER | NMETHODS | METHODS  |
+----+----------+----------+
| 1  |    1     | 1 to 255 |
+----+----------+----------+
*/
static void hello_read(struct selector_key *key) {
	client_session *session = (client_session *) key->data;
	buffer *rb = &session->read_buffer;

	size_t wbytes;
	uint8_t *ptr = buffer_write_ptr(rb, &wbytes); // get where to write and how much space is left
	if (wbytes <= 0) { 
		buffer_compact(rb); // try to recover space
		ptr = buffer_write_ptr(rb, &wbytes); // get the new pointer and size
		if (wbytes <= 0) { // still no space to write
			fprintf(stderr, "No space to write in the read buffer, closing connection\n");
			session->current_state = STATE_ERROR; // no space to write, error <-- not sure about this, shouldnt it automatically compact?? 
			return;
		}
	}
	
	// Read all available data from the socket into our buffer
	ssize_t bytes_read = recv(key->fd, ptr, wbytes, 0);
	if (bytes_read <= 0) {
		session->current_state = STATE_ERROR;
		return;
	}
	buffer_write_adv(rb, bytes_read);

	//  we received the initial 2 bytes ?
	if (buffer_readable_bytes(rb) < 2) {
		return; // not enough data yet, wait for the next read event
	}

	uint8_t version;
	uint8_t nmethods;

	// TODO maybe we can safely consume ? check out no peek later --> yes since we already checked with buffer_can_read
	// i dont see buffer_peek in buffer.h... so will be commenting this
	// version = buffer_peek(rb, 0);
	// nmethods = buffer_peek(rb, 1);

	version = buffer_read(rb); // consume the byte
	nmethods = buffer_read(rb); // consume the byte

	if (version != SOCKS5_VERSION) {
		session->current_state = STATE_ERROR;
		return;
	}

	// SOCKS5 + nmethods + methods <- im not quite getting this
	if (buffer_readable_bytes(rb) < (size_t) (2 + nmethods)) {
		return; // Not enough data yet, wait for more
	}

	// // consume header
	// buffer_read_adv(rb, 2);

	// client supports 0x00 ? no auth
	bool no_auth_supported = false;
	for (int i = 0; i < nmethods; i++) {
		if (buffer_read(rb) == SOCKS5_NO_AUTH) { // consume the byte
			no_auth_supported = true;
		}
	}

	// prepare reply and change interest to WRITE (we want to send the hello response)
	buffer *wb = &session->write_buffer;
	buffer_write(wb, SOCKS5_VERSION); // SOCKS version
	if (no_auth_supported) {
		buffer_write(wb, SOCKS5_NO_AUTH); // no auth
		session->current_state = STATE_HELLO_WRITE;
	} else {
		buffer_write(wb, SOCKS5_NO_ACCEPTABLE_METHODS);				  // FF means error
		session->current_state = STATE_ERROR; // close
	}

	// Obs!!!! change interest to WRITE, selector wakes up WHEN we can write
	selector_set_interest(key->s, key->fd, OP_WRITE);
}

static void hello_write(struct selector_key *key) {
}

static void socks5_handle_read(struct selector_key *key);

void socks5_handle_new_connection(struct selector_key *key) {
	// Called by the socks5 handler when a new client connects
	int listen_fd = key->fd;
	struct sockaddr_storage client_addr;
	socklen_t client_addr_len = sizeof(client_addr);

	// shouldnt blockk since it was dispatched by the selector
	int client_fd = accept(listen_fd, (struct sockaddr *) &client_addr, &client_addr_len);
	if (client_fd < 0) {
		perror("accept error"); // todo more robust error handling...
		return;
	}

	// set new client socket to non-blocking
	if (selector_fd_set_nio(client_fd) == -1) {
		perror("selector_fd_set_nio error");
		close(client_fd);
		return;
	}

	// New session structure for the client // this will bee dispatched on the INITIAL connection request, so we HAVE to
	// register the session
	client_session *session = calloc(1, sizeof(client_session));
	if (!session) {
		perror("calloc error..");
		close(client_fd);
		return;
	}
	session->current_state = STATE_HELLO_READ;
	buffer_init(&session->read_buffer, sizeof(session->raw_read_buffer), session->raw_read_buffer);
	buffer_init(&session->write_buffer, sizeof(session->raw_write_buffer), session->raw_write_buffer);

	// reg the new client socket with the selector
	const struct fd_handler client_handler = {
		.handle_read = socks5_handle_read, .handle_write = NULL, .handle_close = NULL,
		// todo handle the other cases
	};

	selector_register(key->s, client_fd, &client_handler, OP_READ, session);

	printf("Accepted new client: fd=%d\n", client_fd);
}

/**
Explanation:
LISTENIN SOCKET handle_read -> in main
called when the selector tells you the listening socket (the one you called listen() on) is readable.
It means one or more new clients are waiting to be accepted.
What should you do?
We call accept(). This creates a new socket (CLIENT SOCKET) for the new connection.
You register this new client socket with the selector, using a handler (socks5_handle_read) for protocol
processing. So: The listening socket’s handle_read is responsible for creating new sockets for each client (via
accept()).

CLIENT SOCKET socks5_handle_read
called when the selector tells you a client socket is readable. It means the client has read it.
we need to process based on the state (only hello read for now) for that client.
So: The client socket’s handle_read
does not create new sockets. It only processes data for the already-accepted client.
**/

static void socks5_handle_read(struct selector_key *key) {
	client_session *session = (client_session *) key->data;
	switch (session->current_state) {
		case STATE_HELLO_READ:
			hello_read(key);
			break;
		case STATE_REQUEST_READ:
			// todo complete
			break;
		default:
			// Should not happen
			break;
	}
}