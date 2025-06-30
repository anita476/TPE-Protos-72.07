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

	log(DEBUG, "[HELLO_READ] Entered hello_read");

	size_t wbytes;
	uint8_t *ptr = buffer_write_ptr(rb, &wbytes); // get where to write and how much space is left
	if (wbytes <= 0) {
		log(DEBUG, "[HELLO_READ] No space to write, trying to compact buffer");
		buffer_compact(rb);					 // try to recover space
		ptr = buffer_write_ptr(rb, &wbytes); // get the new pointer and size
		if (wbytes <= 0) {					 // still no space to write
			log(ERROR, "[HELLO_READ] No space to write even after compaction. Closing connection.");
			session->current_state = STATE_ERROR;
			return;
		}
	}

	// Read all available data from the socket into our buffer
	ssize_t bytes_read = recv(key->fd, ptr, wbytes, 0);
	if (bytes_read < 0) {
		// if (errno == EAGAIN || errno == EWOULDBLOCK) {
		//     return; // No data available - normal for non-blocking
		// }
		log(ERROR, "[HELLO_READ] recv() error");
		session->current_state = STATE_ERROR;
		return;
	} else if (bytes_read == 0) {
		log(INFO, "[HELLO_READ] Connection closed by peer");
		session->current_state = STATE_ERROR;
		return;
	}
	buffer_write_adv(rb, bytes_read);
	log(DEBUG, "[HELLO_READ] Read %zd bytes from client.", bytes_read);

	//  we received the initial 2 bytes ?

	size_t available;
	uint8_t *data = buffer_read_ptr(rb, &available);
	if (available < 2)
		return;

	// Don't consume bytes until we have the complete message
	uint8_t version = data[0]; // Peek, don't consume
	uint8_t nmethods = data[1];

	log(DEBUG, "[HELLO_READ] Received version: 0x%02x, nmethods: %d", version, nmethods);

	if (version != SOCKS5_VERSION) {
		log(ERROR, "[HELLO_READ] Unsupported SOCKS version: 0x%02x. Closing connection.", version);
		session->current_state = STATE_ERROR;
		return;
	}

	if (nmethods == 0) {
        log(ERROR, "[HELLO_READ] Invalid nmethods: 0");
        session->current_state = STATE_ERROR;
        return;
    }

	if (available < (size_t) (2 + nmethods)) {
		log(DEBUG, "[HELLO_READ] Not enough data yet. Waiting for more.");
		return; // Not enough data yet, wait for more
	}

	// TODO maybe we can safely consume ? check out no peek later --> yes since we already checked with buffer_can_read
	// i dont see buffer_peek in buffer.h... so will be commenting this
	// version = buffer_peek(rb, 0);
	// nmethods = buffer_peek(rb, 1);

	// uint8_t version = buffer_read(rb);	// consume the byte
	// uint8_t nmethods = buffer_read(rb); // consume the byte

	// // consume header
	buffer_read_adv(rb, 2);

	// client supports 0x00 ? no auth
	bool no_auth_supported = false;
	for (int i = 0; i < nmethods; i++) {
		uint8_t method = buffer_read(rb);
		if (buffer_read(rb) == SOCKS5_NO_AUTH) { // consume the byte
			no_auth_supported = true;
		}
	}
	// should we check if there is more data to read? 

	// prepare reply and change interest to WRITE (we want to send the hello response)
	buffer *wb = &session->write_buffer;
	if (buffer_writeable_bytes(wb) < 2) {
		log(ERROR, "[HELLO_READ] No space to write response. Closing connection."); // shouldnt we wait until there is more space left maybe?
		session->current_state = STATE_ERROR;
		return; // no space to write the response
	}

	// safe to write the response
	buffer_write(wb, SOCKS5_VERSION); // SOCKS version TODO: should we be checking if there is space to write? --> it
									  // will silently fail if there is no space, so we should handle that somehow
	if (no_auth_supported) {
		buffer_write(wb, SOCKS5_NO_AUTH); // no auth
		log(DEBUG, "[HELLO_READ] No auth supported. Moving to STATE_HELLO_WRITE.");
		session->current_state = STATE_HELLO_WRITE;
	} else {
		buffer_write(wb, SOCKS5_NO_ACCEPTABLE_METHODS); // FF means error
		log(ERROR, "[HELLO_READ] No acceptable methods. Moving to STATE_ERROR.");
		session->current_state = STATE_HELLO_WRITE; // close
		// session->will_close_after_write = true <- somehting like this maybe?
	}

	// Obs!!!! change interest to WRITE, selector wakes up WHEN we can write
	// selector_set_interest(key->s, key->fd, OP_WRITE);
	selector_set_interest_key(key, OP_WRITE); // change interest to write
	log(DEBUG, "[HELLO_READ] Switching to STATE_HELLO_WRITE and setting interest to OP_WRITE.");
}

/*

The server selects from one of the methods given in METHODS, and
sends a METHOD selection message:

+----+--------+
|VER | METHOD |
+----+--------+
+----+--------+
| 1  |   1    |

If the selected METHOD is X'FF', none of the methods listed by the
client are acceptable, and the CLIENT MUST close the connection. -> shutdown from server side and wait for client to
disconnect?

*/

static void hello_write(struct selector_key *key) {
	client_session *session = (client_session *) key->data;
	buffer *wb = &session->write_buffer;

	log(DEBUG, "[HELLO_WRITE] Entered hello_write.");

	size_t bytes_to_write;
	uint8_t *ptr = buffer_read_ptr(wb, &bytes_to_write);

	if (bytes_to_write == 0) {
		log(ERROR, "[HELLO_WRITE] No data to write. Closing connection.");
		session->current_state = STATE_ERROR;
		return;
	}

	// ISSUE 1: missing non-blocking socket error handling
	// ISSUE 2: missing MSG_NOSIGNAL flag (prevents SIGPIPE)
	// ISSUE 3: not handling partial writes correctly in non-blocking mode
	// ISSUE 4: no handling of STATE_ERROR case after write

	// Send data to client
	ssize_t bytes_written = send(key->fd, ptr, bytes_to_write, 0);
	if (bytes_written <= 0) {
		log(ERROR, "[HELLO_WRITE] Error writing to socket or connection closed.");
		session->current_state = STATE_ERROR;
		return;
	}

	buffer_read_adv(wb, bytes_written);
	log(DEBUG, "[HELLO_WRITE] Sent %zd bytes to client.", bytes_written);

	// Check if there’s still data to send
	if (buffer_readable_bytes(wb) > 0) {
		log(DEBUG, "[HELLO_WRITE] Not all data was sent. Waiting for next write event.");
		// Stay in OP_WRITE to continue sending next time
		return;
	}

	// ISSUE 5: Should handle STATE_ERROR case (when FF was sent)
	// All data was sent, switch back to OP_READ
	session->current_state = STATE_REQUEST_READ;
	selector_set_interest(key->s, key->fd, OP_READ);

	log(DEBUG, "[HELLO_WRITE] All handshake data sent. Switching to STATE_REQUEST_READ.");
}

static void socks5_handle_read(struct selector_key *key);
static void socks5_handle_write(struct selector_key *key);
static void socks5_handle_close(struct selector_key *key);

// reg the new client socket with the selector
// OBS: this has to be static to ensure the memory remains valid throughout the whole program
static const struct fd_handler client_handler = {
	.handle_read = socks5_handle_read, .handle_write = socks5_handle_write, .handle_close = socks5_handle_close,
	// todo handle the other cases
};

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

	selector_register(key->s, client_fd, &client_handler, OP_READ, session);

	log(DEBUG, "[HANDLE_CONNECTION] Accepted new client: fd=%d", client_fd);
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

// TODO: should use stm to handle the states...

static void socks5_handle_write(struct selector_key *key) {
	client_session *session = (client_session *) key->data;
	switch (session->current_state) {
		case STATE_HELLO_WRITE:
			hello_write(key);
			break;
		case STATE_REQUEST_WRITE:
			// todo complete
			break;
		default:
			log(ERROR, "[SOCKS5_HANDLE_WRITE] Unexpected write state: %d", session->current_state);
			break;
	}
}

static void socks5_handle_close(struct selector_key *key) {
	client_session *session = (client_session *) key->data;
	if (session) {
		free(session);
	}
	// no need to close(key->fd) here - selector does it
}