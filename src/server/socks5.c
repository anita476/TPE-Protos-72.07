#include "include/socks5.h"
#include "include/selector.h"
#include <stdio.h>

#define SOCKS5_VERSION 0x05
#define SOCKS5_NO_AUTH 0x00
#define SOCKS5_CMD_CONNECT 0x01
#define SOCKS5_ATYP_IPV4 0x01
#define SOCKS5_ATYP_DOMAIN 0x03
#define SOCKS5_ATYP_IPV6 0x04
#define SOCKS5_NO_ACCEPTABLE_METHODS 0xFF
#define REJECTION_TIMEOUT_SECONDS 2

static void socks5_handle_read(struct selector_key *key);
static void socks5_handle_write(struct selector_key *key);
static void socks5_handle_close(struct selector_key *key);

static void close_client(struct selector_key *key);

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
		errno = 0;
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return; // no data available - normal for non-blocking
		}
		log(ERROR, "[HELLO_READ] recv() error: %s", strerror(errno));
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
		return;
	}

	// // consume header
	buffer_read_adv(rb, 2);

	// client supports 0x00 ? no auth
	bool no_auth_supported = false;
	for (int i = 0; i < nmethods; i++) {
		if (buffer_read(rb) == SOCKS5_NO_AUTH) { // consume the byte
			no_auth_supported = true;
		}
	}
	// should we check if there is more data to read?

	// prepare reply and change interest to WRITE (we want to send the hello response)
	// TODO: what should we do if there is no space to write the response? for now we are just returning
	buffer *wb = &session->write_buffer;
	if (buffer_writeable_bytes(wb) < 2) {
		log(ERROR,
			"[HELLO_READ] No space to write response."); // shouldnt we wait until there is more space left maybe?
		// session->current_state = STATE_ERROR;
		return; // no space to write the response
	}

	// now safe to write the response
	buffer_write(wb, SOCKS5_VERSION); // SOCKS version TODO: should we be checking if there is space to write? --> it
									  // will silently fail if there is no space, so we should handle that somehow
	if (no_auth_supported) {
		buffer_write(wb, SOCKS5_NO_AUTH); // no auth
		log(DEBUG, "[HELLO_READ] No auth supported. Moving to STATE_HELLO_WRITE.");
		session->current_state = STATE_HELLO_WRITE;
	} else {
		buffer_write(wb, SOCKS5_NO_ACCEPTABLE_METHODS); // FF means error
		log(ERROR, "[HELLO_READ] No acceptable methods. Moving to STATE_ERROR.");
		session->current_state = STATE_HELLO_NO_ACCEPTABLE_METHODS; // close
																	// TODO shutdown after write or another state ?
																	// shutdown
		// session->will_close_after_write = true <- somehting like this maybe?
	}

	// Obs!!!! change interest to WRITE, selector wakes up WHEN we can write
	// selector_set_interest(key->s, key->fd, OP_WRITE);
	selector_set_interest_key(key, OP_WRITE); // change interest to write
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
disconnect
*/

static void write_to_client(struct selector_key *key, bool should_shutdown) {
	client_session *session = (client_session *) key->data;
	buffer *wb = &session->write_buffer;

	size_t bytes_to_write;
	uint8_t *ptr = buffer_read_ptr(wb, &bytes_to_write);

	if (bytes_to_write == 0) {
		log(ERROR, "[WRITE_TO_CLIENT] No data to write.");
		session->current_state = STATE_ERROR;
		return;
	}

	ssize_t bytes_written = send(key->fd, ptr, bytes_to_write, MSG_NOSIGNAL);
	if (bytes_written < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			log(DEBUG, "[WRITE_TO_CLIENT] send() would block, waiting for next write event.");
			return; // Try again later when selector notifies
		}
		log(ERROR, "[WRITE_TO_CLIENT] send() error: %s", strerror(errno));
		session->current_state = STATE_ERROR;
		return;
	} else if (bytes_written == 0) {
		log(INFO, "[WRITE_TO_CLIENT] Connection closed by peer during send");
		session->current_state = STATE_ERROR;
		return;
	}
	buffer_read_adv(wb, bytes_written);
	log(DEBUG, "[WRITE_TO_CLIENT] Sent %zd/%zu bytes to client.", bytes_written, bytes_to_write);

	if (buffer_readable_bytes(wb) > 0) {
		log(DEBUG, "[WRITE_TO_CLIENT] Partial write, waiting for next event.");
		return; // More data pending
	}

	// The shutdown is justified because the RFC specifies that the CLIENT must close the connection.
	// However, gracefully shutting down from the server side is considered good practice and is commonly done by
	// industry standards such as nginx. By calling shutdown(), we signal we won’t send or receive more data, allowing
	// for a clean connection teardown.
	if (should_shutdown) {
		log(DEBUG, "[WRITE_TO_CLIENT] All data sent. Shutting down socket.");
		shutdown(key->fd, SHUT_RDWR);
		// Keep the socket registered for OP_READ we receive recv() == 0 from client.
		selector_set_interest(key->s, key->fd, OP_READ);
		session->current_state = STATE_CLIENT_CLOSE;
		// OPTION 2: // selector_unregister_fd(key->s, key->fd); // Trigger handle_close immediately
		return;
	}

	// If we're not shutting down, update to next state
	session->current_state = STATE_REQUEST_READ;
	selector_set_interest(key->s, key->fd, OP_READ);
	log(DEBUG, "[WRITE_TO_CLIENT] All handshake data sent. Switching to STATE_REQUEST_READ.");
}

static void hello_write(struct selector_key *key) {
	write_to_client(key, false);
}

static void hello_write_error(struct selector_key *key) {
	log(DEBUG, "[HELLO_WRITE_ERROR] Entered - sending rejection response");
	write_to_client(key, true);
}

/** A socks request looks like this:
		+----+-----+-------+------+----------+----------+
		|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
		+----+-----+-------+------+----------+----------+
		| 1  |  1  | X'00' |  1   | Variable |    2     |
		+----+-----+-------+------+----------+----------+
**
*/
static void request_read(struct selector_key *key) {
	client_session *session = (client_session *) key->data;
	buffer *rb = &session->read_buffer;

	log(DEBUG, "[REQUEST_READ] Entered request_read.");

	// Buffer
	size_t wbytes;
	uint8_t *ptr = buffer_write_ptr(rb, &wbytes);
	if (wbytes <= 0) {
		log(DEBUG, "[REQUEST_READ] No space to write, trying to compact buffer");
		buffer_compact(rb);
		ptr = buffer_write_ptr(rb, &wbytes);
		if (wbytes <= 0) {
			log(ERROR, "[REQUEST_READ] No space to write even after compaction. Closing connection.");
			session->current_state = STATE_ERROR;
			return;
		}
	}

	// Socket
	ssize_t bytes_read = recv(key->fd, ptr, wbytes, 0);
	if (bytes_read <= 0) {
		if (bytes_read == 0) {
			log(DEBUG, "[REQUEST_READ] Connection closed by client.");
		} else {
			perror("[REQUEST_READ] Error reading from socket");
		}
		session->current_state = STATE_ERROR;
		return;
	}

	// Updating buffer
	buffer_write_adv(rb, bytes_read);
	log(DEBUG, "[REQUEST_READ] Read %zd bytes from client.", bytes_read);

	// Verifying existence of fixed headers (VER, CMD, RSV, ATYP)
	if (buffer_readable_bytes(rb) < 4) {
		log(DEBUG, "[REQUEST_READ] Need 4 bytes for header, have %zu", buffer_readable_bytes(rb));
		return;
	}

	// Consuming fixed headers
	uint8_t version = buffer_read(rb);
	uint8_t cmd = buffer_read(rb);
	uint8_t rsv = buffer_read(rb);
	uint8_t atyp = buffer_read(rb);

	log(DEBUG, "[REQUEST_READ] Header: VER=0x%02x CMD=0x%02x RSV=0x%02x ATYP=0x%02x", version, cmd, rsv, atyp);

	// Version validation
	if (version != SOCKS5_VERSION) {
		log(ERROR, "[HELLO_READ] Unsupported SOCKS version: 0x%02x. Closing connection.", version);
		session->current_state = STATE_ERROR;
		return;
	}

	// Command validation
	if (cmd != SOCKS5_CMD_CONNECT) {
		log(ERROR, "[REQUEST_READ] Unsupported command: 0x%02x (only CONNECT supported)", cmd);
		session->current_state = STATE_ERROR;
		return;
	}

	// Reserved field validation
	if (rsv != 0x00) {
		log(ERROR, "[REQUEST_READ] Invalid RSV: 0x%02x. Closing connection.", rsv);
		session->current_state = STATE_ERROR;
		return;
	}

	// Address lenght validation
	size_t addr_len;
	switch (atyp) {
		case SOCKS5_ATYP_IPV4:
			addr_len = 4;
			break;
		case SOCKS5_ATYP_IPV6:
			addr_len = 16;
			break;
		case SOCKS5_ATYP_DOMAIN:
			if (buffer_readable_bytes(rb) < 1) {
				return;
			}
			size_t available_for_peek;
			uint8_t *peek_data = buffer_read_ptr(rb, &available_for_peek);
			uint8_t domain_len = peek_data[0];
			addr_len = 1 + domain_len;
			break;
		default:
			log(ERROR, "[REQUEST_READ] Unsupported ATYP: 0x%02x. Closing connection.", atyp);
			session->current_state = STATE_ERROR;
			return;
	}

	// Verifying the existence of destination address and port
	if (buffer_readable_bytes(rb) < addr_len + 2) {
		log(DEBUG, "[REQUEST_READ] Need %zu bytes for address and port, have %zu", addr_len + 2,
			buffer_readable_bytes(rb));
		return;
	}

	// Address parsing
	char dst_addr[INET6_ADDRSTRLEN + 1] = {0};
	switch (atyp) {
		case SOCKS5_ATYP_IPV4: {
			uint32_t addr4;
			for (int i = 0; i < 4; i++) {
				((uint8_t *) &addr4)[i] = buffer_read(rb);
			}
			inet_ntop(AF_INET, &addr4, dst_addr, sizeof(dst_addr));
			break;
		}
		case SOCKS5_ATYP_IPV6: {
			uint8_t addr6[16];
			for (int i = 0; i < 16; i++) {
				addr6[i] = buffer_read(rb);
			}
			inet_ntop(AF_INET6, &addr6, dst_addr, sizeof(dst_addr));
			break;
		}
		case SOCKS5_ATYP_DOMAIN: {
			uint8_t domain_len = buffer_read(rb);
			for (int i = 0; i < domain_len; i++) {
				dst_addr[i] = buffer_read(rb);
			}
			dst_addr[domain_len] = '\0';
			break;
		}
	}

	// Port parsing
	uint16_t dst_port = 0;
	dst_port = (buffer_read(rb) << 8) | buffer_read(rb); // >¡Big Endian!
	log(DEBUG, "[REQUEST_READ] Parsed address: %s, port: %d", dst_addr, dst_port);

	// Updating session
	session->current_request.cmd = cmd;
	session->current_request.atyp = atyp;
	if (session->current_request.dstAddress) {
		free(session->current_request.dstAddress);
	}
	session->current_request.dstAddress = strdup(dst_addr);
	session->current_request.dstPort = dst_port;

	// TODO: Missing connect_to_destination and success logic

	// if (connect_to_destination(session) == 0) {
	// 	// Success
	// 	printf("Connected...\n");
	// 	log(DEBUG, "[REQUEST_READ] Connected successfully, sending response");
	// } else {
	// 	log(ERROR, "[REQUEST_READ] No space to write even after compaction");
	// 	session->current_state = STATE_ERROR;
	// 	return;
	// }
}

static void handle_error(struct selector_key *key) {
}

// reg the new client socket with the selector
// OBS: this has to be static to ensure the memory remains valid throughout the whole program
static const struct fd_handler client_handler = {
	.handle_read = socks5_handle_read, 
	.handle_write = socks5_handle_write, 
	.handle_close = socks5_handle_close,
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

	log(INFO, "===============================================================");
	log(INFO, "[HANDLE_CONNECTION] Accepted new client: fd=%d", client_fd);
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
			request_read(key);
			// todo complete
			break;
		case STATE_CLIENT_CLOSE:
			close_client(key);
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
		case STATE_HELLO_NO_ACCEPTABLE_METHODS:
			hello_write_error(key);
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
	log(DEBUG, "[SOCKS5_HANDLE_CLOSE] *** CLOSE HANDLER CALLED *** for fd=%d", key->fd);
	client_session *session = (client_session *) key->data;
	if (session) {
		free(session);
	}
	// IMPORTANT: Do NOT call selector_unregister_fd here!
	// The selector is already in the process of unregistering when it calls this function
}

// Basically: never forcing client to close in order to follow RFC standards. 
// Idk how to implement the timeout 
// Maybe should just selector_unregister_fd in hello_write_error 
static void close_client(struct selector_key *key) {
    client_session *session = (client_session *) key->data;

    char dummy[256];
    ssize_t bytes_read = recv(key->fd, dummy, sizeof(dummy), 0);

    if (bytes_read == 0) {
        log(DEBUG, "[CLOSE_CLIENT] Client closed connection gracefully.");
        selector_unregister_fd(key->s, key->fd); // This will trigger handle_close
    } else if (bytes_read < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return;
        } else {
            log(ERROR, "[CLOSE_CLIENT] recv() error: %s", strerror(errno));
            selector_unregister_fd(key->s, key->fd);
        }
    } else {
        log(DEBUG, "[CLOSE_CLIENT] Unexpected data from client during close. Ignoring and waiting for proper close.");
    }
}
