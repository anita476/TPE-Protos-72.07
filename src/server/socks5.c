#include "include/socks5.h"
#include "include/metrics.h"
#include "include/selector.h"
#include "include/socks5_utils.h"
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>

void socks5_handle_new_connection(struct selector_key *key);
static void socks5_handle_read(struct selector_key *key);
static void socks5_handle_write(struct selector_key *key);
static void socks5_handle_close(struct selector_key *key);
static void socks5_handle_block(struct selector_key *key);

/**************** -Remote connection handlers- *****************/
static void remote_connect_complete(struct selector_key *key);
static void socks5_remote_read(struct selector_key *key);
static void relay_client_to_remote(struct selector_key *key);
static void relay_remote_to_client(struct selector_key *key);

/**************** -Static client handlers structure- *****************/

static const struct fd_handler client_handler = {.handle_read = socks5_handle_read,
												 .handle_write = socks5_handle_write,
												 .handle_close = socks5_handle_close,
												 .handle_block = socks5_handle_block};

static const struct fd_handler remote_handler = {.handle_read = socks5_remote_read,
												 .handle_write = remote_connect_complete,
												 .handle_close = socks5_handle_close,
												 .handle_block = NULL};

/******************* -State machine handlers- *******************/
static void hello_read(struct selector_key *key);
static void hello_write(struct selector_key *key);
static void auth_read(struct selector_key * key);
static void auth_write(struct selector_key *key, bool should_shutdown);
static void hello_write_error(struct selector_key *key);
static void request_read(struct selector_key *key);
static void request_write(struct selector_key *key);
static void request_resolve(struct selector_key *key);
static void request_connect(struct selector_key *key);
static void close_client(struct selector_key *key);
static void relay_data(struct selector_key *key);
static void error_write(struct selector_key *key);
static void handle_error(struct selector_key *key);

// Helpers
static void set_error_state(client_session *session, uint8_t error_code);
static bool send_socks5_error_response(struct selector_key *key);
static void log_resolved_addresses(const char *domain,
								   struct addrinfo *addr_list); // This could be deleted since its just for debugging
static void *dns_resolution_thread(void *arg);
static void handle_connect_failure(struct selector_key *key, int error);
static void handle_connect_success(struct selector_key *key);
static bool valid_user(char * username, char * password);
static bool build_socks5_success_response(client_session *session);

// Destructor
static void cleanup_session(client_session *session);

void socks5_handle_new_connection(struct selector_key *key) {
	int listen_fd = key->fd;
	struct sockaddr_storage client_addr;
	socklen_t client_addr_len = sizeof(client_addr);

	// shouldnt blockk since it was dispatched by the selector
	int client_fd = accept(listen_fd, (struct sockaddr *) &client_addr, &client_addr_len);
	if (client_fd < 0) {
		metrics_increment_errors();
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
	session->client_fd = client_fd;
	session->remote_fd = -1; // Initially no remote connection
	session->current_request.domain_to_resolve = NULL;

	session->current_state = STATE_HELLO_READ;
	session->has_error = false;
	session->error_code = SOCKS5_REPLY_SUCCESS;
	session->error_response_sent = false;
	buffer_init(&session->read_buffer, sizeof(session->raw_read_buffer), session->raw_read_buffer);
	buffer_init(&session->write_buffer, sizeof(session->raw_write_buffer), session->raw_write_buffer);

	selector_register(key->s, client_fd, &client_handler, OP_READ, session);

	log(INFO, "===============================================================");
	log(INFO, "[HANDLE_CONNECTION] Accepted new client: fd=%d", client_fd);

	metrics_increment_connections();
}

// TODO: should use stm to handle the states...
static void socks5_handle_read(struct selector_key *key) {
	client_session *session = (client_session *) key->data;
	switch (session->current_state) {
		case STATE_HELLO_READ:
			hello_read(key);
			break;
		case STATE_AUTH_READ:
			auth_read(key);
			break;
		case STATE_REQUEST_READ:
			request_read(key);
			break;
		case STATE_REQUEST_RESOLVE:
			request_resolve(key);
			break;
		case STATE_REQUEST_CONNECT:
			request_connect(key);
			break;
		case STATE_RELAY:
			relay_data(key);
			break;
		case STATE_CLIENT_CLOSE:
			close_client(key);
			break;
		case STATE_ERROR:
			handle_error(key);
			break;
		default:
			// Should not happen
			log(ERROR, "[SOCKS5_HANDLE_READ] Unexpected state: %d", session->current_state);
			break;
	}
}

static void socks5_handle_write(struct selector_key *key) {
	client_session *session = (client_session *) key->data;
	switch (session->current_state) {
		case STATE_HELLO_WRITE:
			hello_write(key);
			break;
		case STATE_HELLO_NO_ACCEPTABLE_METHODS:
			hello_write_error(key);
			break;
		case STATE_AUTH_WRITE:
			auth_write(key,false);
			break;
		case STATE_REQUEST_WRITE:
			request_write(key);
			break;
		case STATE_ERROR_WRITE:
			error_write(key);
			break;
		case STATE_ERROR:
			handle_error(key);
			break;
		default:
			log(ERROR, "[SOCKS5_HANDLE_WRITE] Unexpected write state: %d", session->current_state);
			handle_error(key);
			break;
	}
}

static void socks5_handle_close(struct selector_key *key) {
	log(DEBUG, "[SOCKS5_HANDLE_CLOSE] *** CLOSE HANDLER CALLED *** for fd=%d", key->fd);
	client_session *session = (client_session *) key->data;
	if (!session) {
		return;
	}
	if (session->client_fd == key->fd) {
		session->client_fd = -1;
	}
	if (session->remote_fd == key->fd) {
		session->remote_fd = -1;
	}

	// Only free session when BOTH are closed
	if (session->client_fd == -1 && session->remote_fd == -1) {
		cleanup_session(session);
		free(session);
	}
	metrics_decrement_connections();
	log(DEBUG, "[SOCKS5_HANDLE_CLOSE] Session cleanup complete for fd=%d", key->fd);
	// IMPORTANT: Do NOT call selector_unregister_fd here!
	// The selector is already in the process of unregistering when it calls this function
}

static void socks5_handle_block(struct selector_key *key) {
	client_session *session = (client_session *) key->data;

	if (session->current_state == STATE_REQUEST_RESOLVE) {
		if (session->dns_failed) {
			log(ERROR, "[HANDLE_BLOCK] DNS resolution failed for fd=%d", key->fd);
			set_error_state(session, session->dns_error_code);
			handle_error(key);
			return;
		}

		if (session->current_request.dst_address == NULL) {
			log(ERROR, "[HANDLE_BLOCK] DNS resolution completed but no addresses returned");
			set_error_state(session, SOCKS5_REPLY_HOST_UNREACHABLE);
			handle_error(key);
			return;
		}
		log(DEBUG, "[HANDLE_BLOCK] DNS resolution completed for fd=%d", key->fd);
		request_connect(key);
	} else {
		log(ERROR, "[HANDLE_BLOCK] Unexpected block event in state %d", session->current_state);
		set_error_state(session,
						SOCKS5_REPLY_GENERAL_FAILURE); // TODO: maybe assign one of the unassigned errors for this
													   // isntead of the general failure: X'09' to X'FF' unassigned
		handle_error(key);
	}
}

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
			set_error_state(session, SOCKS5_REPLY_GENERAL_FAILURE);
			handle_error(key);
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
		set_error_state(session, SOCKS5_REPLY_GENERAL_FAILURE);
		handle_error(key);
		return;
	} else if (bytes_read == 0) {
		log(INFO, "[HELLO_READ] Connection closed by peer");
		set_error_state(session, SOCKS5_REPLY_GENERAL_FAILURE);
		// Immediately handle the error instead of just returning
		handle_error(key);
		return;
	}

	metrics_add_bytes_in(bytes_read);

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
		set_error_state(session, SOCKS5_REPLY_GENERAL_FAILURE);
		handle_error(key);
		return;
	}

	if (nmethods == 0) {
		log(ERROR, "[HELLO_READ] Invalid nmethods: 0");
		set_error_state(session, SOCKS5_REPLY_GENERAL_FAILURE);
		handle_error(key);
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
	bool auth_supported = false;
	for (int i = 0; i < nmethods; i++) {
		uint8_t method = buffer_read(rb);
		if (method == SOCKS5_NO_AUTH) { // consume the byte
			no_auth_supported = true;
		} else if (method == SOCKS5_USER_PASS_AUTH) {
			auth_supported = true;
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
	if (auth_supported) {
		buffer_write(wb, SOCKS5_USER_PASS_AUTH); // no auth
		log(DEBUG, "[HELLO_READ] USER_PASSWORD AUTH supported Moving to STATE_AUTH_READ.");
		session->authenticated = true; // Mark session as authenticated
		session->current_state = STATE_HELLO_WRITE;
	}
	else if (no_auth_supported) {
		buffer_write(wb, SOCKS5_NO_AUTH); // no auth
		log(DEBUG, "[HELLO_READ] No auth supported. Moving to STATE_HELLO_WRITE.");
		session->current_state = STATE_HELLO_WRITE;
		session->authenticated = false;
	} else {
		buffer_write(wb, SOCKS5_NO_ACCEPTABLE_METHODS); // FF means error
		log(ERROR, "[HELLO_READ] No acceptable methods. Moving to STATE_ERROR.");
		session->current_state = STATE_HELLO_NO_ACCEPTABLE_METHODS; // close
	}

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

TODO: maybe change some debugs since it's now being globally used
*/

static void write_to_client(struct selector_key *key, bool should_shutdown) {
	client_session *session = (client_session *) key->data;
	buffer *wb = &session->write_buffer;

	size_t bytes_to_write;
	uint8_t *ptr = buffer_read_ptr(wb, &bytes_to_write);

	if (bytes_to_write == 0) {
		log(ERROR, "[WRITE_TO_CLIENT] No data to write.");
		set_error_state(session, SOCKS5_REPLY_GENERAL_FAILURE);
		return;
	}

	ssize_t bytes_written = send(key->fd, ptr, bytes_to_write, MSG_NOSIGNAL);
	if (bytes_written < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			log(DEBUG, "[WRITE_TO_CLIENT] send() would block, waiting for next write event.");
			return; // Try again later when selector notifies
		}
		if (errno == EPIPE) {
			// client has closed the connection -> do not write (broken pipe exception in send)
			log(INFO, "[WRITE_TO_CLIENT] Client already closed connection (EPIPE), closing socket.");
			metrics_increment_errors();
			log(DEBUG, "[WRITE_TO_CLIENT] Unregistering fd=%d from selector", key->fd);
			selector_unregister_fd(key->s, key->fd);
			close(key->fd);
			log(DEBUG, "[WRITE_TO_CLIENT] EPIPE cleanup complete for fd=%d", key->fd);
			return;
		}
		log(ERROR, "[WRITE_TO_CLIENT] send() error: %s", strerror(errno));
		set_error_state(session, SOCKS5_REPLY_GENERAL_FAILURE);
		return;
	} else if (bytes_written == 0) {
		log(INFO, "[WRITE_TO_CLIENT] Connection closed by peer during send");
		set_error_state(session, SOCKS5_REPLY_GENERAL_FAILURE);
		return;
	}

	metrics_add_bytes_out(bytes_written);

	buffer_read_adv(wb, bytes_written);
	log(INFO, "[WRITE_TO_CLIENT] Sent %zd/%zu bytes to client.", bytes_written, bytes_to_write);

	if (buffer_readable_bytes(wb) > 0) {
		log(DEBUG, "[WRITE_TO_CLIENT] Partial write, waiting for next event.");
		return; // More data pending
	}

	// The shutdown is justified because the RFC specifies that the CLIENT must close the connection.
	// Gracefully shutting down from the server side is considered good practice and is commonly done by
	// industry standards such as nginx. By calling shutdown(), we signal we won’t send or receive more data, allowing
	// for a clean connection teardown.
	if (should_shutdown) {
		log(DEBUG, "[WRITE_TO_CLIENT] All data sent. Shutting down socket.");
		shutdown(key->fd, SHUT_RDWR);
		selector_unregister_fd(key->s, key->fd);
		close(key->fd);
		return;
	}

	// If we're not shutting down, update to next state
	if (session->authenticated) {
		session->current_state = STATE_AUTH_READ;
	}
	else {
		session->current_state = STATE_REQUEST_READ;
	}

	selector_set_interest(key->s, key->fd, OP_READ);
}


static void auth_read(struct selector_key *key) {
	client_session *session = (client_session *) key->data;
	buffer *rb = &session->read_buffer;

	log(DEBUG, "[AUTH_READ] Entered auth_read.");

	size_t wbytes;
	uint8_t *ptr = buffer_write_ptr(rb, &wbytes);
	if (wbytes <= 0) {
		log(DEBUG, "[AUTH_READ] No space to write, trying to compact buffer");
		buffer_compact(rb);
		ptr = buffer_write_ptr(rb, &wbytes);
		if (wbytes <= 0) {
			log(ERROR, "[AUTH_READ] No space to write even after compaction. Closing connection.");
			set_error_state(session, SOCKS5_REPLY_GENERAL_FAILURE);
			handle_error(key);
			return;
		}
	}

	ssize_t bytes_read = recv(key->fd, ptr, wbytes, 0);
	if (bytes_read <= 0) {
		if (bytes_read == 0) {
			log(DEBUG, "[AUTH_READ] Connection closed by client.");
		} else {
			perror("[AUTH_READ] Error reading from socket");
		}
		set_error_state(session, SOCKS5_REPLY_GENERAL_FAILURE);
		handle_error(key);
		return;
	}

	metrics_add_bytes_in(bytes_read);

	 buffer_write_adv(rb, bytes_read);
	log(DEBUG, "[AUTH_READ] Read %zd bytes from client.", bytes_read);

	size_t available;
	uint8_t *peek = buffer_read_ptr(rb, &available);
	if (available < 2) {
		log(DEBUG, "[AUTH_READ] Need at least 2 bytes for header, have %zu", available);
		return; // Not enough data yet
	}

	uint8_t version = peek[0];
	uint8_t ulen = peek[1];


	log(DEBUG, "[AUTH_READ] Header: VER=0x%02x ULEN=%d", version, ulen);

	if (version != SOCKS5_AUTH_VERSION) {
		log(ERROR, "[AUTH_READ] Unsupported Subnegotiation version: 0x%02x. Closing connection.", version);
		set_error_state(session, SOCKS5_REPLY_GENERAL_FAILURE);
		handle_error(key);
		return;
	}

	//check if plen field has been sent
	if ( available < (size_t)(2 + ulen)) {
		log(DEBUG, "[AUTH_READ] Not enough data yet. Waiting for more.");
		return; // Not enough data yet
	}
	uint8_t plen = peek[2 + ulen];
	if (available < (size_t) (3 + ulen + plen)) {
		log(DEBUG, "[AUTH_READ] Not enough data yet. Waiting for more.");
		return; // Not enough data yet
	}
	// Consume the header
	buffer_read_adv(rb, 2); // Consume version and ulen
	peek = buffer_read_ptr(rb, &available);
	char username[ulen + 1];
	strncpy(username,(char *)peek , ulen);
	username[ulen] = '\0'; // Null-terminate the username string
	buffer_read_adv(rb, ulen + 1); // Consume username and plen field
	peek = buffer_read_ptr(rb, &available);
	char password[plen + 1];
	strncpy(password, (char *)peek, plen);
	password[plen] = '\0'; // Null-terminate the password string
	log(DEBUG, "[AUTH_READ] Username: '%s', Password: '%s'", username, password);
	buffer_read_adv(rb, plen);

	// prepare reply and change interest to WRITE (we want to send the auth response)
	// TODO: what should we do if there is no space to write the response? for now we are just returning

	buffer * wb = &session->write_buffer;
	if (buffer_writeable_bytes(wb) < 2) {
		log(ERROR,
			"[AUTH_READ] No space to write response."); // shouldnt we wait until there is more space left maybe?
		// session->current_state = STATE_ERROR;
		return; // no space to write the response
	}

	// now safe to write the response
	buffer_write(wb, SOCKS5_AUTH_VERSION);
	if (!valid_user(username,password)) {
		buffer_write(wb, SOCKS5_REPLY_GENERAL_FAILURE);
		session->current_state = STATE_HELLO_NO_ACCEPTABLE_METHODS; ///maybe user a different state for auth error?
	} else {
		buffer_write(wb, SOCKS5_AUTH_SUCCESS);

		session->current_state = STATE_AUTH_WRITE;
	}
	selector_set_interest_key(key, OP_WRITE);

}

static void auth_write(struct selector_key * key, bool should_shutdown) {
	client_session *session = (client_session *) key->data;
	buffer *wb = &session->write_buffer;

	size_t bytes_to_write;
	uint8_t *ptr = buffer_read_ptr(wb, &bytes_to_write);

	if (bytes_to_write == 0) {
		log(ERROR, "[AUTH_WRITE] No data to write.");
		set_error_state(session, SOCKS5_REPLY_GENERAL_FAILURE);
		return;
	}

	ssize_t bytes_written = send(key->fd, ptr, bytes_to_write, MSG_NOSIGNAL);
	if (bytes_written < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			log(DEBUG, "[AUTH_WRITE] send() would block, waiting for next write event.");
			return; // Try again later when selector notifies
		}
		if (errno == EPIPE) {
			// client has closed the connection -> do not write (broken pipe exception in send)
			log(INFO, "[AUTH_WRITE] Client already closed connection (EPIPE), closing socket.");
			metrics_increment_errors();
			log(DEBUG, "[AUTH_WRITE] Unregistering fd=%d from selector", key->fd);
			selector_unregister_fd(key->s, key->fd);
			close(key->fd);
			log(DEBUG, "[AUTH_WRITE] EPIPE cleanup complete for fd=%d", key->fd);
			return;
		}
		log(ERROR, "[AUTH_WRITE] send() error: %s", strerror(errno));
		set_error_state(session, SOCKS5_REPLY_GENERAL_FAILURE);
		return;
	} else if (bytes_written == 0) {
		log(INFO, "[AUTH_WRITE] Connection closed by peer during send");
		set_error_state(session, SOCKS5_REPLY_GENERAL_FAILURE);
		return;
	}

	metrics_add_bytes_out(bytes_written);

	buffer_read_adv(wb, bytes_written);
	log(INFO, "[AUTH_WRITE] Sent %zd/%zu bytes to client.", bytes_written, bytes_to_write);

	if (buffer_readable_bytes(wb) > 0) {
		log(DEBUG, "[AUTH_WRITE] Partial write, waiting for next event.");
		return; // More data pending
	}

	// The shutdown is justified because the RFC specifies that the CLIENT must close the connection.
	// Gracefully shutting down from the server side is considered good practice and is commonly done by
	// industry standards such as nginx. By calling shutdown(), we signal we won’t send or receive more data, allowing
	// for a clean connection teardown.
	if (should_shutdown) {
		log(DEBUG, "[AUTH_WRITE] All data sent. Shutting down socket.");
		shutdown(key->fd, SHUT_RDWR);
		selector_unregister_fd(key->s, key->fd);
		close(key->fd);
		return;
	}

	// If we're not shutting down, update to next state
	session->current_state = STATE_REQUEST_READ;
	selector_set_interest(key->s, key->fd, OP_READ);
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
			set_error_state(session, SOCKS5_REPLY_GENERAL_FAILURE);
			handle_error(key);
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
		set_error_state(session, SOCKS5_REPLY_GENERAL_FAILURE);
		handle_error(key);
		return;
	}

	metrics_add_bytes_in(bytes_read);

	// Updating buffer
	buffer_write_adv(rb, bytes_read);
	log(DEBUG, "[REQUEST_READ] Read %zd bytes from client.", bytes_read);

	size_t available;
	uint8_t *peek = buffer_read_ptr(rb, &available);
	if (available < 4) {
		log(DEBUG, "[REQUEST_READ] Need 4 bytes for header, have %zu", available);
		return;
	}

	uint8_t version = peek[0];
	uint8_t cmd = peek[1];
	uint8_t rsv = peek[2];
	uint8_t atyp = peek[3];

	log(DEBUG, "[REQUEST_READ] Header: VER=0x%02x CMD=0x%02x RSV=0x%02x ATYP=0x%02x", version, cmd, rsv, atyp);

	// Version validation
	if (version != SOCKS5_VERSION) {
		log(ERROR, "[REQUEST_READ] Unsupported SOCKS version: 0x%02x. Closing connection.", version);
		set_error_state(session, SOCKS5_REPLY_GENERAL_FAILURE);
		handle_error(key);
		return;
	}

	// Command validation
	if (cmd != SOCKS5_CMD_CONNECT) {
		log(ERROR, "[REQUEST_READ] Unsupported command: 0x%02x (only CONNECT supported)", cmd);
		set_error_state(session, SOCKS5_REPLY_COMMAND_NOT_SUPPORTED);
		handle_error(key);
		return;
	}

	// Reserved field validation
	if (rsv != 0x00) {
		log(ERROR, "[REQUEST_READ] Invalid RSV: 0x%02x. Closing connection.", rsv);
		set_error_state(session, SOCKS5_REPLY_GENERAL_FAILURE);
		handle_error(key);
		return;
	}

	size_t total_required = 4; // VER, CMD, RSV, ATYP

	if (atyp == SOCKS5_ATYP_IPV4) {
		total_required += 4 + 2; // IPv4 address + Port
	} else if (atyp == SOCKS5_ATYP_IPV6) {
		total_required += 16 + 2; // IPv6 address + Port
	} else if (atyp == SOCKS5_ATYP_DOMAIN) {
		if (available < 5)
			return; // Need at least 1 more byte to know the domain length

		uint8_t domain_len = peek[4];
		total_required += 1 + domain_len + 2; // domain_len + domain + port
	} else {
		log(ERROR, "[REQUEST_READ] Unsupported ATYP: 0x%02x. Closing connection.", atyp);
		set_error_state(session, SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED);
		handle_error(key);
		return;
	}

	if (available < total_required) {
		log(DEBUG, "[REQUEST_READ] Need %zu bytes, have %zu", total_required, available);
		return;
	}

	buffer_read_adv(rb, 4);

	session->current_request.atyp = atyp;

	if (atyp == SOCKS5_ATYP_IPV4) {
		uint32_t ip = 0;
		for (int i = 0; i < 4; i++) {
			ip = (ip << 8) | buffer_read(rb); // Build in host order
		}
		uint16_t port = (buffer_read(rb) << 8) | buffer_read(rb);

		// Port 0 is reserved and means "any available port" in some contexts (like bind())
		// For outbound connections, port 0 doesn't make sense - you can't connect TO port 0
		// Port cant be bigger than 65535, so no need to check that
		if (port == 0) {
			log(ERROR, "[REQUEST_READ] Invalid port number: %d", port);
			set_error_state(session, SOCKS5_REPLY_GENERAL_FAILURE); // X'01' - General server failure
			handle_error(key);
			return;
		}
		session->current_request.dst_address = create_ipv4_addrinfo(ip, port);
		if (!session->current_request.dst_address) {
			set_error_state(session, SOCKS5_REPLY_GENERAL_FAILURE);
			handle_error(key);
			return;
		}
		request_connect(key); // TODO: idk if here i should leave the selector to change or if i can just call the
							  // function (and in the other cases too)
		return;

	} else if (atyp == SOCKS5_ATYP_IPV6) {
		uint8_t ip[16];
		for (int i = 0; i < 16; i++) {
			ip[i] = buffer_read(rb);
		}
		uint16_t port = (buffer_read(rb) << 8) | buffer_read(rb);

		if (port == 0) {
			log(ERROR, "[REQUEST_READ] Invalid port number: %d", port);
			set_error_state(session, SOCKS5_REPLY_GENERAL_FAILURE); // X'01' - General server failure
			handle_error(key);
			return;
		}

		session->current_request.dst_address = create_ipv6_addrinfo(ip, port);
		if (!session->current_request.dst_address) {
			set_error_state(session, SOCKS5_REPLY_GENERAL_FAILURE);
			handle_error(key);
			return;
		}

		request_connect(key); // Connect immediately
		return;

	} else if (atyp == SOCKS5_ATYP_DOMAIN) {
		uint8_t domain_len = buffer_read(rb);

		char domain_name[256] = {0};
		for (int i = 0; i < domain_len; i++) {
			domain_name[i] = buffer_read(rb);
		}
		domain_name[domain_len] = '\0';

		uint16_t port = (buffer_read(rb) << 8) | buffer_read(rb);
		if (port == 0) {
			log(ERROR, "[REQUEST_READ] Invalid port number: %d", port);
			set_error_state(session, SOCKS5_REPLY_GENERAL_FAILURE); // X'01' - General server failure
			handle_error(key);
			return;
		}
		session->current_request.dst_port = port;

		if (session->current_request.domain_to_resolve) {
			free(session->current_request.domain_to_resolve);
		}
		session->current_request.domain_to_resolve = strdup(domain_name);

		log(DEBUG, "[REQUEST_READ] Parsed domain name %s and port %d.", domain_name, port);

		request_resolve(key);
		return;

	} else {
		// Shouldnt reach here
		log(ERROR, "[REQUEST_READ] Unsupported ATYP: 0x%02x. Closing connection.", atyp);
		session->current_state = STATE_ERROR;
		return;
	}
}

static void request_write(struct selector_key *key) {
	client_session *session = (client_session *) key->data;

	log(DEBUG, "[REQUEST_WRITE] Sending SOCKS5 success response to client");

	write_to_client(key, false);

	if (buffer_readable_bytes(&session->write_buffer) == 0) {
		log(INFO, "[REQUEST_WRITE] SOCKS5 handshake complete - connection established");

		session->current_state = STATE_RELAY;

		// Now both sockets have proper read handlers
		selector_set_interest(key->s, session->client_fd, OP_READ);
		selector_set_interest(key->s, session->remote_fd, OP_READ);

		log(DEBUG, "[REQUEST_WRITE] Relay mode activated");
	}
}

static void request_resolve(struct selector_key *key) {
	client_session *session = (client_session *) key->data;

	log(DEBUG, "[REQUEST_RESOLVE] Starting DNS resolution for %s", session->current_request.domain_to_resolve);

	pthread_t tid;
	struct selector_key *thread_key = malloc(sizeof(*key));
	if (thread_key == NULL) {
		log(ERROR, "[REQUEST_RESOLVE] Failed to allocate memory for thread key.");
		set_error_state(session, SOCKS5_REPLY_GENERAL_FAILURE); // TODO: idk what error to set here
		handle_error(key);
		return;
	}
	memcpy(thread_key, key, sizeof(*key));

	if (pthread_create(&tid, NULL, dns_resolution_thread, thread_key) != 0) {
		log(ERROR, "[REQUEST_RESOLVE] Failed to create DNS thread.");
		free(thread_key);
		set_error_state(session, SOCKS5_REPLY_GENERAL_FAILURE);
		handle_error(key);
		return;
	}

	pthread_detach(tid);
	session->current_state = STATE_REQUEST_RESOLVE;

	// suspend processing until DNS resolution completes
	selector_set_interest_key(key, OP_READ);
}

static void *dns_resolution_thread(void *arg) {
	struct selector_key *key = (struct selector_key *) arg;
	client_session *session = (client_session *) key->data;

	struct addrinfo hints;
	struct addrinfo *res = NULL;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;	 // Allow IPv4 and IPv6
	hints.ai_socktype = SOCK_STREAM; // TCP only
	hints.ai_protocol = IPPROTO_TCP; // TCP protocol
	hints.ai_flags = AI_ADDRCONFIG;	 // Only return addresses we can actually use check
									 // TODO: check this

	char port_str[6];
	snprintf(port_str, sizeof(port_str), "%u", session->current_request.dst_port);

	int err = getaddrinfo(session->current_request.domain_to_resolve, port_str, &hints, &res);
	if (err != 0) {
		log(ERROR, "[DNS_THREAD] getaddrinfo failed: %s", gai_strerror(err));
		session->dns_failed = true;
		session->dns_error_code = map_getaddrinfo_error_to_socks5(err);
		session->current_request.dst_address = NULL;
	} else {
		log_resolved_addresses(session->current_request.domain_to_resolve, res);
		session->dns_failed = false;
		session->current_request.dst_address = res;
	}

	selector_notify_block(key->s, key->fd);
	free(key);
	return NULL;
}

static void request_connect(struct selector_key *key) {
	client_session *session = (client_session *) key->data;

	log(INFO, "[REQUEST_CONNECT] Attempting to connect to resolved address.");

	struct addrinfo *addr = session->current_request.dst_address;

	if (!addr) {
		log(ERROR, "[REQUEST_CONNECT] No destination address available");
		set_error_state(session, SOCKS5_REPLY_GENERAL_FAILURE);
		handle_error(key);
		return;
	}
	char addr_buf[INET6_ADDRSTRLEN + 8];
	sockaddr_to_human(addr_buf, sizeof(addr_buf), addr->ai_addr);

	const char *family_str = "Unknown";
	if (addr->ai_family == AF_INET) {
		family_str = "IPv4";
	} else if (addr->ai_family == AF_INET6) {
		family_str = "IPv6";
	}

	log(INFO, "[REQUEST_CONNECT] Attempting connection to %s: %s", family_str, addr_buf);

	// Close existing remote_fd if it was already set
	if (session->remote_fd != -1) {
		close(session->remote_fd);
		session->remote_fd = -1;
	}

	session->remote_fd = socket(addr->ai_family, SOCK_STREAM, 0);
	if (session->remote_fd == -1) {
		log(ERROR, "[REQUEST_CONNECT] Failed to create socket: %s", strerror(errno));
		set_error_state(session, SOCKS5_REPLY_GENERAL_FAILURE);
		handle_error(key);
		return;
	}

	if (selector_fd_set_nio(session->remote_fd) == -1) {
		log(ERROR, "[REQUEST_CONNECT] Failed to set non-blocking mode.");
		close(session->remote_fd); // cant think clearly, dunno if this is the right place to close it
		session->remote_fd = -1;
		set_error_state(session, SOCKS5_REPLY_GENERAL_FAILURE);
		handle_error(key);
		return;
	}

	// Attempt connection
	int connect_result = connect(session->remote_fd, addr->ai_addr, addr->ai_addrlen);
	if (connect_result == 0 || (connect_result == -1 && errno == EINPROGRESS)) {
		selector_status st = selector_register(key->s, session->remote_fd, &remote_handler, OP_WRITE, session);
		if (st != SELECTOR_SUCCESS) {
			log(ERROR, "[REQUEST_CONNECT] Failed to register remote fd: %d", st);
			close(session->remote_fd);
			session->remote_fd = -1;
			set_error_state(session, SOCKS5_REPLY_GENERAL_FAILURE);
			handle_error(key);
			return;
		}

		session->current_state = STATE_REQUEST_CONNECT;
		selector_set_interest_key(key, OP_NOOP);
		// selector_set_interest_key(key, OP_READ);
		log(DEBUG, "[REQUEST_CONNECT] Connection in progress...");
		return;
	}

	log(ERROR, "[REQUEST_CONNECT] Connection failed immediately: %s", strerror(errno));

	// try the next address if available
	if (addr->ai_next) {
		log(DEBUG, "[REQUEST_CONNECT] Trying next address...");

		struct addrinfo *failed_addr = session->current_request.dst_address;
		session->current_request.dst_address = addr->ai_next;

		// unlink and free the failed address
		failed_addr->ai_next = NULL;
		if (session->current_request.atyp == SOCKS5_ATYP_DOMAIN) {
			freeaddrinfo(failed_addr); // DNS result
		} else {
			// Manually created addrinfo for IPv4/IPv6
			if (failed_addr->ai_addr)
				free(failed_addr->ai_addr);
			free(failed_addr);
		}

		// Try connecting to next address
		request_connect(key);
		return;
	}
	log(ERROR, "[REQUEST_CONNECT] No more addresses to try");
	uint8_t error_code = map_connect_error_to_socks5(errno);
	set_error_state(session, error_code);
	handle_error(key);
}

static void remote_connect_complete(struct selector_key *key) {
	int error = 0;
	socklen_t len = sizeof(error);

	if (getsockopt(key->fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0 || error != 0) {
		log(ERROR, "[REMOTE_CONNECT_COMPLETE] Connection failed: %s", strerror(error != 0 ? error : errno));
		handle_connect_failure(key, error);
		return;
	}

	handle_connect_success(key);
}

static void handle_connect_failure(struct selector_key *key, int error) {
	client_session *session = (client_session *) key->data;

	selector_unregister_fd_noclose(key->s, key->fd);
	close(key->fd);
	session->remote_fd = -1;

	struct addrinfo *current_addr = session->current_request.dst_address;
	if (current_addr && current_addr->ai_next != NULL) {
		log(INFO, "[REMOTE_CONNECT_COMPLETE] Trying next address...");

		struct addrinfo *failed_addr = current_addr;
		session->current_request.dst_address = current_addr->ai_next;

		// free failed address
		failed_addr->ai_next = NULL;
		if (session->current_request.atyp == SOCKS5_ATYP_DOMAIN) {
			freeaddrinfo(failed_addr);
		} else {
			if (failed_addr->ai_addr)
				free(failed_addr->ai_addr);
			free(failed_addr);
		}

		// try connecting to next IP
		struct selector_key client_key = {.s = key->s, .fd = session->client_fd, .data = session};
		request_connect(&client_key);
		return;
	}

	log(ERROR, "[REMOTE_CONNECT_COMPLETE] No more addresses to try.");
	uint8_t error_code = map_connect_error_to_socks5(error);

	struct selector_key client_key = {.s = key->s, .fd = session->client_fd, .data = session};
	set_error_state(session, error_code);
	handle_error(&client_key);
}

static void handle_connect_success(struct selector_key *key) {
	client_session *session = (client_session *) key->data;

	log(INFO, "[REMOTE_CONNECT_COMPLETE] Connection successful");

	if (session->current_request.dst_address) {
		if (session->current_request.atyp == SOCKS5_ATYP_DOMAIN) {
			freeaddrinfo(session->current_request.dst_address);
		} else {
			struct addrinfo *current = session->current_request.dst_address;
			while (current) {
				struct addrinfo *next = current->ai_next;
				if (current->ai_addr)
					free(current->ai_addr);
				free(current);
				current = next;
			}
		}
		session->current_request.dst_address = NULL;
	}

	if (!build_socks5_success_response(session)) {
		log(ERROR, "[REMOTE_CONNECT_COMPLETE] Failed to build success response");

		struct selector_key client_key = {.s = key->s, .fd = session->client_fd, .data = session};
		set_error_state(session, SOCKS5_REPLY_GENERAL_FAILURE);
		handle_error(&client_key);
		return;
	}

	selector_set_interest(key->s, key->fd, OP_NOOP);

	session->current_state = STATE_REQUEST_WRITE;
	selector_set_interest(key->s, session->client_fd, OP_WRITE);
}

static bool build_socks5_success_response(client_session *session) {
	buffer *wb = &session->write_buffer;
	buffer_reset(wb);

	if (buffer_writeable_bytes(wb) < 10) {
		return false;
	}

	buffer_write(wb, SOCKS5_VERSION); // VER
	buffer_write(wb, 0x00);			  // REP: success
	buffer_write(wb, 0x00);			  // RSV

	struct sockaddr_storage local_addr;
	socklen_t local_len = sizeof(local_addr);

	if (getsockname(session->remote_fd, (struct sockaddr *) &local_addr, &local_len) != 0) {
		// TODO: check if this is the right thing to do? fallback to a default address if getsockname fails
		log(ERROR, "[BUILD_SOCKS5_SUCCESS_RESPONSE] getsockname failed: %s. Using default 0.0.0.0", strerror(errno));
		buffer_write(wb, SOCKS5_ATYP_IPV4);
		for (int i = 0; i < 6; i++) {
			buffer_write(wb, 0x00);
		}
		return true;
	}

	if (local_addr.ss_family == AF_INET) {
		struct sockaddr_in *in = (struct sockaddr_in *) &local_addr;
		buffer_write(wb, SOCKS5_ATYP_IPV4);
		buffer_write(wb, ((uint8_t *) &in->sin_addr)[0]);
		buffer_write(wb, ((uint8_t *) &in->sin_addr)[1]);
		buffer_write(wb, ((uint8_t *) &in->sin_addr)[2]);
		buffer_write(wb, ((uint8_t *) &in->sin_addr)[3]);
		buffer_write(wb, ntohs(in->sin_port) >> 8);
		buffer_write(wb, ntohs(in->sin_port) & 0xFF);
	} else if (local_addr.ss_family == AF_INET6) {
		struct sockaddr_in6 *in6 = (struct sockaddr_in6 *) &local_addr;
		buffer_write(wb, SOCKS5_ATYP_IPV6);
		for (int i = 0; i < 16; i++) {
			buffer_write(wb, in6->sin6_addr.s6_addr[i]);
		}
		buffer_write(wb, ntohs(in6->sin6_port) >> 8);
		buffer_write(wb, ntohs(in6->sin6_port) & 0xFF);
	} else {
		// This really shouldn't happen, but using this fallback
		buffer_write(wb, SOCKS5_ATYP_IPV4);
		for (int i = 0; i < 6; i++) {
			buffer_write(wb, 0x00);
		}
	}

	return true;
}

// Not being used atm
static void close_client(struct selector_key *key) {
	char dummy[256];
	ssize_t bytes_read = recv(key->fd, dummy, sizeof(dummy), 0);

	if (bytes_read == 0) {
		log(DEBUG, "[CLOSE_CLIENT] Client closed connection gracefully.");
		selector_unregister_fd(key->s, key->fd); // This will trigger handle_close
		close(key->fd);
	} else if (bytes_read < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return;
		} else {
			log(ERROR, "[CLOSE_CLIENT] recv() error: %s", strerror(errno));
			metrics_increment_errors();
			selector_unregister_fd(key->s, key->fd);
			close(key->fd);
		}
	} else {
		log(DEBUG, "[CLOSE_CLIENT] Unexpected data from client during close. Ignoring and waiting for proper close.");
	}
}

static void relay_data(struct selector_key *key) {
	client_session *session = (client_session *) key->data;

	if (key->fd == session->client_fd) {
		// Data from client to remote server
		relay_client_to_remote(key);
	} else if (key->fd == session->remote_fd) {
		// Data from remote server to client
		relay_remote_to_client(key);
	} else {
		log(ERROR, "[RELAY_DATA] Unknown fd=%d", key->fd);
		handle_error(key);
	}
}

static void relay_client_to_remote(struct selector_key *key) {
	client_session *session = (client_session *) key->data;

	// Read from client, write to remote
	char buffer[16384];
	ssize_t bytes_read = recv(session->client_fd, buffer, sizeof(buffer), 0);

	if (bytes_read <= 0) {
		log(DEBUG, "[RELAY] Client connection closed");
		handle_error(key);
		return;
	}

	ssize_t bytes_written = send(session->remote_fd, buffer, bytes_read, MSG_NOSIGNAL);
	if (bytes_written <= 0) {
		log(DEBUG, "[RELAY] Remote connection closed");
		handle_error(key);
		return;
	}

	log(DEBUG, "[RELAY] Relayed %zd bytes client->remote", bytes_read);
}

static void relay_remote_to_client(struct selector_key *key) {
	client_session *session = (client_session *) key->data;

	// Read from remote, write to client
	char buffer[16384];
	ssize_t bytes_read = recv(session->remote_fd, buffer, sizeof(buffer), 0);

	if (bytes_read <= 0) {
		log(DEBUG, "[RELAY] Remote connection closed");
		handle_error(key);
		return;
	}

	ssize_t bytes_written = send(session->client_fd, buffer, bytes_read, MSG_NOSIGNAL);
	if (bytes_written <= 0) {
		log(DEBUG, "[RELAY] Client connection closed");
		handle_error(key);
		return;
	}

	log(DEBUG, "[RELAY] Relayed %zd bytes remote->client", bytes_read);
}

static void socks5_remote_read(struct selector_key *key) {
	client_session *session = (client_session *) key->data;

	if (session->current_state == STATE_RELAY) {
		relay_remote_to_client(key);
	} else {
		log(ERROR, "[REMOTE_READ] Unexpected read in state %d", session->current_state);
		handle_error(key);
	}
}

// ERROR FUNCTIONS

static void error_write(struct selector_key *key) {
	// client_session *session = (client_session *) key->data;

	log(DEBUG, "[ERROR_WRITE] Sending error response to client");

	// Use the existing write_to_client function with shutdown=true
	write_to_client(key, true);
}

static void set_error_state(client_session *session, uint8_t error_code) {
	session->has_error = true;
	session->error_code = error_code;
	session->error_response_sent = false;
	session->current_state = STATE_ERROR;
	metrics_increment_errors();
	log(DEBUG, "[SET_ERROR_STATE] Setting error state with code: 0x%02x", error_code);
}

static bool send_socks5_error_response(struct selector_key *key) {
	client_session *session = (client_session *) key->data;
	buffer *wb = &session->write_buffer;

	// Check if we already sent the error response
	if (session->error_response_sent) {
		return true;
	}

	// todo should always reset before writing?
	buffer_reset(wb);

	if (buffer_writeable_bytes(wb) < 10) { // Minimum size for error response
		log(ERROR, "[SEND_SOCKS5_ERROR] No space in write buffer");
		return false;
	}

	buffer_write(wb, SOCKS5_VERSION);	   // VER
	buffer_write(wb, session->error_code); // REP (error code)
	buffer_write(wb, 0x00);				   // RSV
	buffer_write(wb, SOCKS5_ATYP_IPV4);	   // ATYP (IPv4)

	// BND.ADDR (0.0.0.0)
	buffer_write(wb, 0x00);
	buffer_write(wb, 0x00);
	buffer_write(wb, 0x00);
	buffer_write(wb, 0x00);

	// BND.PORT (0)
	buffer_write(wb, 0x00);
	buffer_write(wb, 0x00);

	session->error_response_sent = true;
	log(DEBUG, "[SEND_SOCKS5_ERROR] Prepared error response with code: 0x%02x", session->error_code);
	return true;
}

// if connect_to_destination fails: log(ERROR, "[REQUEST_READ] Connection to destination failed");
// set_error_state(session, SOCKS5_REPLY_CONNECTION_REFUSED);
// return;
static void handle_error(struct selector_key *key) {
	client_session *session = (client_session *) key->data;

	log(DEBUG, "[HANDLE_ERROR] Handling error state for fd=%d", key->fd);

	if (session && session->has_error && !session->error_response_sent) {
		// We need to send an error response first
		if (send_socks5_error_response(key)) {
			// Switch to error write state and write mode to send the error response
			session->current_state = STATE_ERROR_WRITE;
			selector_set_interest(key->s, key->fd, OP_WRITE);
			log(DEBUG, "[HANDLE_ERROR] Switching to STATE_ERROR_WRITE to send error response");
			return;
		}
	}
	selector_unregister_fd(key->s, key->fd);
	close(key->fd); // always close the fd, selector does NOT handle it
}

static void log_resolved_addresses(const char *domain, struct addrinfo *addr_list) {
	if (!addr_list) {
		log(INFO, "[DNS_RESOLVE] No addresses resolved for domain: %s", domain);
		return;
	}

	log(INFO, "[DNS_RESOLVE] Resolved addresses for domain '%s':", domain);

	int count = 0;
	char addr_buf[INET6_ADDRSTRLEN + 8]; // Extra space for port

	for (struct addrinfo *addr = addr_list; addr != NULL; addr = addr->ai_next) {
		sockaddr_to_human(addr_buf, sizeof(addr_buf), addr->ai_addr);

		const char *family_str = "Unknown";
		if (addr->ai_family == AF_INET) {
			family_str = "IPv4";
		} else if (addr->ai_family == AF_INET6) {
			family_str = "IPv6";
		}

		log(INFO, "[DNS_RESOLVE]   [%d] %s: %s", count + 1, family_str, addr_buf);
		count++;
	}

	log(INFO, "[DNS_RESOLVE] Total addresses resolved: %d", count);
}

static bool valid_user(char * username, char * password) {
	return strcmp(username, "nep") == 0 && strcmp(password, "nep") == 0;
	///TODO implement proper validation
}

static void cleanup_session(client_session *session) {
	if (!session || session->cleaned_up)
		return;
	session->cleaned_up = true;

	if (session->current_request.dst_address) {
		if (session->current_request.atyp == SOCKS5_ATYP_DOMAIN) {
			freeaddrinfo(session->current_request.dst_address);
		} else {
			struct addrinfo *current = session->current_request.dst_address;
			while (current) {
				struct addrinfo *next = current->ai_next;
				if (current->ai_addr)
					free(current->ai_addr);
				free(current);
				current = next;
			}
		}
		session->current_request.dst_address = NULL;
	}

	if (session->current_request.domain_to_resolve) {
		free(session->current_request.domain_to_resolve);
		session->current_request.domain_to_resolve = NULL;
	}

	if (session->remote_fd != -1) {
		close(session->remote_fd);
		session->remote_fd = -1;
	}

	buffer_reset(&session->read_buffer);
	buffer_reset(&session->write_buffer);
}
