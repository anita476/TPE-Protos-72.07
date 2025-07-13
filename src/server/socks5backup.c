// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
#include "include/socks5.h"
#include "include/metrics.h"
#include "include/selector.h"
#include "include/socks5_utils.h"
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

extern struct timespec g_select_timeout;
extern int g_connection_timeout;
extern size_t g_socks5_buffer_size;
extern struct user *users;
extern uint8_t nusers; // Number of users loaded from args

static void log_socks5_attempt(client_session *session, uint8_t status_code);

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
static void relay_write(struct selector_key *key);

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
static void auth_read(struct selector_key *key);
static void request_read(struct selector_key *key);
static void request_write(struct selector_key *key);
static void request_resolve(struct selector_key *key);
static void request_connect(struct selector_key *key);
static void relay_data(struct selector_key *key);
static void handle_error(struct selector_key *key);

static void write_to_client(struct selector_key *key, bool should_shutdown);

// Helpers
static void set_error_state(client_session *session, uint8_t error_code);
static bool send_socks5_error_response(struct selector_key *key);
static error_type_t map_socks5_error_to_type(uint8_t error_code);
static void log_resolved_addresses(const char *domain,
								   struct addrinfo *addr_list); // This could be deleted since its just for debugging
static void *dns_resolution_thread(void *arg);
static void handle_connect_failure(struct selector_key *key, int error);
static void handle_connect_success(struct selector_key *key);
bool valid_user(const char *username, const char *password, uint8_t *out_type);
static bool build_socks5_success_response(client_session *session);
void store_client_info(client_session *session, struct sockaddr_storage *client_addr);
void store_dest_info(client_session *session, uint8_t atyp, const char *addr, uint16_t port);

// Destructor
static void cleanup_session(client_session *session);

void socks5_handle_new_connection(struct selector_key *key) {
	int listen_fd = key->fd;
	struct sockaddr_storage client_addr;
	socklen_t client_addr_len = sizeof(client_addr);

	// shouldnt block since it was dispatched by the selector
	int client_fd = accept(listen_fd, (struct sockaddr *) &client_addr, &client_addr_len);
	if (client_fd < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			// no connection to accept (race condition)
			return;
		}
		metrics_increment_errors(ERROR_TYPE_NETWORK);
		perror("accept error");
		return;
	}

	// set new client socket to non-blocking
	if (selector_fd_set_nio(client_fd) == -1) {
		metrics_increment_errors(ERROR_TYPE_SYSTEM);
		perror("selector_fd_set_nio error");
		close(client_fd);
		return;
	}

	// New session structure for the client // this will bee dispatched on the INITIAL connection request, so we HAVE to
	// register the session
	client_session *session = calloc(1, sizeof(client_session));
	if (!session) {
		metrics_increment_errors(ERROR_TYPE_MEMORY);
		log(ERROR, "[HANDLE CONNECTION] Failed to allocate client session");
		perror("calloc error..");
		close(client_fd);
		return;
	}
	session->type = SESSION_SOCKS5; // Set session type
	// initialize timeout
	session->connection_start = time(NULL);
	session->idle_timeout = g_connection_timeout;
	session->next_timeout = session->connection_start + session->idle_timeout;
	selector_update_session_timeout(key->s, session, session->next_timeout);

	// Initialize core state
	session->client_fd = client_fd;
	session->remote_fd = -1;
	session->current_state = STATE_HELLO_READ;

	// Store client info immediately
	store_client_info(session, &client_addr);

	// Initialize destination info
	strcpy(session->logging.dest_addr, "unknown");
	session->logging.dest_port = 0;
	session->logging.dest_atyp = 0x01; // Default to IPv4

	// Initialize connection data
	session->connection.domain_to_resolve = NULL;
	session->connection.dst_addresses = NULL;
	session->connection.dst_port = 0;
	session->connection.atyp = 0xFF; // Invalid until set

	// Initialize error handling
	session->has_error = false;
	session->error_code = SOCKS5_REPLY_SUCCESS;
	session->error_response_sent = false;
	session->dns_failed = false;
	session->dns_error_code = 0;

	// Initialize authentication
	session->authenticated = false;
	session->username = NULL;

	// Initialize cleanup flag
	session->cleaned_up = false;

	// Initialize buffers
	session->buffer_size = g_socks5_buffer_size; // can be changed at runtime!
	session->raw_read_buffer = malloc(session->buffer_size);
	if (session->raw_read_buffer == NULL) {
		log(ERROR, "[HANDLE CONNECTION] Failed to allocate read buffer");
		close(client_fd);
		free(session);
		metrics_increment_errors(ERROR_TYPE_MEMORY);
		return;
	}
	session->raw_write_buffer = malloc(session->buffer_size);
	if (session->raw_write_buffer == NULL) {
		log(ERROR, "[HANDLE CONNECTION] Failed to allocate read buffer");
		free(session->raw_read_buffer);
		close(client_fd);
		free(session);
		metrics_increment_errors(ERROR_TYPE_MEMORY);
		return;
	}

	// We  will initialize them when remote connection is established, to avoid allocating extra resources
	session->raw_remote_read_buffer = NULL;
	session->raw_remote_write_buffer = NULL;

	buffer_init(&session->read_buffer, session->buffer_size, session->raw_read_buffer);
	buffer_init(&session->write_buffer, session->buffer_size, session->raw_write_buffer);

	if (selector_register(key->s, client_fd, &client_handler, OP_READ, session) != SELECTOR_SUCCESS) {
		log(ERROR, "[HANDLE CONNECTION] Failed to register client fd with selector");
		free(session->raw_read_buffer);
		free(session->raw_write_buffer);
		close(client_fd);
		free(session);
		metrics_increment_errors(ERROR_TYPE_SYSTEM);
		return;
	}

	log(INFO, "===============================================================");
	log(INFO, "[HANDLE_CONNECTION] Accepted new client: fd=%d from %s:%d", client_fd, session->logging.client_ip,
		session->logging.client_port);

	metrics_increment_connections();
}

static void socks5_handle_read(struct selector_key *key) {
	client_session *session = (client_session *) key->data;

	// Reset timeout on any data received
	time_t now = time(NULL);
	session->next_timeout = now + session->idle_timeout;
	selector_update_session_timeout(key->s, session, session->next_timeout);

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
		case STATE_AUTH_WRITE: // todo take out redundant state
			write_to_client(key, false);
			break;
		case STATE_REQUEST_WRITE:
			request_write(key);
			break;
		case STATE_RELAY:
			relay_write(key);
			break;
		case STATE_ERROR_WRITE:
			write_to_client(key, true); // This will send the error response and close the connection
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
	// Remove from timeout tracking
	selector_remove_session_timeout(key->s, session);

	// Check if we're already cleaning up this session
	if (session->cleaned_up) {
		log(DEBUG, "[SOCKS5_HANDLE_CLOSE] Session already being cleaned up, skipping");
		return;
	}

	// Mark which fd was closed
	if (session->client_fd == key->fd) {
		log(DEBUG, "[SOCKS5_HANDLE_CLOSE] Client fd=%d closed", key->fd);
		session->client_fd = -1;
	} else if (session->remote_fd == key->fd) {
		log(DEBUG, "[SOCKS5_HANDLE_CLOSE] Remote fd=%d closed", key->fd);
		session->remote_fd = -1;
	}

	// prevent recursive calls
	session->cleaned_up = true;

	// Clean up the other fd if it's still open
	if (session->client_fd != -1 && session->client_fd != key->fd) {
		log(DEBUG, "[SOCKS5_HANDLE_CLOSE] Closing remaining client fd=%d", session->client_fd);
		selector_unregister_fd(key->s, session->client_fd);
		close(session->client_fd);
		session->client_fd = -1;
	}
	if (session->remote_fd != -1 && session->remote_fd != key->fd) {
		log(DEBUG, "[SOCKS5_HANDLE_CLOSE] Closing remaining remote fd=%d", session->remote_fd);
		selector_unregister_fd(key->s, session->remote_fd);
		close(session->remote_fd);
		session->remote_fd = -1;
	}

	// If both remote and client are closed, only then clean up resources
	log(DEBUG, "[SOCKS5_HANDLE_CLOSE] Both fds closed, cleaning up session");
	cleanup_session(session);
	free(session);
	metrics_decrement_connections();

	log(DEBUG, "[SOCKS5_HANDLE_CLOSE] Close handler complete for fd=%d", key->fd);
}
static void socks5_handle_block(struct selector_key *key) {
	client_session *session = (client_session *) key->data;

	if (session->current_state == STATE_REQUEST_RESOLVE) {
		if (session->dns_failed) {
			log(ERROR, "[HANDLE_BLOCK] DNS resolution failed for fd=%d", key->fd);
			log_socks5_attempt(session, session->dns_error_code);
			set_error_state(session, session->dns_error_code);
			handle_error(key);
			return;
		}

		if (session->connection.dst_addresses == NULL) {
			log(ERROR, "[HANDLE_BLOCK] DNS resolution completed but no addresses returned");
			set_error_state(session, SOCKS5_REPLY_HOST_UNREACHABLE);
			handle_error(key);
			return;
		}
		log(DEBUG, "[HANDLE_BLOCK] DNS resolution completed for fd=%d", key->fd);
		request_connect(key);
	} else if (session->current_state == STATE_REQUEST_CONNECT) {
		// DNS resolution completed but we're already in connect state, continue
		// timing issue
		log(DEBUG, "[HANDLE_BLOCK] DNS resolution completed while already in connect state for fd=%d", key->fd);
		// DONT call request_connect again, it's already running
	} else {
		log(ERROR, "[HANDLE_BLOCK] Unexpected block event in state %d", session->current_state);
		set_error_state(session, SOCKS5_REPLY_GENERAL_FAILURE);
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
	// read some bytes
	time_t now = time(NULL);
	session->connection_start = now;
	session->next_timeout = now + session->idle_timeout;
	selector_update_session_timeout(key->s, session, session->next_timeout);

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
		set_error_state(session, SOCKS5_REPLY_COMMAND_NOT_SUPPORTED);
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
	} else if (no_auth_supported) {
		buffer_write(wb, SOCKS5_NO_AUTH); // no auth
		log(DEBUG, "[HELLO_READ] No auth supported. Moving to STATE_HELLO_WRITE.");
		session->current_state = STATE_HELLO_WRITE;
		session->authenticated = false;
	} else {
		log_socks5_attempt(session, SOCKS5_REPLY_CONNECTION_NOT_ALLOWED);

		buffer_write(wb, SOCKS5_NO_ACCEPTABLE_METHODS); // FF means error
		log(ERROR, "[HELLO_READ] No acceptable methods. Moving to STATE_ERROR.");
		set_error_state(session, SOCKS5_REPLY_CONNECTION_NOT_ALLOWED); // Maps to AUTH
		// session->current_state = STATE_ERROR_WRITE; // close
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
			metrics_increment_errors(ERROR_TYPE_NETWORK);
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
	// industry standards such as nginx. By calling shutdown(), we signal we won't send or receive more data, allowing
	// for a clean connection teardown.
	if (should_shutdown) {
		log(DEBUG, "[WRITE_TO_CLIENT] All data sent. Shutting down socket.");
		shutdown(key->fd, SHUT_RDWR);
		selector_unregister_fd(key->s, key->fd);
		close(key->fd);
		return;
	}

	// If we're not shutting down, update to next state
	// TODO: probably a better way tod othis is using a state machine
	switch (session->current_state) {
		case STATE_HELLO_WRITE:
			if (session->authenticated) {
				session->current_state = STATE_AUTH_READ;
				log(DEBUG, "[WRITE_TO_CLIENT] Hello complete, transitioning to AUTH_READ");
			} else {
				session->current_state = STATE_REQUEST_READ;
				log(DEBUG, "[WRITE_TO_CLIENT] Hello complete, transitioning to REQUEST_READ");
			}
			break;

		case STATE_AUTH_WRITE:
			session->current_state = STATE_REQUEST_READ;
			log(DEBUG, "[WRITE_TO_CLIENT] Auth complete, transitioning to REQUEST_READ");
			break;

		case STATE_REQUEST_WRITE:
			session->current_state = STATE_RELAY;
			log(DEBUG, "[WRITE_TO_CLIENT] Request complete, transitioning to RELAY");
			selector_set_interest(key->s, session->client_fd, OP_READ);
			selector_set_interest(key->s, session->remote_fd, OP_READ);
			return;

		default:
			log(ERROR, "[WRITE_TO_CLIENT] Unexpected state for write completion: %d", session->current_state);
			set_error_state(session, SOCKS5_REPLY_GENERAL_FAILURE);
			handle_error(key);
			return;
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

	// check if plen field has been sent
	if (available < (size_t) (2 + ulen)) {
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
	strncpy(username, (char *) peek, ulen);
	username[ulen] = '\0';		   // Null-terminate the username string
	buffer_read_adv(rb, ulen + 1); // Consume username and plen field
	peek = buffer_read_ptr(rb, &available);
	char password[plen + 1];
	strncpy(password, (char *) peek, plen);
	password[plen] = '\0'; // Null-terminate the password string
	log(DEBUG, "[AUTH_READ] Username: '%s', Password: '%s'", username, password);
	buffer_read_adv(rb, plen);

	// prepare reply and change interest to WRITE (we want to send the auth response)
	// TODO: what should we do if there is no space to write the response? for now we are just returning

	buffer *wb = &session->write_buffer;
	if (buffer_writeable_bytes(wb) < 2) {
		log(ERROR,
			"[AUTH_READ] No space to write response."); // shouldnt we wait until there is more space left maybe? -->
														// YES, by returning we are indeed waiting for the next time the
														// selector notifies us
		// session->current_state = STATE_ERROR;
		return; // no space to write the response
	}

	// now safe to write the response
	buffer_write(wb, SOCKS5_AUTH_VERSION);
	uint8_t user_type;
	if (!valid_user(username, password, &user_type)) {
		log_socks5_attempt(session, SOCKS5_REPLY_CONNECTION_NOT_ALLOWED);
		buffer_write(wb, SOCKS5_REPLY_GENERAL_FAILURE); // TODO: CHECK THIS!
		// set_error_state(session, SOCKS5_REPLY_CONNECTION_NOT_ALLOWED);
		session->current_state = STATE_ERROR_WRITE; /// maybe user a different state for auth error?
	} else {
		if (session->username) {
			free(session->username);
		}
		session->user_type = user_type;
		session->username = strdup(username);
		buffer_write(wb, SOCKS5_AUTH_SUCCESS);
		session->current_state = STATE_AUTH_WRITE;
	}
	selector_set_interest_key(key, OP_WRITE);
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
		set_error_state(session, SOCKS5_REPLY_COMMAND_NOT_SUPPORTED);
		handle_error(key);
		return;
	}

	// Command validation
	if (cmd != SOCKS5_CMD_CONNECT) {
		log(ERROR, "[REQUEST_READ] Unsupported command: 0x%02x (only CONNECT supported)", cmd);
		log_socks5_attempt(session, SOCKS5_REPLY_COMMAND_NOT_SUPPORTED);
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
		log_socks5_attempt(session, SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED);
		set_error_state(session, SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED);
		handle_error(key);
		return;
	}

	if (available < total_required) {
		log(DEBUG, "[REQUEST_READ] Need %zu bytes, have %zu", total_required, available);
		return;
	}
	session->connection.atyp = atyp; // Store ATYP for later use

	buffer_read_adv(rb, 4);

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
			set_error_state(session, SOCKS5_REPLY_GENERAL_FAILURE);
			handle_error(key);
			return;
		}

		// Convert IP to string for both logging and getaddrinfo
		char ip_str[INET_ADDRSTRLEN];
		struct in_addr addr = {.s_addr = htonl(ip)};
		if (!inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str))) {
			log(ERROR, "[REQUEST_READ] Failed to convert IPv4 address");
			set_error_state(session, SOCKS5_REPLY_GENERAL_FAILURE);
			handle_error(key);
			return;
		}

		// Store destination info for logging
		store_dest_info(session, SOCKS5_ATYP_IPV4, ip_str, port);

		// Convert port to string
		char port_str[6];
		snprintf(port_str, sizeof(port_str), "%u", port);

		// Use getaddrinfo for consistent memory management
		struct addrinfo hints;
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;
		hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV; // No DNS lookup needed

		int err = getaddrinfo(ip_str, port_str, &hints, &session->connection.dst_addresses);
		if (err != 0) {
			log(ERROR, "[REQUEST_READ] IPv4 getaddrinfo failed: %s", gai_strerror(err));
			set_error_state(session, SOCKS5_REPLY_GENERAL_FAILURE);
			handle_error(key);
			return;
		}

		log(DEBUG, "[REQUEST_READ] IPv4 address resolved: %s:%u", ip_str, port);
		request_connect(key);
		return;

	} else if (atyp == SOCKS5_ATYP_IPV6) {
		uint8_t ip[16];
		for (int i = 0; i < 16; i++) {
			ip[i] = buffer_read(rb);
		}
		uint16_t port = (buffer_read(rb) << 8) | buffer_read(rb);

		if (port == 0) {
			log(ERROR, "[REQUEST_READ] Invalid port number: %d", port);
			set_error_state(session, SOCKS5_REPLY_GENERAL_FAILURE);
			handle_error(key);
			return;
		}

		// Convert IPv6 to string for both logging and getaddrinfo
		char ip_str[INET6_ADDRSTRLEN];
		if (!inet_ntop(AF_INET6, ip, ip_str, sizeof(ip_str))) {
			log(ERROR, "[REQUEST_READ] Failed to convert IPv6 address");
			set_error_state(session, SOCKS5_REPLY_GENERAL_FAILURE);
			handle_error(key);
			return;
		}

		// Store destination info for logging
		store_dest_info(session, SOCKS5_ATYP_IPV6, ip_str, port);

		// Convert port to string
		char port_str[6];
		snprintf(port_str, sizeof(port_str), "%u", port);

		// Use getaddrinfo for consistent memory management
		struct addrinfo hints;
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_INET6;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;
		hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV; // No DNS lookup needed

		int err = getaddrinfo(ip_str, port_str, &hints, &session->connection.dst_addresses);
		if (err != 0) {
			log(ERROR, "[REQUEST_READ] IPv6 getaddrinfo failed: %s", gai_strerror(err));
			set_error_state(session, SOCKS5_REPLY_GENERAL_FAILURE);
			handle_error(key);
			return;
		}

		log(DEBUG, "[REQUEST_READ] IPv6 address resolved: [%s]:%u", ip_str, port);
		request_connect(key);
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
			set_error_state(session, SOCKS5_REPLY_GENERAL_FAILURE);
			handle_error(key);
			return;
		}

		// Store destination info for logging
		store_dest_info(session, SOCKS5_ATYP_DOMAIN, domain_name, port);

		// Store for DNS resolution (async)
		session->connection.dst_port = port;
		if (session->connection.domain_to_resolve) {
			free(session->connection.domain_to_resolve);
		}
		session->connection.domain_to_resolve = strdup(domain_name);

		log(DEBUG, "[REQUEST_READ] Parsed domain name %s and port %d.", domain_name, port);
		request_resolve(key);
		return;

	} else {
		log(ERROR, "[REQUEST_READ] Unsupported ATYP: 0x%02x. Closing connection.", atyp);
		set_error_state(session, SOCKS5_REPLY_GENERAL_FAILURE);
		handle_error(key);
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

	log(DEBUG, "[REQUEST_RESOLVE] Starting DNS resolution for %s", session->connection.domain_to_resolve);

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

// NOTE: During abrupt server shutdown (SIGTERM), there may be a small memory leak
// from active DNS resolution threads. This is expected behavior and does not
// affect normal server operation.
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
	snprintf(port_str, sizeof(port_str), "%u", session->connection.dst_port);

	int err = getaddrinfo(session->connection.domain_to_resolve, port_str, &hints, &res);
	if (err != 0) {
		if (err == EAI_MEMORY) {
			metrics_increment_errors(ERROR_TYPE_MEMORY);
		}
		log(ERROR, "[DNS_THREAD] getaddrinfo failed: %s", gai_strerror(err));
		session->dns_failed = true;
		session->dns_error_code = map_getaddrinfo_error_to_socks5(err);
		session->connection.dst_addresses = NULL;
	} else {
		log_resolved_addresses(session->connection.domain_to_resolve, res);
		session->dns_failed = false;
		session->connection.dst_addresses = res;
	}

	selector_notify_block(key->s, key->fd);
	free(key);
	return NULL;
}

static void request_connect(struct selector_key *key) {
	client_session *session = (client_session *) key->data;

	log(INFO, "[REQUEST_CONNECT] Attempting to connect to resolved address.");

	struct addrinfo *addr = session->connection.dst_addresses;

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
	if (connect_result == 0) {
		// session->current_state = STATE_REQUEST_CONNECT; // arent we already in this state?
		// selector_set_interest_key(key, OP_NOOP); // we doing this to avoid selector trying to read from remote_fd
		// Now that weve connected, create the write and read buffers
		// using buffer_size because in a single session buffer size is locked in
		session->raw_remote_read_buffer = malloc(session->buffer_size);
		session->raw_remote_write_buffer = malloc(session->buffer_size);
		if (!session->raw_remote_read_buffer || !session->raw_remote_write_buffer) {
			log(ERROR, "[REQUEST_CONNECT] Failed to allocate buffers for remote connection.");
			metrics_increment_errors(ERROR_TYPE_MEMORY);
			// Free the other buffer if one failed
			if (session->raw_remote_read_buffer) {
				free(session->raw_remote_read_buffer);
				session->raw_remote_read_buffer = NULL;
			}
			if (session->raw_remote_write_buffer) {
				free(session->raw_remote_write_buffer);
				session->raw_remote_write_buffer = NULL;
			}
			handle_error(key);
			return;
		}
		buffer_init(&session->remote_read_buffer, session->buffer_size, session->raw_remote_read_buffer);
		buffer_init(&session->remote_write_buffer, session->buffer_size, session->raw_remote_write_buffer);

		if (selector_register(key->s, session->remote_fd, &remote_handler, OP_NOOP, session) != SELECTOR_SUCCESS) {
			log(ERROR, "[REQUEST_CONNECT] Failed to register remote fd");
			set_error_state(session, SOCKS5_REPLY_GENERAL_FAILURE);
			handle_error(key);
			return;
		}

		log(DEBUG, "[REQUEST_CONNECT] Connection in progress...");
		handle_connect_success(key);
		return;
	} else if (connect_result == -1 && errno == EINPROGRESS) {
		selector_status st = selector_register(key->s, session->remote_fd, &remote_handler, OP_WRITE, session);
		if (st != SELECTOR_SUCCESS) {
			log(ERROR, "[REQUEST_CONNECT] Failed to register remote fd: %d", st);
			close(session->remote_fd);
			session->remote_fd = -1;
			set_error_state(session, SOCKS5_REPLY_GENERAL_FAILURE);
			handle_error(key);
			return;
		}
		// Asignar buffers para cuando se complete la conexión
		session->raw_remote_read_buffer = malloc(session->buffer_size);
		session->raw_remote_write_buffer = malloc(session->buffer_size);
		if (!session->raw_remote_read_buffer || !session->raw_remote_write_buffer) {
			log(ERROR, "[REQUEST_CONNECT] Failed to allocate buffers for remote connection.");
			metrics_increment_errors(ERROR_TYPE_MEMORY);
			if (session->raw_remote_read_buffer) {
				free(session->raw_remote_read_buffer);
				session->raw_remote_read_buffer = NULL;
			}
			if (session->raw_remote_write_buffer) {
				free(session->raw_remote_write_buffer);
				session->raw_remote_write_buffer = NULL;
			}
			handle_error(key);
			return;
		}

		buffer_init(&session->remote_read_buffer, session->buffer_size, session->raw_remote_read_buffer);
		buffer_init(&session->remote_write_buffer, session->buffer_size, session->raw_remote_write_buffer);

		session->current_state = STATE_REQUEST_CONNECT;
		selector_set_interest_key(key, OP_NOOP);
		return;
	}
	log(ERROR, "[REQUEST_CONNECT] Connection failed immediately: %s", strerror(errno));

	// try the next address if available
	if (addr->ai_next) {
		log(DEBUG, "[REQUEST_CONNECT] Trying next address...");

		struct addrinfo *failed_addr = session->connection.dst_addresses;
		session->connection.dst_addresses = addr->ai_next;

		// unlink and free the failed address
		failed_addr->ai_next = NULL;
		freeaddrinfo(failed_addr);

		// Try connecting to next address
		request_connect(key);
		return;
	}
	log(ERROR, "[REQUEST_CONNECT] No more addresses to try");
	uint8_t error_code = map_connect_error_to_socks5(errno);
	log_socks5_attempt(session, error_code);
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

	selector_unregister_fd(key->s, key->fd);
	close(key->fd);
	session->remote_fd = -1;

	struct addrinfo *current_addr = session->connection.dst_addresses;
	if (current_addr && current_addr->ai_next != NULL) {
		log(INFO, "[REMOTE_CONNECT_COMPLETE] Trying next address...");

		struct addrinfo *failed_addr = current_addr;
		session->connection.dst_addresses = current_addr->ai_next;

		// free failed address
		failed_addr->ai_next = NULL;
		freeaddrinfo(failed_addr);

		// try connecting to next IP
		struct selector_key client_key = {.s = key->s, .fd = session->client_fd, .data = session};
		request_connect(&client_key);
		return;
	}

	log(ERROR, "[HANDLE_CONNECT_FAILURE] No more addresses to try.");
	uint8_t error_code = map_connect_error_to_socks5(error);
	log_socks5_attempt(session, error_code);

	struct selector_key client_key = {.s = key->s, .fd = session->client_fd, .data = session};
	set_error_state(session, error_code);
	handle_error(&client_key);
}

static void handle_connect_success(struct selector_key *key) {
	client_session *session = (client_session *) key->data;

	log(INFO, "[REMOTE_CONNECT_COMPLETE] Connection successful");
	log_socks5_attempt(session, 0x00);

	if (session->connection.dst_addresses) {
		freeaddrinfo(session->connection.dst_addresses);
		session->connection.dst_addresses = NULL;
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

	buffer *client_to_remote_buf = &session->remote_write_buffer;

	size_t space;
	uint8_t *write_ptr = buffer_write_ptr(client_to_remote_buf, &space);

	ssize_t bytes_read = recv(session->client_fd, write_ptr, space, 0);
	if (bytes_read < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return;
		metrics_increment_errors(ERROR_TYPE_NETWORK);
		handle_error(key);
		return;
	}
	if (bytes_read == 0) {
		log(DEBUG, "[RELAY] Client closed connection");

		selector_unregister_fd(key->s, key->fd);
		close(key->fd);
		return;
	}

	buffer_write_adv(client_to_remote_buf, bytes_read);
	metrics_add_bytes_in(bytes_read);

	// Flush from client_to_remote_buf to remote
	while (buffer_can_read(client_to_remote_buf)) {
		size_t len;
		uint8_t *read_ptr = buffer_read_ptr(client_to_remote_buf, &len);
		ssize_t bytes_written = send(session->remote_fd, read_ptr, len, MSG_NOSIGNAL);
		if (bytes_written < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				// Wait until remote is writable !
				selector_set_interest(key->s, session->remote_fd, OP_WRITE);
				break;
			}
			metrics_increment_errors(ERROR_TYPE_NETWORK);
			handle_error(key);
			return;
		}
		metrics_add_bytes_out(bytes_written);
		buffer_read_adv(client_to_remote_buf, bytes_written);
	}

	log(DEBUG, "[RELAY] Relayed data client->remote");

	// If buffer still has data, make sure OP_WRITE is enabled
	if (buffer_can_read(client_to_remote_buf)) {
		selector_set_interest(key->s, session->remote_fd, OP_WRITE);
	}
}

static void relay_remote_to_client(struct selector_key *key) {
	client_session *session = (client_session *) key->data;

	buffer *remote_to_client_buf = &session->remote_read_buffer;

	size_t space;
	uint8_t *write_pnt = buffer_write_ptr(remote_to_client_buf, &space);
	int bytes_read = recv(session->remote_fd, write_pnt, space, 0);
	if (bytes_read < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return;
		metrics_increment_errors(ERROR_TYPE_NETWORK);
		handle_error(key);
		return;
	}
	if (bytes_read == 0) {
		log(DEBUG, "[RELAY] Remote closed connection");
		selector_unregister_fd(key->s, key->fd);
		close(key->fd);
		return;
	}

	buffer_write_adv(remote_to_client_buf, bytes_read);
	metrics_add_bytes_in(bytes_read);

	// Flush to client
	while (buffer_can_read(remote_to_client_buf)) {
		size_t read_len;
		uint8_t *read_pt = buffer_read_ptr(remote_to_client_buf, &read_len);
		ssize_t bytes_written = send(session->client_fd, read_pt, read_len, MSG_NOSIGNAL);
		if (bytes_written < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				selector_set_interest(key->s, session->client_fd, OP_WRITE);
				break;
			}
			metrics_increment_errors(ERROR_TYPE_NETWORK);
			handle_error(key);
			return;
		}
		metrics_add_bytes_out(bytes_written);
		buffer_read_adv(remote_to_client_buf, bytes_written);
	}

	log(DEBUG, "[RELAY] Relayed data remote->client");

	// is there more to read from ?
	if (buffer_can_read(remote_to_client_buf)) {
		selector_set_interest(key->s, session->client_fd, OP_WRITE);
	}
}

static void relay_write(struct selector_key *key) {
	client_session *session = (client_session *) key->data;

	if (key->fd == session->client_fd) {
		// client want to write -> if theres pending in buffer from remote we must write it to client!!
		buffer *remote_to_client_buf = &session->remote_read_buffer;

		while (buffer_can_read(remote_to_client_buf)) {
			size_t read_len;
			uint8_t *read_pt = buffer_read_ptr(remote_to_client_buf, &read_len);
			ssize_t bytes_written = send(session->client_fd, read_pt, read_len, MSG_NOSIGNAL);
			if (bytes_written < 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK) {
					// still can't write, keep write interest
					return;
				}
				metrics_increment_errors(ERROR_TYPE_NETWORK);
				handle_error(key);
				return;
			}
			metrics_add_bytes_out(bytes_written);
			buffer_read_adv(remote_to_client_buf, bytes_written);
		}

		// if data was flushed, remove write interest from client
		if (!buffer_can_read(remote_to_client_buf)) {
			selector_set_interest(key->s, session->client_fd, OP_READ);
		}

		log(DEBUG, "[RELAY_WRITE] Flushed pending data from remote to client");

	} else if (key->fd == session->remote_fd) {
		// Remote is writable -> try to flush any pending data from client to remote
		buffer *client_to_remote_buf = &session->remote_write_buffer;

		while (buffer_can_read(client_to_remote_buf)) {
			size_t len;
			uint8_t *read_ptr = buffer_read_ptr(client_to_remote_buf, &len);
			ssize_t bytes_written = send(session->remote_fd, read_ptr, len, MSG_NOSIGNAL);
			if (bytes_written < 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK) {
					// can't write, keep write interest
					return;
				}
				metrics_increment_errors(ERROR_TYPE_NETWORK);
				handle_error(key);
				return;
			}
			metrics_add_bytes_out(bytes_written);
			buffer_read_adv(client_to_remote_buf, bytes_written);
		}

		// If we've flushed all data, remove write interest from remote
		if (!buffer_can_read(client_to_remote_buf)) {
			selector_set_interest(key->s, session->remote_fd, OP_READ);
		}

		log(DEBUG, "[RELAY_WRITE] Flushed pending data from client to remote");

	} else {
		log(ERROR, "[RELAY_WRITE] Unknown fd=%d", key->fd);
		handle_error(key);
	}
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

static error_type_t map_socks5_error_to_type(uint8_t error_code) {
	switch (error_code) {
		case SOCKS5_REPLY_NETWORK_UNREACHABLE:
		case SOCKS5_REPLY_HOST_UNREACHABLE:
		case SOCKS5_REPLY_CONNECTION_REFUSED:
			return ERROR_TYPE_NETWORK;
		case SOCKS5_REPLY_COMMAND_NOT_SUPPORTED:
		case SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED:
			return ERROR_TYPE_PROTOCOL;
		case SOCKS5_REPLY_TTL_EXPIRED:
			return ERROR_TYPE_TIMEOUT;
		case SOCKS5_REPLY_CONNECTION_NOT_ALLOWED:
			return ERROR_TYPE_AUTH;
		default:
			return ERROR_TYPE_OTHER;
	}
}

static void set_error_state(client_session *session, uint8_t error_code) {
	session->has_error = true;
	session->error_code = error_code;
	session->error_response_sent = false;
	session->current_state = STATE_ERROR;

	error_type_t error_type = map_socks5_error_to_type(error_code);
	metrics_increment_errors(error_type);
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
	// selector_unregister_fd(key->s, key->fd); REMOVED line bc the selector will handle cleanup via EPOLLHUP
	log(DEBUG, "[HANDLE_ERROR] Closing fd=%d to trigger cleanup", key->fd);
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

bool valid_user(const char *username, const char *password, uint8_t *out_type) {
	for (int i = 0; i < nusers; i++) {
		if (strcmp(username, users[i].name) == 0 && strcmp(password, users[i].pass) == 0) {
			*out_type = users[i].type;
			return true;
		}
	}
	return false;
}

static void cleanup_session(client_session *session) {
	if (!session) // no longer need the flag setting here
		return;

	log(DEBUG, "[CLEANUP] Starting session cleanup for client_fd=%d, remote_fd=%d", session->client_fd,
		session->remote_fd);

	// Clean up connection data
	if (session->connection.dst_addresses) {
		log(DEBUG, "[CLEANUP] Freeing dst_addresses (atyp=%d)", session->connection.atyp);
		freeaddrinfo(session->connection.dst_addresses);
		session->connection.dst_addresses = NULL;
	}

	if (session->connection.domain_to_resolve) {
		free(session->connection.domain_to_resolve);
		session->connection.domain_to_resolve = NULL;
	}

	if (session->remote_fd != -1) {
		log(ERROR, "[CLEANUP] remote_fd=%d still open during cleanup", session->remote_fd);
		close(session->remote_fd);
		session->remote_fd = -1;
	}

	// Clean up client buffers
	if (session->raw_read_buffer) {
		buffer_reset(&session->read_buffer);
		free(session->raw_read_buffer);
		session->raw_read_buffer = NULL;
	}
	if (session->raw_write_buffer) {
		buffer_reset(&session->write_buffer);
		free(session->raw_write_buffer);
		session->raw_write_buffer = NULL;
	}

	// Clean up remote buffers only if they were allocated
	if (session->raw_remote_read_buffer) {
		buffer_reset(&session->remote_read_buffer);
		free(session->raw_remote_read_buffer);
		session->raw_remote_read_buffer = NULL;
	}
	if (session->raw_remote_write_buffer) {
		buffer_reset(&session->remote_write_buffer);
		free(session->raw_remote_write_buffer);
		session->raw_remote_write_buffer = NULL;
	}

	if (session->username) {
		free(session->username);
		session->username = NULL;
	}
}

static void log_socks5_attempt(client_session *session, uint8_t status_code) {
	const char *username = session->username ? session->username : NULL;

	// All data is already stored in session - no system calls needed!
	add_access_log(username, session->logging.client_ip, session->logging.client_port, session->logging.dest_atyp,
				   session->logging.dest_addr, session->logging.dest_port, status_code);

	log(DEBUG, "[ACCESS_LOG] %s@%s:%d -> %s:%d (status: 0x%02x)", username ? username : "anonymous",
		session->logging.client_ip, session->logging.client_port, session->logging.dest_addr,
		session->logging.dest_port, status_code);
}

void store_client_info(client_session *session, struct sockaddr_storage *client_addr) {
	session->logging.client_port = 0;
	strcpy(session->logging.client_ip, "unknown");

	if (client_addr->ss_family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in *) client_addr;
		inet_ntop(AF_INET, &sin->sin_addr, session->logging.client_ip, sizeof(session->logging.client_ip));
		session->logging.client_port = ntohs(sin->sin_port);
	} else if (client_addr->ss_family == AF_INET6) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) client_addr;
		inet_ntop(AF_INET6, &sin6->sin6_addr, session->logging.client_ip, sizeof(session->logging.client_ip));
		session->logging.client_port = ntohs(sin6->sin6_port);
	}
}

void store_dest_info(client_session *session, uint8_t atyp, const char *addr, uint16_t port) {
	session->logging.dest_atyp = atyp;
	session->logging.dest_port = port;
	strncpy(session->logging.dest_addr, addr, sizeof(session->logging.dest_addr) - 1);
	session->logging.dest_addr[sizeof(session->logging.dest_addr) - 1] = '\0';
}