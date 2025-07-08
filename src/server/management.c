#include "include/management.h"
#include "include/args.h"
#include "include/config.h"
#include "include/logger.h"
#include "include/metrics.h"
#include "include/selector.h"
#include "include/management_commands.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// State machine handlers
static void management_handle_read(struct selector_key *key);
static void management_handle_write(struct selector_key *key);
static void management_handle_close(struct selector_key *key);

// Individual state handlers
static void hello_read(struct selector_key *key);
static void hello_write(struct selector_key *key);
static void command_read(struct selector_key *key);
static void command_write(struct selector_key *key);
static void handle_error(struct selector_key *key);

/**************** Handler structures (following SOCKS5 pattern) *****************/

static const struct fd_handler management_handler = {.handle_read = management_handle_read,
													 .handle_write = management_handle_write,
													 .handle_close = management_handle_close,
													 .handle_block = NULL};

/**************** Main connection handler *****************/

void management_handle_new_connection(struct selector_key *key) {
	int listen_fd = key->fd;
	struct sockaddr_storage client_addr;
	socklen_t client_addr_len = sizeof(client_addr);

	int client_fd = accept(listen_fd, (struct sockaddr *) &client_addr, &client_addr_len);
	if (client_fd < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return; // no connection to accept (race condition)
		}
		log(ERROR, "[MANAGEMENT] accept() error: %s", strerror(errno));
		return;
	}

	if (selector_fd_set_nio(client_fd) == -1) {
		log(ERROR, "[MANAGEMENT] Failed to set non-blocking mode");
		close(client_fd);
		return;
	}

	management_session *session = calloc(1, sizeof(management_session));
	if (!session) {
		log(ERROR, "[MANAGEMENT] Failed to allocate session");
		close(client_fd);
		return;
	}

	session->client_fd = client_fd;
	session->current_state = MNG_STATE_HELLO_READ;
	session->authenticated = false;
	session->user_type = 0xFF; // invalid until authenticated
	session->has_error = false;
	session->error_code = RESPONSE_SUCCESS_CLIENT;
	session->error_response_sent = false;
	session->cleaned_up = false;

	// allocating buffers (following SOCKS5 pattern)
	session->buffer_size = g_management_buffer_size;
	session->raw_read_buffer = malloc(session->buffer_size);
	session->raw_write_buffer = malloc(session->buffer_size);

	if (!session->raw_read_buffer || !session->raw_write_buffer) {
		log(ERROR, "[MANAGEMENT] Failed to allocate buffers");
		if (session->raw_read_buffer)
			free(session->raw_read_buffer);
		if (session->raw_write_buffer)
			free(session->raw_write_buffer);
		free(session);
		close(client_fd);
		return;
	}

	buffer_init(&session->read_buffer, session->buffer_size, session->raw_read_buffer);
	buffer_init(&session->write_buffer, session->buffer_size, session->raw_write_buffer);

	if (selector_register(key->s, client_fd, &management_handler, OP_READ, session) != SELECTOR_SUCCESS) {
		log(ERROR, "[MANAGEMENT] Failed to register with selector");
		cleanup_session(session);
		free(session);
		close(client_fd);
		return;
	}

	log(INFO, "[MANAGEMENT] New CalSetting connection: fd=%d", client_fd);
}

/**************** State machine dispatchers *****************/

static void management_handle_read(struct selector_key *key) {
	management_session *session = (management_session *) key->data;

	switch (session->current_state) {
		case MNG_STATE_HELLO_READ:
			hello_read(key);
			break;
		case MNG_STATE_COMMAND_READ:
			command_read(key);
			break;
		case MNG_STATE_ERROR:
			handle_error(key);
			break;
		default:
			log(ERROR, "[MANAGEMENT] Unexpected read state: %d", session->current_state);
			set_error_state(session, RESPONSE_GENERAL_SERVER_FAILURE);
			handle_error(key);
			break;
	}
}

static void management_handle_write(struct selector_key *key) {
	management_session *session = (management_session *) key->data;

	switch (session->current_state) {
		case MNG_STATE_HELLO_WRITE:
			hello_write(key);
			break;
		case MNG_STATE_COMMAND_WRITE:
			command_write(key);
			break;
		case MNG_STATE_ERROR:
			handle_error(key);
			break;
		default:
			log(ERROR, "[MANAGEMENT] Unexpected write state: %d", session->current_state);
			set_error_state(session, RESPONSE_GENERAL_SERVER_FAILURE);
			handle_error(key);
			break;
	}
}

static void management_handle_close(struct selector_key *key) {
	management_session *session = (management_session *) key->data;

	log(DEBUG, "[MANAGEMENT] Closing connection fd=%d", key->fd);

	if (session) {
		cleanup_session(session);
		free(session);
	}
}

/**************** Individual state handlers *****************/
/*
Reads:
VER | ULEN | PWDLEN | USERNAME (ULEN bytes) | PASSWORD (PWDLEN bytes)
*/

static void hello_read(struct selector_key *key) {
	management_session *session = (management_session *) key->data;
	if (!session) {
		return;
	}
	buffer *rb = &session->read_buffer;

	log(DEBUG, "[MANAGEMENT] Hello read state");

	size_t wbytes;
	uint8_t *ptr = buffer_write_ptr(rb, &wbytes);
	if (wbytes <= 0) {
		buffer_compact(rb);
		ptr = buffer_write_ptr(rb, &wbytes);
		if (wbytes <= 0) {
			log(ERROR, "[MANAGEMENT] No buffer space for hello read");
			set_error_state(session, RESPONSE_GENERAL_SERVER_FAILURE);
			handle_error(key);
			return;
		}
	}

	ssize_t bytes_read = recv(key->fd, ptr, wbytes, 0);
	if (bytes_read < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return;
		}
		log(ERROR, "[MANAGEMENT] recv() error in hello_read: %s", strerror(errno));
		set_error_state(session, RESPONSE_GENERAL_SERVER_FAILURE);
		handle_error(key);
		return;
	} else if (bytes_read == 0) {
		log(INFO, "[MANAGEMENT] Connection closed by client during hello");
		set_error_state(session, RESPONSE_GENERAL_SERVER_FAILURE);
		handle_error(key);
		return;
	}

	buffer_write_adv(rb, bytes_read);
	log(DEBUG, "[MANAGEMENT] Read %zd bytes for hello", bytes_read);

	size_t available;
	uint8_t *data = buffer_read_ptr(rb, &available);
	if (available < HELLO_HEADER_FIXED_LEN) {
		return;
	}

	uint8_t version = data[0];
	uint8_t ulen = data[1];
	uint8_t pwdlen = data[2];

	log(DEBUG, "[MANAGEMENT] Hello header: ver=%d ulen=%d pwdlen=%d", version, ulen, pwdlen);

	if (version != CALSETTING_VERSION) {
		log(ERROR, "[MANAGEMENT] Wrong protocol version: %d", version);
		set_error_state(session, RESPONSE_WRONG_VERSION);
		handle_error(key);
		return;
	}

	size_t total_needed = HELLO_HEADER_FIXED_LEN + ulen + pwdlen;
	if (available < total_needed) {
		return;
	}

	buffer_read_adv(rb, HELLO_HEADER_FIXED_LEN);

	char username[USERNAME_MAX_SIZE], password[PASSWORD_MAX_SIZE];
	for (int i = 0; i < ulen; i++) {
		username[i] = buffer_read(rb);
	}
	username[ulen] = '\0';

	for (int i = 0; i < pwdlen; i++) {
		password[i] = buffer_read(rb);
	}
	password[pwdlen] = '\0';

	log(DEBUG, "[MANAGEMENT] Authenticating user: %s", username);

	uint8_t auth_result = authenticate_user(username, password);
	uint8_t response_code;

	// TODO: determine whether there is a better way to handle user types and do this check
	if (auth_result == USER_TYPE_ADMIN) {
		response_code = RESPONSE_SUCCESS_ADMIN;
		session->user_type = USER_TYPE_ADMIN;
		session->authenticated = true;
		strcpy(session->username, username);
		log(INFO, "[MANAGEMENT] Admin authenticated: %s", username);
	} else if (auth_result == USER_TYPE_CLIENT) {
		response_code = RESPONSE_SUCCESS_CLIENT;
		session->user_type = USER_TYPE_CLIENT;
		session->authenticated = true;
		strcpy(session->username, username);
		log(INFO, "[MANAGEMENT] User authenticated: %s", username);
	} else { // auth_result == RESPONSE_AUTH_FAILURE
		response_code = RESPONSE_AUTH_FAILURE;
		session->authenticated = false;
		log(INFO, "[MANAGEMENT] Authentication failed: %s", username);
		// TODO: should close the session after sending the response (it's done based on whether the session is
		// authenticated... is this theb est way?)
	}

	buffer *wb = &session->write_buffer;
	if (buffer_writeable_bytes(wb) < 2) {
		log(ERROR, "[MANAGEMENT] No space for hello response");
		set_error_state(session, RESPONSE_GENERAL_SERVER_FAILURE);
		handle_error(key);
		return;
	}

	buffer_write(wb, CALSETTING_VERSION);
	buffer_write(wb, response_code);

	session->current_state = MNG_STATE_HELLO_WRITE;
	selector_set_interest_key(key, OP_WRITE);
}

static void hello_write(struct selector_key *key) {
	management_session *session = (management_session *) key->data;
	if (!write_to_client(key, false)) {
		return; // still writing
	}

	if (!session->authenticated) {
		// authentication failed, close connection
		session->current_state = MNG_STATE_DONE;
		selector_unregister_fd(key->s, key->fd);
		close(key->fd);
		return;
	}

	// authentication success, wait for commands
	session->current_state = MNG_STATE_COMMAND_READ;
	selector_set_interest_key(key, OP_READ);
}

/*
VER CMD ARG1 ARG2 (4 bytes total)
*/

static void command_read(struct selector_key *key) {
	management_session *session = (management_session *) key->data;
	buffer *rb = &session->read_buffer;

	log(DEBUG, "[MANAGEMENT] Command read state");

	size_t wbytes;
	uint8_t *ptr = buffer_write_ptr(rb, &wbytes);
	if (wbytes <= 0) {
		buffer_compact(rb);
		ptr = buffer_write_ptr(rb, &wbytes);
		if (wbytes <= 0) {
			log(ERROR, "[MANAGEMENT] No buffer space for command read");
			set_error_state(session, RESPONSE_GENERAL_SERVER_FAILURE);
			handle_error(key);
			return;
		}
	}

	ssize_t bytes_read = recv(key->fd, ptr, wbytes, 0);
	if (bytes_read < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return;
		}
		log(ERROR, "[MANAGEMENT] recv() error in command_read: %s", strerror(errno));
		set_error_state(session, RESPONSE_GENERAL_SERVER_FAILURE);
		handle_error(key);
		return;
	} else if (bytes_read == 0) {
		log(INFO, "[MANAGEMENT] Connection closed by client during command");
		selector_unregister_fd(key->s, key->fd);
		close(key->fd);
		return;
	}

	buffer_write_adv(rb, bytes_read);
	log(DEBUG, "[MANAGEMENT] Read %zd bytes for command", bytes_read); // TODO: unnecessary debug log... maybe delete

	size_t available;
	uint8_t *data = buffer_read_ptr(rb, &available);
	if (available < REQUEST_SIZE) {
		return;
	}

	uint8_t version = data[0];
	uint8_t cmd = data[1];
	uint8_t arg1 = data[2];
	uint8_t arg2 = data[3];

	log(DEBUG, "[MANAGEMENT] Command: ver=0x%02x cmd=0x%02x arg1=0x%02x arg2=0x%02x", version, cmd, arg1, arg2);

	if (version != CALSETTING_VERSION) {
		log(ERROR, "[MANAGEMENT] Wrong version in command: %d", version);
		set_error_state(session, RESPONSE_WRONG_VERSION);
		handle_error(key);
		return;
	}
	buffer_read_adv(rb, REQUEST_SIZE);

	if (session->user_type != USER_TYPE_ADMIN) {
		switch (cmd) {
			case COMMAND_LOGS:
			case COMMAND_CHANGE_BUFFER_SIZE:
			case COMMAND_CHANGE_TIMEOUT:
			case COMMAND_ADD_CLIENT:
			case COMMAND_REMOVE_USER:
				// admin-only commands
				log(ERROR, "[MANAGEMENT] User %s attempted admin command %d", session->username, cmd);
				set_error_state(session, RESPONSE_NOT_ALLOWED);
				handle_error(key);
				return;
		}
	}

	switch (cmd) {
		case COMMAND_METRICS:
			process_metrics_command(session);
			break;
		case COMMAND_LOGS:
			process_logs_command(session, arg1, arg2);
			break;
		case COMMAND_USER_LIST:
			process_userlist_command(session, arg1, arg2);
			break;
		case COMMAND_CHANGE_BUFFER_SIZE:
			process_change_buffer_command(session, arg1);
			break;
		case COMMAND_CHANGE_TIMEOUT:
			process_change_timeout_command(session, arg1);
			break;
		case COMMAND_ADD_ADMIN:
			process_add_user_command(session, arg1, arg2, USER_TYPE_ADMIN);
			break;
		case COMMAND_ADD_CLIENT:
			process_add_user_command(session, arg1, arg2, USER_TYPE_CLIENT);
			break;
		case COMMAND_REMOVE_USER:
			process_remove_user_command(session, arg1);
			break;
		case COMMAND_GET_CURRENT_CONFIG:
			process_get_current_config_command(session);
			break;
		default:
			// TODO: this should never happen due to earlier validation
			log(ERROR, "[MANAGEMENT] Unknown command: %d", cmd);
			set_error_state(session, RESPONSE_GENERAL_SERVER_FAILURE);
			handle_error(key);
			return;
	}

	session->current_state = MNG_STATE_COMMAND_WRITE;
	selector_set_interest_key(key, OP_WRITE);
}

static void command_write(struct selector_key *key) {
	management_session *session = (management_session *) key->data;

	if (!write_to_client(key, false)) {
		return;
	}

	session->current_state = MNG_STATE_COMMAND_READ;
	selector_set_interest_key(key, OP_READ);
}

void handle_error(struct selector_key *key) {
	// management_session *session = (management_session *) key->data;

	log(DEBUG, "[MANAGEMENT] Handling error state");

	// for management protocol, we usually just close the connection on error
	selector_unregister_fd(key->s, key->fd);
	close(key->fd);
}