// management.c - Complete implementation following SOCKS5 pattern
#include "include/management.h"
#include "include/args.h"
#include "include/config.h"
#include "include/logger.h"
#include "include/metrics.h"
#include "include/selector.h"
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_INPUT_SIZE 256
#define CLAMP_UINT16(value) ((value) > UINT16_MAX ? UINT16_MAX : (uint16_t) (value))

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

// Command processors
static void process_metrics_command(management_session *session);
static void process_logs_command(management_session *session, uint8_t number, uint8_t offset);
static void process_userlist_command(management_session *session, uint8_t number, uint8_t offset);
static void process_change_buffer_command(management_session *session, uint8_t new_size);
static void process_change_timeout_command(management_session *session, uint8_t new_timeout);

// Helper functions
static void set_error_state(management_session *session, uint8_t error_code);
static void cleanup_session(management_session *session);
static bool write_to_client(struct selector_key *key, bool should_close);
static uint8_t authenticate_user(const char *username, const char *password);
static log_entry_t* get_reusable_log_buffer(size_t required_count);

// External configuration variables
extern size_t g_socks5_buffer_size;
extern int g_connection_timeout;
extern size_t g_management_buffer_size;
extern struct users *us;
extern uint8_t nusers;

static log_entry_t *reusable_log_buffer = NULL;
static size_t reusable_buffer_capacity = 0;

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

	char username[MAX_INPUT_SIZE], password[MAX_INPUT_SIZE];
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

	log(DEBUG, "[MANAGEMENT] Command: ver=%d cmd=%d arg1=%d arg2=%d", version, cmd, arg1, arg2);

	if (version != CALSETTING_VERSION) {
		log(ERROR, "[MANAGEMENT] Wrong version in command: %d", version);
		set_error_state(session, RESPONSE_WRONG_VERSION);
		handle_error(key);
		return;
	}

	// TODO: check if command is valid (within range) -> size of commands could change so maybe figure out a better way
	// if (cmd < COMMAND_LOGS || cmd > COMMAND_CHANGE_TIMEOUT) {
	// 	log(ERROR, "[MANAGEMENT] Invalid command: %d", cmd);
	// 	set_error_state(session, RESPONSE_BAD_REQUEST);
	// 	handle_error(key);
	// 	return;
	// }

	buffer_read_adv(rb, REQUEST_SIZE);

	session->current_command = cmd;
	session->current_arg1 = arg1;
	session->current_arg2 = arg2;

	// check permissions
	if (session->user_type != USER_TYPE_ADMIN) {
		switch (cmd) {
			case COMMAND_LOGS:
			case COMMAND_USER_LIST:
			case COMMAND_CHANGE_BUFFER_SIZE:
			case COMMAND_CHANGE_TIMEOUT:
				// admin-only commands
				log(DEBUG, "[MANAGEMENT] User %s attempted admin command %d", session->username, cmd);
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

/**************** Command processors *****************/
/*
VER | SOCKS5_STATE | CONCURRENT_CONNECTIONS | TOTAL_CONNECTIONS | MAX_CONCURRENT | BYTES_IN
 1  |      1       |          4             |        8          |       4        |    8

BYTES_OUT | TOTAL_BYTES | TOTAL_ERRORS | UPTIME_SECONDS | NETWORK_ERRORS | PROTOCOL_ERRORS
	8     |      8      |      4       |       4        |       4        |       4

AUTH_ERRORS | SYSTEM_ERRORS | TIMEOUT_ERRORS | MEMORY_ERRORS | OTHER_ERRORS
	 4      |       4       |       4        |       4       |      4

Total size: 1 + 1 + 4 + 8 + 4 + 8 + 8 + 8 + 4 + 4 + 4 + 4 + 4 + 4 + 4 + 4 + 4 = 78 bytes
*/
static void process_metrics_command(management_session *session) {
	buffer *wb = &session->write_buffer;

	// ensure buffer is clean
	buffer_reset(wb);

	if (buffer_writeable_bytes(wb) < sizeof(metrics_t)) {
		log(ERROR, "[MANAGEMENT] No space for metrics response");
		set_error_state(session, RESPONSE_GENERAL_SERVER_FAILURE);
		return;
	}

	server_metrics *real_metrics = metrics_get();
	if (!real_metrics) {
		log(ERROR, "[MANAGEMENT] Failed to get server metrics");
		set_error_state(session, RESPONSE_GENERAL_SERVER_FAILURE);
		return;
	}

	uint32_t uptime = (uint32_t) (time(NULL) - real_metrics->start_time);

	metrics_t response = {.version = CALSETTING_VERSION,
						  .server_state = 1, // TODO: determine server state propelry

						  .total_connections = real_metrics->total_connections > UINT32_MAX ?
												   UINT32_MAX :
												   (uint32_t) real_metrics->total_connections,
						  .concurrent_connections = CLAMP_UINT16(real_metrics->concurrent_connections),
						  .max_concurrent_connections = CLAMP_UINT16(real_metrics->max_concurrent_connections),

						  .bytes_transferred_in = real_metrics->bytes_transferred_in,
						  .bytes_transferred_out = real_metrics->bytes_transferred_out,
						  .total_bytes_transferred = real_metrics->total_bytes_transferred,

						  .total_errors = real_metrics->total_errors,
						  .uptime_seconds = uptime,

						  .network_errors = CLAMP_UINT16(real_metrics->error_counts[ERROR_TYPE_NETWORK]),
						  .protocol_errors = CLAMP_UINT16(real_metrics->error_counts[ERROR_TYPE_PROTOCOL]),
						  .auth_errors = CLAMP_UINT16(real_metrics->error_counts[ERROR_TYPE_AUTH]),
						  .system_errors = CLAMP_UINT16(real_metrics->error_counts[ERROR_TYPE_SYSTEM]),
						  .timeout_errors = CLAMP_UINT16(real_metrics->error_counts[ERROR_TYPE_TIMEOUT]),
						  .memory_errors = CLAMP_UINT16(real_metrics->error_counts[ERROR_TYPE_MEMORY]),
						  .other_errors = CLAMP_UINT16(real_metrics->error_counts[ERROR_TYPE_OTHER]),

						  .reserved = 0,
						  .reserved2 = 0};
	response.total_connections = htonl(response.total_connections);
	response.concurrent_connections = htons(response.concurrent_connections);
	response.max_concurrent_connections = htons(response.max_concurrent_connections);
	response.bytes_transferred_in = htobe64(response.bytes_transferred_in);
	response.bytes_transferred_out = htobe64(response.bytes_transferred_out);
	response.total_bytes_transferred = htobe64(response.total_bytes_transferred);
	response.total_errors = htonl(response.total_errors);
	response.uptime_seconds = htonl(response.uptime_seconds);
	response.network_errors = htons(response.network_errors);
	response.protocol_errors = htons(response.protocol_errors);
	response.auth_errors = htons(response.auth_errors);
	response.system_errors = htons(response.system_errors);
	response.timeout_errors = htons(response.timeout_errors);
	response.memory_errors = htons(response.memory_errors);
	response.other_errors = htons(response.other_errors);

	size_t writable;
	uint8_t *write_ptr = buffer_write_ptr(wb, &writable);

	if (writable < sizeof(metrics_t)) {
		log(ERROR, "[MANAGEMENT] Buffer space lost between initial check and write");
		set_error_state(session, RESPONSE_GENERAL_SERVER_FAILURE);
		return;
	}

	memcpy(write_ptr, &response, sizeof(metrics_t));
	buffer_write_adv(wb, sizeof(metrics_t));

	log(DEBUG, "[MANAGEMENT] Metrics response written successfully");
}

/*
VER | STATUS | COUNT | RSV | LOG_ENTRY_1 | LOG_ENTRY_2 | ... | LOG_ENTRY_N
 1   |   1    |   1   |  1  | (586 bytes each)
Total size: 4 + (586 * COUNT) bytes
*/
// Example calculation for different buffer sizes:

/*
Buffer Size | Max Logs | Wire Size per Log | Total Size
------------|----------|-------------------|------------
4KB (4096)  |    6     |       586         |   3520
8KB (8192)  |   13     |       586         |   7622  
16KB        |   28     |       586         |  16404

*/
static void process_logs_command(management_session *session, uint8_t number, uint8_t offset) {
	buffer *wb = &session->write_buffer;
	buffer_reset(wb);

	size_t available = g_management_buffer_size - LOGS_RESPONSE_HEADER_FIXED_LEN;
    int max_logs_per_response = (int)available / LOG_ENTRY_WIRE_SIZE;

	log(DEBUG, "[MANAGEMENT] Buffer can handle max %d logs per response", max_logs_per_response);

	if (max_logs_per_response <= 0) {
        log(ERROR, "[MANAGEMENT] Buffer too small for even one log entry");
        buffer_write(wb, CALSETTING_VERSION);
        buffer_write(wb, RESPONSE_GENERAL_SERVER_FAILURE);
        buffer_write(wb, 0);
        buffer_write(wb, 0);
        return;
    }

	// Cap the request to what fits in buffer
    int logs_to_fetch = (number > max_logs_per_response) ? max_logs_per_response : number;

	if (logs_to_fetch != number) {
        log(DEBUG, "[MANAGEMENT] Capping request from %d to %d logs (buffer limit)", 
            number, logs_to_fetch);
    }

    log_entry_t *log_buffer = get_reusable_log_buffer(logs_to_fetch);
    if (!log_buffer) {
        log(ERROR, "[MANAGEMENT] Failed to allocate temp log buffer");
        buffer_write(wb, CALSETTING_VERSION);
        buffer_write(wb, RESPONSE_GENERAL_SERVER_FAILURE);
        buffer_write(wb, 0);
        buffer_write(wb, 0);
        return;
    }

	int actual_count = get_recent_logs(log_buffer, logs_to_fetch, offset);

	log(DEBUG, "[MANAGEMENT] Retrieved %d logs from offset %d", actual_count, offset);

	size_t total_size = LOGS_RESPONSE_HEADER_FIXED_LEN + (actual_count * LOG_ENTRY_WIRE_SIZE);
    
    // This should never fail since we calculated based on buffer size
    if (buffer_writeable_bytes(wb) < total_size) {
        log(ERROR, "[MANAGEMENT] CRITICAL: Buffer calculation error! Need %zu, have %zu", total_size, buffer_writeable_bytes(wb));
        free(log_buffer);
        buffer_write(wb, CALSETTING_VERSION);
        buffer_write(wb, RESPONSE_GENERAL_SERVER_FAILURE);
        buffer_write(wb, 0);
        buffer_write(wb, 0);
        return;
    }

	buffer_write(wb, CALSETTING_VERSION);
    buffer_write(wb, RESPONSE_SUCCESS_ADMIN);
    buffer_write(wb, actual_count);
    buffer_write(wb, 0);

	// Write each log entry (payload)
	 for (int i = 0; i < actual_count; i++) {
        log_entry_t *entry = &log_buffer[i];

        size_t available_bytes;
        uint8_t *write_ptr = buffer_write_ptr(wb, &available_bytes);

        if (available_bytes < LOG_ENTRY_WIRE_SIZE) {
            log(ERROR, "[MANAGEMENT] Buffer exhausted at entry %d/%d", i, actual_count);
            return;
        }

        size_t entry_offset = 0;

        // Date (21 bytes)
        memcpy(write_ptr + entry_offset, entry->date, 21);
        entry_offset += 21;

        // Username length (1 byte)
        write_ptr[entry_offset] = entry->ulen;
        entry_offset += 1;
        
        // Username (255 bytes)
        size_t username_len = entry->ulen;
        if (username_len > 0) {
            memcpy(write_ptr + entry_offset, entry->username, username_len);
        }
        if (username_len < 255) {
            memset(write_ptr + entry_offset + username_len, 0, 255 - username_len);
        }
        entry_offset += 255;

        // Register type (1 byte)
        write_ptr[entry_offset] = entry->register_type;
        entry_offset += 1;

        // Origin IP (46 bytes)
        size_t origin_ip_len = strlen(entry->origin_ip);
        if (origin_ip_len > 0) {
            size_t copy_len = (origin_ip_len > 46) ? 46 : origin_ip_len;
            memcpy(write_ptr + entry_offset, entry->origin_ip, copy_len);
            if (copy_len < 46) {
                memset(write_ptr + entry_offset + copy_len, 0, 46 - copy_len);
            }
        } else {
            memset(write_ptr + entry_offset, 0, 46);
        }
        entry_offset += 46;

        // Origin port (2 bytes, big-endian)
        write_ptr[entry_offset] = (entry->origin_port >> 8) & 0xFF;
        write_ptr[entry_offset + 1] = entry->origin_port & 0xFF;
        entry_offset += 2;

        // Destination ATYP (1 byte)
        write_ptr[entry_offset] = entry->destination_ATYP;
        entry_offset += 1;

        // Destination address (256 bytes)
        size_t dest_addr_len = strlen(entry->destination_address);
        if (dest_addr_len > 0) {
            size_t copy_len = (dest_addr_len > 256) ? 256 : dest_addr_len;
            memcpy(write_ptr + entry_offset, entry->destination_address, copy_len);
            if (copy_len < 256) {
                memset(write_ptr + entry_offset + copy_len, 0, 256 - copy_len);
            }
        } else {
            memset(write_ptr + entry_offset, 0, 256);
        }
        entry_offset += 256;

        // Destination port (2 bytes, big-endian)
        write_ptr[entry_offset] = (entry->destination_port >> 8) & 0xFF;
        write_ptr[entry_offset + 1] = entry->destination_port & 0xFF;
        entry_offset += 2;

        // Status code (1 byte)
        write_ptr[entry_offset] = entry->status_code;

        buffer_write_adv(wb, LOG_ENTRY_WIRE_SIZE);
    }

    log(DEBUG, "[MANAGEMENT] Successfully sent %d logs for offset %d", actual_count, offset);
}

static void process_userlist_command(management_session *session, uint8_t number, uint8_t offset) {
    buffer *wb = &session->write_buffer;
    buffer_reset(wb);

    uint8_t total_users = nusers;
    uint8_t users_to_send = 0;
    
    if (offset >= total_users) {
        // Invalid offset, send empty response
        if (buffer_writeable_bytes(wb) < GET_USERS_RESPONSE_HEADER_FIXED_LEN) {
            log(ERROR, "[MANAGEMENT] No space for user list response");
            set_error_state(session, RESPONSE_GENERAL_SERVER_FAILURE);
            return;
        }
        
        buffer_write(wb, CALSETTING_VERSION);
        buffer_write(wb, 1); // package_id
        buffer_write(wb, 0); // nusers = 0
        buffer_write(wb, 0); // reserved
        return;
    }
    
    uint8_t remaining_users = total_users - offset;
    users_to_send = (number > remaining_users) ? remaining_users : number;
    
    // Calculate required space for variable-length entries
    size_t required_space = GET_USERS_RESPONSE_HEADER_FIXED_LEN;
    for (uint8_t i = 0; i < users_to_send; i++) {
        uint8_t user_index = offset + i;
        if (user_index < nusers) {
            uint8_t username_len = strlen(us[user_index].name);
            if (username_len > 255) username_len = 255; // Limit to uint8_t max
            required_space += 1 + username_len + 1 + 1; // ulen + username + user_type + package_id
        }
    }
    
    if (buffer_writeable_bytes(wb) < required_space) {
        log(ERROR, "[MANAGEMENT] No space for user list response (need %zu bytes)", required_space);
        set_error_state(session, RESPONSE_GENERAL_SERVER_FAILURE);
        return;
    }

    buffer_write(wb, CALSETTING_VERSION);
    buffer_write(wb, 1); // package_id
    buffer_write(wb, users_to_send);
    buffer_write(wb, 0); // reserved

    for (uint8_t i = 0; i < users_to_send; i++) {
        uint8_t user_index = offset + i;
        if (user_index >= nusers) break;
        
        struct users *current_user = &us[user_index];
        uint8_t username_len = strlen(current_user->name);
        if (username_len > 255) username_len = 255;
        
        buffer_write(wb, username_len);
        for (int j = 0; j < username_len; j++) {
            buffer_write(wb, current_user->name[j]);
        }
		// is it faster to memcpy + adv?
        
		// TODO: admin users should be determined by their type, for now just check if "admin" is in name
        // Determine user type
        uint8_t user_type = USER_TYPE_CLIENT;
        if (strstr(current_user->name, "admin") != NULL) {
            user_type = USER_TYPE_ADMIN;
        }
        
        buffer_write(wb, user_type);
        buffer_write(wb, 1); // package_id
    }

    log(DEBUG, "[MANAGEMENT] Prepared user list response for %s (req: %d, offset: %d, sent: %d)", 
        session->username, number, offset, users_to_send);
}

// TODO: check if it's actually working properly and what happens in the midst of connection
static void process_change_buffer_command(management_session *session, uint8_t new_size) {
	buffer *wb = &session->write_buffer;
	buffer_reset(wb);

	if (buffer_writeable_bytes(wb) < CHANGE_SERVER_SETTINGS_RESPONSE_HEADER_FIXED_LEN) {
		log(ERROR, "[MANAGEMENT] No space for change buffer response");
		set_error_state(session, RESPONSE_GENERAL_SERVER_FAILURE);
		return;
	}

	uint8_t response_code = RESPONSE_GENERAL_SERVER_FAILURE;

	// validate user permissions? tbh i feel like its unnecessary at this point
	if (session->user_type != USER_TYPE_ADMIN) {
		log(DEBUG, "[MANAGEMENT] Non-admin user %s attempted to change buffer size",
			session->username ? session->username : "unknown");
		response_code = RESPONSE_NOT_ALLOWED;
	}

	if (new_size < MIN_BUFF_SIZE_KB || new_size > MAX_BUFF_SIZE_KB) {
		log(ERROR, "[MANAGEMENT] Invalid buffer size: %d KB (valid range: %d-%d KB)", new_size, MIN_BUFF_SIZE_KB,
			MAX_BUFF_SIZE_KB);
		response_code = RESPONSE_BAD_REQUEST;
	} else {
		size_t old_buffer_size = g_socks5_buffer_size;
		g_socks5_buffer_size = new_size * 1024; // convert KB to bytes
		response_code = RESPONSE_SUCCESS_ADMIN;

		log(INFO, "[MANAGEMENT] Buffer size changed from %zu to %zu bytes (%d KB) by %s", old_buffer_size,
			g_socks5_buffer_size, new_size, session->username ? session->username : "unknown");

		// TODO: not sure whether to keep this or not in order to notify impact on active connections
		// if (get_active_connection_count() > 0) {
		//     log(DEBUG, "[MANAGEMENT] Buffer size changed while connections active. "
		//               "New size will affect future connections only.");
		// }
	}

	buffer_write(wb, CALSETTING_VERSION);
	buffer_write(wb, response_code);
	buffer_write(wb, COMMAND_CHANGE_BUFFER_SIZE);

	log(DEBUG, "[MANAGEMENT] Prepared change buffer response for %s", session->username);
}

static void process_change_timeout_command(management_session *session, uint8_t new_timeout) {
	buffer *wb = &session->write_buffer;
	buffer_reset(wb);

	if (buffer_writeable_bytes(wb) < CHANGE_SERVER_SETTINGS_RESPONSE_HEADER_FIXED_LEN) {
		log(ERROR, "[MANAGEMENT] No space for change timeout response");
		set_error_state(session, RESPONSE_GENERAL_SERVER_FAILURE);
		return;
	}

	uint8_t response_code = RESPONSE_GENERAL_SERVER_FAILURE;

	if (new_timeout >= MIN_TIMEOUT_SECONDS && new_timeout <= MAX_TIMEOUT_SECONDS) {
		g_connection_timeout = new_timeout;
		response_code = RESPONSE_SUCCESS_ADMIN;
		log(INFO, "[MANAGEMENT] Timeout changed to %d seconds by %s", new_timeout, session->username);
	} else {
		log(ERROR, "[MANAGEMENT] Invalid timeout: %d seconds", new_timeout);
	}

	buffer_write(wb, CALSETTING_VERSION);
	buffer_write(wb, response_code);
	buffer_write(wb, COMMAND_CHANGE_TIMEOUT);

	log(DEBUG, "[MANAGEMENT] Prepared change timeout response for %s", session->username);
}

/**************** Helper functions *****************/

static bool write_to_client(struct selector_key *key, bool should_close) {
	management_session *session = (management_session *) key->data;
	buffer *wb = &session->write_buffer;

	size_t bytes_to_write;
	uint8_t *ptr = buffer_read_ptr(wb, &bytes_to_write);

	if (bytes_to_write == 0) {
		return true;
	}

	ssize_t bytes_written = send(key->fd, ptr, bytes_to_write, MSG_NOSIGNAL);
	if (bytes_written < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return false;
		}
		if (errno == EPIPE) {
			log(INFO, "[MANAGEMENT] Client closed connection (EPIPE)");
			// selector_unregister_fd(key->s, key->fd);
			close(key->fd);
			return true;
		}
		log(ERROR, "[MANAGEMENT] send() error: %s", strerror(errno));
		set_error_state(session, RESPONSE_GENERAL_SERVER_FAILURE);
		return true;
	} else if (bytes_written == 0) {
		log(INFO, "[MANAGEMENT] Connection closed during send");
		return true;
	}

	buffer_read_adv(wb, bytes_written);
	log(DEBUG, "[MANAGEMENT] Sent %zd/%zu bytes", bytes_written, bytes_to_write);

	if (buffer_readable_bytes(wb) > 0) {
		return false;
	}

	if (should_close) {
		// selector_unregister_fd(key->s, key->fd);
		close(key->fd);
	}

	return true; // All data sent
}

static void set_error_state(management_session *session, uint8_t error_code) {
	session->has_error = true;
	session->error_code = error_code;
	session->error_response_sent = false;
	session->current_state = MNG_STATE_ERROR;
	log(DEBUG, "[MANAGEMENT] Error state set: code=0x%02x", error_code);
}

static void handle_error(struct selector_key *key) {
	// management_session *session = (management_session *) key->data;

	log(DEBUG, "[MANAGEMENT] Handling error state");

	// for management protocol, we usually just close the connection on error
	selector_unregister_fd(key->s, key->fd);
	close(key->fd);
}

static void cleanup_session(management_session *session) {
	if (!session || session->cleaned_up) {
		return;
	}

	if (session->raw_read_buffer) {
		free(session->raw_read_buffer);
		session->raw_read_buffer = NULL;
	}

	if (session->raw_write_buffer) {
		free(session->raw_write_buffer);
		session->raw_write_buffer = NULL;
	}

	if (reusable_log_buffer) {
        free(reusable_log_buffer);
        reusable_log_buffer = NULL;
        reusable_buffer_capacity = 0;
    }

	session->cleaned_up = true;
	log(DEBUG, "[MANAGEMENT] Session cleanup complete");
}

// TODO: MUST CHANGE LATER!! for now uses the same validation function as SOCKSs
static uint8_t authenticate_user(const char *username, const char *password) {
	if (us != NULL && nusers > 0) {
		for (int i = 0; i < nusers; i++) {
			if (strcmp(username, us[i].name) == 0 && strcmp(password, us[i].pass) == 0) {
				// Determine user type based on username
				if (strstr(username, "admin") != NULL) {
					return USER_TYPE_ADMIN;
				} else {
					return USER_TYPE_CLIENT;
				}
			}
		}
	}

	// fallback hardcoded users (for now matching socks5)
	if (strcmp(username, "nep") == 0 && strcmp(password, "nep") == 0) {
		return USER_TYPE_ADMIN;
	} else if (strcmp(username, "admin") == 0 && strcmp(password, "admin") == 0) {
		return USER_TYPE_ADMIN;
	} else if (strcmp(username, "user") == 0 && strcmp(password, "user") == 0) {
		return USER_TYPE_CLIENT;
	}

	return RESPONSE_AUTH_FAILURE;
}

static log_entry_t* get_reusable_log_buffer(size_t required_count) {
    if (required_count > reusable_buffer_capacity) {
        log_entry_t *new_buffer = realloc(reusable_log_buffer, required_count * sizeof(log_entry_t));
        if (!new_buffer) {
            log(ERROR, "[MANAGEMENT] Failed to resize reusable buffer to %zu entries", required_count);
            return NULL;
        }
        
        reusable_log_buffer = new_buffer;
        reusable_buffer_capacity = required_count;
        log(DEBUG, "[MANAGEMENT] Resized reusable buffer to %zu entries", required_count);
    }
    
    return reusable_log_buffer;
}