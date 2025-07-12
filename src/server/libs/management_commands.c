// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
#include "../include/management_commands.h"
#include "../../shared/include/calsetting_protocol.h"
#include "../include/args.h"
#include "../include/config.h"
#include "../include/logger.h"
#include "../include/metrics.h"
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <time.h>

// TODO: when should the server close the client vs. when should it just send an error to the client?

#define CLAMP_UINT16(value) ((value) > UINT16_MAX ? UINT16_MAX : (uint16_t) (value))

extern size_t g_socks5_buffer_size;
extern int g_connection_timeout;
extern size_t g_management_buffer_size;
extern struct user *users;
extern uint8_t nusers;

// Static variables for this module
static log_entry_t *reusable_log_buffer = NULL;
static size_t reusable_buffer_capacity = 0;

/*********** HELPER FUNCTIONS **************/
// Standard 4-byte response header: VER | STATUS | CMD | ARG
static void write_response_header(buffer *wb, uint8_t status, uint8_t command, uint8_t arg);
static void write_simple_response_header(buffer *wb, uint8_t status, uint8_t command);

// TODO: check error state bc idk if its even necessary

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
void process_metrics_command(management_session *session) {
	server_metrics *real_metrics = metrics_get();
	if (!real_metrics) {
		log(ERROR, "[MANAGEMENT] Failed to get server metrics");
		set_error_state(session, RESPONSE_GENERAL_SERVER_FAILURE);
		return;
	}

	buffer *wb = &session->write_buffer;
	buffer_reset(wb);

	if (buffer_writeable_bytes(wb) < METRICS_RESPONSE_SIZE) {
		log(ERROR, "[MANAGEMENT] Insufficient buffer space for metrics response");
		set_error_state(session, RESPONSE_GENERAL_SERVER_FAILURE);
		return;
	}

	// Build response in temporary buffer with proper byte order
	uint8_t response[METRICS_RESPONSE_SIZE];
	uint8_t *ptr = response;

	uint32_t uptime = (uint32_t) (time(NULL) - real_metrics->start_time);

	// Pack data efficiently
	*ptr++ = CALSETTING_VERSION;
	*ptr++ = 1; // TODO: get server state properly, currently hardcoded to 1

	uint32_t concurrent = htonl(real_metrics->concurrent_connections);
	memcpy(ptr, &concurrent, 4);
	ptr += 4;

	uint64_t total_conn = htobe64(real_metrics->total_connections);
	memcpy(ptr, &total_conn, 8);
	ptr += 8;

	uint32_t max_concurrent = htonl(real_metrics->max_concurrent_connections);
	memcpy(ptr, &max_concurrent, 4);
	ptr += 4;

	uint64_t bytes_in = htobe64(real_metrics->bytes_transferred_in);
	memcpy(ptr, &bytes_in, 8);
	ptr += 8;

	uint64_t bytes_out = htobe64(real_metrics->bytes_transferred_out);
	memcpy(ptr, &bytes_out, 8);
	ptr += 8;

	uint64_t total_bytes = htobe64(real_metrics->total_bytes_transferred);
	memcpy(ptr, &total_bytes, 8);
	ptr += 8;

	uint32_t total_errors = htonl(real_metrics->total_errors);
	memcpy(ptr, &total_errors, 4);
	ptr += 4;

	uint32_t uptime_net = htonl(uptime);
	memcpy(ptr, &uptime_net, 4);
	ptr += 4;

	// Error counts
	uint32_t network_errors = htonl(real_metrics->error_counts[ERROR_TYPE_NETWORK]);
	memcpy(ptr, &network_errors, 4);
	ptr += 4;

	uint32_t protocol_errors = htonl(real_metrics->error_counts[ERROR_TYPE_PROTOCOL]);
	memcpy(ptr, &protocol_errors, 4);
	ptr += 4;

	uint32_t auth_errors = htonl(real_metrics->error_counts[ERROR_TYPE_AUTH]);
	memcpy(ptr, &auth_errors, 4);
	ptr += 4;

	uint32_t system_errors = htonl(real_metrics->error_counts[ERROR_TYPE_SYSTEM]);
	memcpy(ptr, &system_errors, 4);
	ptr += 4;

	uint32_t timeout_errors = htonl(real_metrics->error_counts[ERROR_TYPE_TIMEOUT]);
	memcpy(ptr, &timeout_errors, 4);
	ptr += 4;

	uint32_t memory_errors = htonl(real_metrics->error_counts[ERROR_TYPE_MEMORY]);
	memcpy(ptr, &memory_errors, 4);
	ptr += 4;

	uint32_t other_errors = htonl(real_metrics->error_counts[ERROR_TYPE_OTHER]);
	memcpy(ptr, &other_errors, 4);
	ptr += 4;

	// Single write to buffer
	size_t writable;
	uint8_t *write_ptr = buffer_write_ptr(wb, &writable);

	if (writable >= METRICS_RESPONSE_SIZE) {
		memcpy(write_ptr, response, METRICS_RESPONSE_SIZE);
		buffer_write_adv(wb, METRICS_RESPONSE_SIZE);
	} else {
		// Fallback to individual writes
		for (int i = 0; i < METRICS_RESPONSE_SIZE; i++) {
			buffer_write(wb, response[i]);
		}
	}

	log(DEBUG, "[MANAGEMENT] Bulk metrics response written successfully (%d bytes)", METRICS_RESPONSE_SIZE);
}

/*
VER | STATUS | CMD | COUNT |  LOG_ENTRY_1 | LOG_ENTRY_2 | ... | LOG_ENTRY_N
 1  |  1  |  1   |   1   |  (586 bytes each)
Total size: 4 + (586 * COUNT) bytes
*/
void process_logs_command(management_session *session, uint8_t number, uint8_t offset) {
	buffer *wb = &session->write_buffer;
	buffer_reset(wb);
	size_t available = g_management_buffer_size - RESPONSE_HEADER_LEN;
	int max_logs_per_response = (int) available / LOG_ENTRY_WIRE_SIZE;

	log(DEBUG, "[MANAGEMENT] Buffer can handle max %d logs per response", max_logs_per_response);

	if (max_logs_per_response <= 0) {
		log(ERROR, "[MANAGEMENT] Buffer too small for even one log entry");
		write_simple_response_header(wb, RESPONSE_GENERAL_SERVER_FAILURE, COMMAND_LOGS);
		return;
	}

	// Cap the request to what fits in buffer
	int logs_to_fetch = (number > max_logs_per_response) ? max_logs_per_response : number;
	if (logs_to_fetch != number) {
		log(DEBUG, "[MANAGEMENT] Capping request from %d to %d logs (buffer limit)", number, logs_to_fetch);
	}

	log_entry_t *log_buffer = get_reusable_log_buffer(logs_to_fetch);
	if (!log_buffer) {
		log(ERROR, "[MANAGEMENT] Failed to allocate temp log buffer");
		write_simple_response_header(wb, RESPONSE_GENERAL_SERVER_FAILURE, COMMAND_LOGS);
		return;
	}

	int actual_count = get_recent_logs(log_buffer, logs_to_fetch, offset);

	log(DEBUG, "[MANAGEMENT] Retrieved %d logs from offset %d", actual_count, offset);
	size_t total_size = RESPONSE_HEADER_LEN + (actual_count * LOG_ENTRY_WIRE_SIZE);

	if (buffer_writeable_bytes(wb) < total_size) {
		return;
	}

	write_response_header(wb, RESPONSE_SUCCESS, COMMAND_LOGS, actual_count);

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

/*
Response format:
VER | STATUS | CMD | NUSERS | USER_1_LEN | USER_1_TYPE | USER_1_NAME | ... | USER_N_LEN | USER_N_TYPE | USER_N_NAME |
 1  |   1    |  1  |   1    |     1       |      1      |    255      | ... |     1      |      1      |    255      |

Fixed size per user: 1 + 1 + 255 = 257 bytes
Total response size: 4 (header) + (NUSERS * 257) bytes
*/
void process_userlist_command(management_session *session, uint8_t number, uint8_t offset) {
	buffer *wb = &session->write_buffer;
	buffer_reset(wb);

	uint8_t total_users = nusers;
	uint8_t users_to_send = 0;

	if (offset >= total_users) {
		// Invalid offset, send empty response
		if (buffer_writeable_bytes(wb) < RESPONSE_HEADER_LEN) {
			return;
		}

		write_response_header(wb, RESPONSE_BAD_REQUEST, COMMAND_USER_LIST, 0);
		return;
	}

	uint8_t remaining_users = total_users - offset;
	users_to_send = (number > remaining_users) ? remaining_users : number;
	const size_t bytes_per_user = 1 + 1 + USERNAME_MAX_SIZE;

	// TODO: if users_to_send == 0 -> send answer right away?

	// Calculate required space for variable-length entries
	size_t required_space =
		RESPONSE_HEADER_LEN +
		users_to_send * (1 + 1 + 255); // 1 byte for username length, 1 byte for user type, 255 bytes for username

	if (required_space > g_management_buffer_size) {
		// Calculate max users that fit in buffer
		size_t max_users_in_buffer = (g_management_buffer_size - RESPONSE_HEADER_LEN / (255 + 1 + 1));
		if (users_to_send > max_users_in_buffer) {
			users_to_send = (uint8_t) max_users_in_buffer;
			log(DEBUG, "[MANAGEMENT] Capping users from %d to %d (buffer limit)", number, users_to_send);
		}
		required_space = RESPONSE_HEADER_LEN + (users_to_send * bytes_per_user);
	}

	if (buffer_writeable_bytes(wb) < required_space) {
		log(ERROR, "[MANAGEMENT] No space for user list response (need %zu bytes)", required_space);
		return;
	}

	write_response_header(wb, RESPONSE_SUCCESS, COMMAND_USER_LIST, users_to_send);

	for (uint8_t i = 0; i < users_to_send; i++) {
		uint8_t user_index = offset + i;
		if (user_index >= nusers)
			break;

		struct user *current_user = &users[user_index];
		// Skip invalid users (same logic as first pass)
		if (!current_user->name || strlen(current_user->name) == 0) {
			continue;
		}
		uint8_t username_len = strlen(current_user->name); // will truncate to 255 if longer than that

		buffer_write(wb, username_len);
		buffer_write(wb, current_user->type);

		size_t available;
		uint8_t *write_ptr = buffer_write_ptr(wb, &available);

		if (available < USERNAME_MAX_SIZE) {
			log(ERROR, "[MANAGEMENT] Buffer space lost during user entry write");
			break;
		}

		if (username_len > 0) {
			memcpy(write_ptr, current_user->name, username_len);
		}

		// Pad remaining bytes with zeros
		if (username_len < USERNAME_MAX_SIZE) {
			memset(write_ptr + username_len, 0, USERNAME_MAX_SIZE - username_len);
		}

		buffer_write_adv(wb, USERNAME_MAX_SIZE);
	}

	log(DEBUG, "[MANAGEMENT] Prepared user list response for %s (req: %d, offset: %d, sent: %d)", session->username,
		number, offset, users_to_send);
}

/*
Response format:
VER | STATUS | CMD | RSV
*/
void process_change_buffer_command(management_session *session, uint8_t new_size) {
	buffer *wb = &session->write_buffer;
	buffer_reset(wb);

	uint8_t response_code = RESPONSE_GENERAL_SERVER_FAILURE;

	if (new_size < MIN_BUFF_SIZE_KB || new_size > MAX_BUFF_SIZE_KB) {
		// This shouldnt even happen because client side alr verifies this
		log(ERROR, "[MANAGEMENT] Invalid buffer size: %d KB", new_size);
		response_code = RESPONSE_BAD_REQUEST;
	} else {
		size_t old_buffer_size = g_socks5_buffer_size;
		g_socks5_buffer_size = new_size * 1024;
		response_code = RESPONSE_SUCCESS;
		log(INFO, "[MANAGEMENT] Buffer size changed from %zu to %zu bytes by %s", old_buffer_size, g_socks5_buffer_size,
			session->username);
	}
	write_simple_response_header(wb, response_code, COMMAND_CHANGE_BUFFER_SIZE);
}

/*
Response format:
VER | STATUS | CMD | RSV
*/
void process_change_timeout_command(management_session *session, uint8_t new_timeout) {
	buffer *wb = &session->write_buffer;
	buffer_reset(wb);

	uint8_t response_code = RESPONSE_GENERAL_SERVER_FAILURE;

	if (new_timeout < MIN_TIMEOUT_SECONDS || new_timeout > MAX_TIMEOUT_SECONDS) {
		// This shouldnt even happen because client side alr verifies this
		log(ERROR, "[MANAGEMENT] Invalid timeout: %d seconds", new_timeout);
		response_code = RESPONSE_BAD_REQUEST;
	} else {
		g_connection_timeout = new_timeout; // Update global timeout
		response_code = RESPONSE_SUCCESS;
		log(INFO, "[MANAGEMENT] Timeout changed to %d seconds", new_timeout);
	}
	write_simple_response_header(wb, response_code, COMMAND_CHANGE_TIMEOUT);
}

/*
VER | STATUS | CMD | RSV
*/
void process_add_user_command(management_session *session, uint8_t arg1, uint8_t arg2, uint8_t type) {
	buffer *wb = &session->write_buffer;
	buffer_reset(wb);

	// arg1 = username_len, arg2 = password_len (from the command header)
	uint8_t username_len = arg1;
	uint8_t password_len = arg2;

	if (username_len == 0 || password_len == 0) {
		write_simple_response_header(wb, RESPONSE_INVALID_CREDENTIALS, COMMAND_ADD_CLIENT);
		return;
	}

	buffer *rb = &session->read_buffer;
	size_t available;
	(void) buffer_read_ptr(rb, &available);

	if (available < (size_t) (username_len + password_len)) {
		return; // wait...
	}

	char username[USERNAME_MAX_SIZE + 1];
	char password[PASSWORD_MAX_SIZE + 1];

	for (int i = 0; i < username_len; i++) {
		username[i] = buffer_read(rb);
	}
	username[username_len] = '\0';

	for (int i = 0; i < password_len; i++) {
		password[i] = buffer_read(rb);
	}
	password[password_len] = '\0';

	uint8_t result = add_user_to_system(username, password, type);

	write_simple_response_header(wb, result, COMMAND_ADD_CLIENT);

	if (result == RESPONSE_SUCCESS) {
		log(INFO, "[MANAGEMENT] Admin %s added new user: %s", session->username, username);
	}
}

/*
Response format:
VER | STATUS | CMD | RSV
*/
void process_remove_user_command(management_session *session, uint8_t arg1) {
	buffer *wb = &session->write_buffer;
	buffer_reset(wb);

	uint8_t username_len = arg1;

	if (username_len == 0) {
		buffer_write(wb, CALSETTING_VERSION);
		buffer_write(wb, RESPONSE_INVALID_CREDENTIALS);
		buffer_write(wb, COMMAND_REMOVE_USER);
		return;
	}

	buffer *rb = &session->read_buffer;
	size_t available;
	(void) buffer_read_ptr(rb, &available);

	if (available < username_len) {
		return; // wait..
	}

	char username[USERNAME_MAX_SIZE + 1];

	for (int i = 0; i < username_len; i++) {
		username[i] = buffer_read(rb);
	}
	username[username_len] = '\0';

	// Prevent self-removal
	if (strcmp(username, session->username) == 0) {
		write_simple_response_header(wb, RESPONSE_BAD_REQUEST, COMMAND_REMOVE_USER);
		log(INFO, "[MANAGEMENT] Admin %s attempted to remove themselves", session->username);
		return;
	}

	uint8_t result = remove_user_from_system(username);

	write_simple_response_header(wb, result, COMMAND_REMOVE_USER);

	if (result == RESPONSE_SUCCESS) {
		log(INFO, "[MANAGEMENT] Admin %s removed user: %s", session->username, username);
	}
}

/*
VER | STATUS | CMD | RSV | BUFFER_SIZE_KB | TIMEOUT_SECONDS | ... (for future use)
 1  |   1    |  1  |  1  |     1          |       1         | ...
*/
void process_get_current_config_command(management_session *session) {
	log(DEBUG, "[MANAGEMENT] Processing get current config command");

	buffer *wb = &session->write_buffer;
	buffer_reset(wb);

	if (buffer_writeable_bytes(wb) < RESPONSE_HEADER_LEN + 2) {
		log(ERROR, "[MANAGEMENT] No space for config response");
		set_error_state(session, RESPONSE_GENERAL_SERVER_FAILURE);
		return;
	}

	uint8_t buffer_size_kb = (uint8_t) (g_socks5_buffer_size / 1024);
	if (buffer_size_kb == 0 && g_socks5_buffer_size > 0) {
		buffer_size_kb = 1;
	}

	uint8_t timeout_seconds = (uint8_t) g_select_timeout.tv_sec;

	write_simple_response_header(wb, RESPONSE_SUCCESS, COMMAND_GET_CURRENT_CONFIG);
	buffer_write(wb, buffer_size_kb);
	buffer_write(wb, timeout_seconds);

	log(INFO, "[MANAGEMENT] Config sent to admin %s: buffer_size=%uKB, timeout=%us", session->username, buffer_size_kb,
		timeout_seconds);
}

/********************** HELPER FUNCTIONS *****************************/

uint8_t authenticate_user(const char *username, const char *password) {
	if (users != NULL && nusers > 0) {
		for (int i = 0; i < nusers; i++) {
			if (strcmp(username, users[i].name) == 0 && strcmp(password, users[i].pass) == 0) {
				if (users[i].type == USER_TYPE_ADMIN) {
					return USER_TYPE_ADMIN;
				} else if (users[i].type == USER_TYPE_CLIENT) {
					return USER_TYPE_CLIENT;
				} else {
					log(ERROR, "[MANAGEMENT] Unknown user type for user %s", username);
					return RESPONSE_AUTH_FAILURE; // unknown user type
				}
			}
		}
	}
	return RESPONSE_AUTH_FAILURE;
}

log_entry_t *get_reusable_log_buffer(size_t required_count) {
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

// confio que el cliente me mande bien los datos asi que muchos chequeos no hago
uint8_t add_user_to_system(const char *username, const char *password, uint8_t user_type) {
	if (!username || !password) {
		log(ERROR, "[MANAGEMENT] NULL username or password provided");
		return RESPONSE_BAD_REQUEST;
	}

	if (strlen(username) == 0 || strlen(password) == 0) {
		log(ERROR, "[MANAGEMENT] Empty username or password provided");
		return RESPONSE_BAD_REQUEST;
	}

	// Check if user already exists (maybe should be by id)
	for (int i = 0; i < nusers; i++) {
		if (users[i].name && strcmp(username, users[i].name) == 0) {
			return RESPONSE_USER_ALREADY_EXISTS;
		}
	}

	if (nusers >= MAX_USERS) {
		return RESPONSE_MAX_USERS_REACHED;
	}

	users[nusers].name = malloc(strlen(username) + 1);
	if (!users[nusers].name) {
		return RESPONSE_GENERAL_SERVER_FAILURE;
	}
	strcpy(users[nusers].name, username);

	users[nusers].pass = malloc(strlen(password) + 1);
	if (!users[nusers].pass) {
		free(users[nusers].name);
		users[nusers].name = NULL;
		return RESPONSE_GENERAL_SERVER_FAILURE;
	}
	strcpy(users[nusers].pass, password);

	users[nusers].type = user_type;

	nusers++;

	log(INFO, "[MANAGEMENT] Added new user: %s (type: %d)", username, user_type);
	return RESPONSE_SUCCESS;
}

// not a very efficient way to do this, but for now it works
uint8_t remove_user_from_system(const char *username) {
	int user_index = -1;
	for (int i = 0; i < nusers; i++) {
		if (users[i].name && strcmp(username, users[i].name) == 0) {
			user_index = i;
			break;
		}
	}

	if (user_index == -1) {
		return RESPONSE_USER_NOT_FOUND;
	}

	// Shift remaining users down
	for (int i = user_index; i < nusers - 1; i++) {
		users[i].name = users[i + 1].name;
		users[i].pass = users[i + 1].pass;
	}

	// Clear the last entry
	users[nusers - 1].name = NULL;
	users[nusers - 1].pass = NULL;

	nusers--;

	log(INFO, "[MANAGEMENT] Removed user: %s", username);
	return RESPONSE_SUCCESS;
}

void cleanup_session(management_session *session) {
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

bool write_to_client(struct selector_key *key, bool should_close) {
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

void set_error_state(management_session *session, uint8_t error_code) {
	session->has_error = true;
	session->error_code = error_code;
	session->error_response_sent = false;
	session->current_state = MNG_STATE_ERROR;
	log(DEBUG, "[MANAGEMENT] Error state set: code=0x%02x", error_code);
}

static void write_response_header(buffer *wb, uint8_t status, uint8_t command, uint8_t arg) {
	if (buffer_writeable_bytes(wb) < 4) {
		return;
	}

	buffer_write(wb, CALSETTING_VERSION); // VER
	buffer_write(wb, status);			  // STATUS
	buffer_write(wb, command);			  // CMD
	buffer_write(wb, arg);				  // ARG/COUNT/RESERVED
}

static void write_simple_response_header(buffer *wb, uint8_t status, uint8_t command) {
	return write_response_header(wb, status, command, 0);
}