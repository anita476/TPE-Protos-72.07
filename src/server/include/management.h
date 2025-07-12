#ifndef _MANAGEMENT_H_
#define _MANAGEMENT_H_
#include "../../shared/include/calsetting_protocol.h"
#include "../../shared/include/commands.h"
#include "buffer.h"
#include "constants.h"
#include "metrics.h"
#include "selector.h"

// #define BUFFER_SIZE_MAX 1024 * 64
// #define BUFFER_SIZE_MIN 1024
// #define TIMEOUT_SEC_MAX 60
// #define TIMEOUT_SEC_MIN 1

// Management connection states (similar to SOCKS5 states)
typedef enum {
	MNG_STATE_HELLO_READ,	 // Reading authentication request
	MNG_STATE_HELLO_WRITE,	 // Sending authentication response
	MNG_STATE_COMMAND_READ,	 // Reading command requests
	MNG_STATE_COMMAND_WRITE, // Sending command responses
	MNG_STATE_ERROR,		 // Error state
	MNG_STATE_DONE			 // Connection finished
} management_state;

// Management session structure (similar to client_session)
typedef struct {
	SessionType type; // type management
	management_state current_state;
	int client_fd;

	// Authentication info
	char username[256];
	uint8_t user_type; // USER_TYPE_CLIENT or USER_TYPE_ADMIN
	bool authenticated;

	size_t buffer_size;
	buffer read_buffer;
	buffer write_buffer;
	uint8_t *raw_read_buffer;
	uint8_t *raw_write_buffer;

	// Error handling
	bool has_error;
	uint8_t error_code;
	bool error_response_sent;
	bool cleaned_up;

} management_session;

// Function declarations (following SOCKS5 pattern)
void management_handle_new_connection(struct selector_key *key);

#endif
