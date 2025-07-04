//
// Created by nep on 7/4/25.
//

#ifndef LIB_CLIENT_H
#define LIB_CLIENT_H

#include <stdint.h>

#define METRICS_PROTOCOL_VERSION 1
#define RESPONSE_SUCCESS 0
#define RESPONSE_AUTH_FAILURE 0x01
#define RESPONSE_GENERAL_SERVER_FAILURE 0x02
#define RESPONSE_WRONG_VERSION 0x03
#define RESPONSE_NOT_ALLOWED 0x04
#define RESPONSE_BAD_REQUEST 0x05

#define COMMAND_LOGS 0x00
#define COMMAND_USER_LIST 0x01
#define COMMAND_METRICS 0x02
#define COMMAND_CHANGE_BUFFER_SIZE 0x03
#define COMMAND_CHANGE_TIMEOUT 0x04

#define REQUEST_SIZE 4

typedef struct metrics {
	uint8_t version;
	uint8_t server_state;
	uint32_t n_current_connections;
	uint32_t n_total_connections;
	uint32_t n_total_bytes_received;
	uint32_t n_total_bytes_sent;
	uint16_t n_timeouts;
	uint16_t n_server_errors;
	uint16_t n_bad_requests;
}metrics;

#endif //LIB_CLIENT_H
