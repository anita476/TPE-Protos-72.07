#ifndef LIB_CLIENT_H
#define LIB_CLIENT_H

#include <netinet/in.h>
#include <stdint.h>
#include "../../shared/include/calsetting_protocol.h"

static uint8_t get_user_type();

// typedef struct metrics {
// 	uint8_t version;
// 	uint8_t server_state;
// 	uint32_t n_current_connections;
// 	uint32_t n_total_connections;
// 	uint32_t n_total_bytes_received;
// 	uint32_t n_total_bytes_sent;
// 	uint16_t n_timeouts;
// 	uint16_t n_server_errors;
// 	uint16_t n_bad_requests;
// 	uint8_t error_code;  //in case we need it
// } metrics;

// Connection functions
int setup_tcp_client_Socket(char *address, char *port);

// Authentication functions
int hello_send(char *username, char *password, int sock);
int hello_read(int sock);

// Server interaction functions
metrics_t *handle_metrics(int sock, metrics_t *m);
log_strct *handle_log(int sock, uint8_t n, uint8_t offset);
user_list_entry *handle_get_users(uint8_t n, uint8_t offset, int sock);

// Server configuration functions
uint8_t handle_change_buffer_size(int sock, uint8_t new_size);
uint8_t handle_change_timeout(int sock, uint8_t new_timeout);

// Memory management functions
void free_log_list(log_strct *head);
void free_user_list(user_list_entry *head);

#endif //LIB_CLIENT_H
