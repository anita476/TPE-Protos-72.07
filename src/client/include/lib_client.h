#ifndef LIB_CLIENT_H
#define LIB_CLIENT_H

#include "../../shared/include/calsetting_protocol.h"
#include <netinet/in.h>
#include <stdint.h>

static uint8_t get_user_type();

typedef struct client_log_entry {
	char date[DATE_SIZE];
	uint8_t ulen;
	char username[USERNAME_MAX_SIZE];
	char register_type;
	char origin_ip[INET6_ADDRSTRLEN];
	uint16_t origin_port;
	uint8_t destination_ATYP;
	char destination_address[DOMAIN_MAX_SIZE + 1];
	uint16_t destination_port;
	uint8_t status_code;
	struct client_log_entry *next; // Only client needs this
} client_log_entry_t;

typedef struct server_current_config {
	uint8_t buffer_size_kb;	 // Buffer size in KB
	uint8_t timeout_seconds; // Timeout in seconds
} server_current_config;

// Connection functions
int setup_tcp_client_Socket(char *address, char *port);

// Authentication functions
int hello_send(char *username, char *password, int sock);
int hello_read(int sock);

// Server interaction functions
metrics_t *handle_metrics(int sock, metrics_t *m);
client_log_entry_t *handle_log(int sock, uint8_t n, uint8_t offset);
user_list_entry *handle_get_users(uint8_t n, uint8_t offset, int sock);
server_current_config *handle_get_current_config(int sock, server_current_config *config);

// Server configuration functions
uint8_t handle_change_buffer_size(int sock, uint8_t new_size);
uint8_t handle_change_timeout(int sock, uint8_t new_timeout);
uint8_t handle_add_client(int sock, char *username, char *password);
uint8_t handle_add_admin(int sock, char *ussername, char *password);
uint8_t handle_remove_user(int sock, char *username);

// Memory management functions
void free_log_list(client_log_entry_t *head);
void free_user_list(user_list_entry *head);

#endif // LIB_CLIENT_H
