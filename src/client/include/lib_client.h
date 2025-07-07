#ifndef LIB_CLIENT_H
#define LIB_CLIENT_H

#include <netinet/in.h>
#include <stdint.h>
#include "../../shared/include/calsetting_protocol.h"

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
    struct client_log_entry *next;  // Only client needs this
} client_log_entry_t;

// Connection functions
int setup_tcp_client_Socket(char *address, char *port);

// Authentication functions
int hello_send(char *username, char *password, int sock);
int hello_read(int sock);

// Server interaction functions
metrics_t *handle_metrics(int sock, metrics_t *m);
client_log_entry_t * handle_log(int sock, uint8_t n, uint8_t offset);
user_list_entry *handle_get_users(uint8_t n, uint8_t offset, int sock);

// Server configuration functions
uint8_t handle_change_buffer_size(int sock, uint8_t new_size);
uint8_t handle_change_timeout(int sock, uint8_t new_timeout);

// Memory management functions
void free_log_list(client_log_entry_t *head);
void free_user_list(user_list_entry *head);

#endif //LIB_CLIENT_H
