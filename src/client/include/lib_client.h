#ifndef LIB_CLIENT_H
#define LIB_CLIENT_H

#include <netinet/in.h>
#include <stdint.h>
#include "../../shared/include/calsetting_protocol.h"

#define METRICS_PROTOCOL_VERSION 1
#define RESPONSE_SUCCESS_CLIENT 0x00
#define RESPONSE_SUCCESS_ADMIN 0x01
#define RESPONSE_AUTH_FAILURE 0x02
#define RESPONSE_GENERAL_SERVER_FAILURE 0x03
#define RESPONSE_WRONG_VERSION 0x04
#define RESPONSE_NOT_ALLOWED 0x05
#define RESPONSE_USER_NOT_FOUND 0x06

#define RESPONSE_BAD_REQUEST 0x06 //not for server but used by lib to let the frontend know

#define HELLO_CLIENT_RESPONSE_CODE 0x00
#define HELLO_ADMIN_RESPONSE_CODE 0x01
#define HELLO_ERROR_RESPONSE_CODE 0x02

#define COMMAND_LOGS 0x00
#define COMMAND_USER_LIST 0x01
#define COMMAND_METRICS 0x02
#define COMMAND_CHANGE_BUFFER_SIZE 0x03
#define COMMAND_CHANGE_TIMEOUT 0x04
#define COMMAND_GET_CURRENT_CONFIG 0x05
#define COMMAND_ADD_CLIENT 0x06
#define COMMAND_ADD_ADMIN 0x07
#define COMMAND_REMOVE_USER 0x08

#define RESERVED_BYTE 0x00

#define REQUEST_SIZE 4

#define DATE_SIZE 21
#define USERNAME_MAX_SIZE 255
#define PASSWORD_MAX_SIZE 255
#define DOMAIN_MAX_SIZE 255
#define DOMAIN_ATYP 0x03
#define IPV4_ATYP 0x01
#define IPV6_ATYP 0x04

#define IPV4_LEN_BYTES 4
#define IPV6_LEN_BYTES 16

#define USER_TYPE_CLIENT 0x00
#define USER_TYPE_ADMIN 0x01

#define MIN_BUFF_SIZE_KB 1
#define MAX_BUFF_SIZE_KB 10   //todo check values

#define MIN_TIMEOUT_SECONDS 1
#define MAX_TIMEOUT_SECONDS 255

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

typedef struct server_current_config {
	uint8_t buffer_size_kb; // Buffer size in KB
	uint8_t timeout_seconds; // Timeout in seconds
}server_current_config;

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
uint8_t handle_add_client(int sock, char * username, char * password);
uint8_t handle_add_admin(int sock, char * ussername, char * password);
uint8_t handle_remove_user(int sock, char * username);

// Memory management functions
void free_log_list(client_log_entry_t *head);
void free_user_list(user_list_entry *head);


#endif //LIB_CLIENT_H
