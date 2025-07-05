//
// Created by nep on 7/4/25.
//

#ifndef LIB_CLIENT_H
#define LIB_CLIENT_H

#include <netinet/in.h>
#include <stdint.h>

#define METRICS_PROTOCOL_VERSION 1
#define RESPONSE_SUCCESS_CLIENT 0x00
#define RESPONSE_SUCCESS_ADMIN 0x01
#define RESPONSE_AUTH_FAILURE 0x02
#define RESPONSE_GENERAL_SERVER_FAILURE 0x03
#define RESPONSE_WRONG_VERSION 0x04
#define RESPONSE_NOT_ALLOWED 0x05

#define RESPONSE_BAD_REQUEST 0x06 //not for server but used by lib to let the frontend know

#define HELLO_CLIENT_RESPONSE_CODE 0x00
#define HELLO_ADMIN_RESPONSE_CODE 0x01
#define HELLO_ERROR_RESPONSE_CODE 0x02


#define COMMAND_LOGS 0x00
#define COMMAND_USER_LIST 0x01
#define COMMAND_METRICS 0x02
#define COMMAND_CHANGE_BUFFER_SIZE 0x03
#define COMMAND_CHANGE_TIMEOUT 0x04

#define RESERVED_BYTE 0x00

#define REQUEST_SIZE 4

#define DATE_SIZE 21
#define USERNAME_MAX_SIZE 255
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
	uint8_t error_code;  //in case we need it
}metrics;

typedef struct log_strct {
	char date[DATE_SIZE];  //date in ISO-8601 format YYYY-MM-DDTHH:MM:SS
	uint8_t ulen;
	char username[USERNAME_MAX_SIZE];
	char register_type; //always 'A'
	char origin_ip[INET_ADDRSTRLEN];
	uint16_t origin_port; //origin port
	uint8_t destination_ATYP; //0x01 for IPv4, 0x04 for IPv6, 0x03 for domain
	char destination_address[DOMAIN_MAX_SIZE + 1]; //destination address, if IPv4 or IPv6. in socks5 protocol domains need the first byte for domainLen so max len will be 255 + 1
	uint16_t destination_port; //origin port
	uint8_t status_code;
	struct log_strct * next; //pointer to the next log in the linked list
}log_strct;

typedef struct user_list_entry {
	uint8_t ulen;
	char username[USERNAME_MAX_SIZE];
	uint8_t user_type;
	uint8_t package_id;  //TODO capaz sacar?
	struct user_list_entry * next;
}user_list_entry;

void free_log_list(log_strct * head);
void free_user_list(user_list_entry * head);

#endif //LIB_CLIENT_H
