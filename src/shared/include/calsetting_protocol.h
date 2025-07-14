// shared/include/calsetting_protocol.h
#ifndef CALSETTING_PROTOCOL_H
#define CALSETTING_PROTOCOL_H

#include <netinet/in.h>
#include <stdint.h>

// Protocol version
#define CALSETTING_VERSION 0x01

// SERVER RESPONSE CODES
#define RESPONSE_SUCCESS 0x00				 // Success
#define RESPONSE_SUCCESS_CLIENT 0x01		 // Usuario autenticado
#define RESPONSE_SUCCESS_ADMIN 0x02			 // Admin autenticado
#define RESPONSE_AUTH_FAILURE 0x03			 // Error de autenticación
#define RESPONSE_GENERAL_SERVER_FAILURE 0x04 // General server error
#define RESPONSE_WRONG_VERSION 0x05			 // Versión incorrecta
#define RESPONSE_NOT_ALLOWED 0x06			 // Not allowed
#define RESPONSE_USER_NOT_FOUND 0x07
#define RESPONSE_INVALID_CREDENTIALS 0x08 // Invalid credentials
#define RESPONSE_USER_ALREADY_EXISTS 0x09 // User already exists
#define RESPONSE_MAX_USERS_REACHED 0x0A	  // Max users reached
#define RESPONSE_BAD_REQUEST 0x0B		  // Client validation error

// CLIENT RESPONSE CODES
#define HELLO_CLIENT_RESPONSE_CODE 0x00
#define HELLO_ADMIN_RESPONSE_CODE 0x01
#define HELLO_ERROR_RESPONSE_CODE 0x02

// Command codes
#define COMMAND_LOGS 0x00				// Logs
#define COMMAND_USER_LIST 0x01			// Lista de usuarios
#define COMMAND_METRICS 0x02			// Métricas
#define COMMAND_CHANGE_BUFFER_SIZE 0x03 // Change Buffer Size
#define COMMAND_CHANGE_TIMEOUT 0x04		// Change Timeout
#define COMMAND_GET_CURRENT_CONFIG 0x05
#define COMMAND_ADD_CLIENT 0x06
#define COMMAND_ADD_ADMIN 0x07
#define COMMAND_REMOVE_USER 0x08

// User types
#define USER_TYPE_CLIENT 0x00
#define USER_TYPE_ADMIN 0x01

// Protocol constants
#define RESERVED_BYTE 0x00
#define DATE_SIZE 21 // ISO-8601 timestamp
#define USERNAME_MAX_SIZE 255
#define PASSWORD_MAX_SIZE 255
#define DOMAIN_MAX_SIZE 255

#define REQUEST_SIZE 4
#define RESPONSE_HEADER_LEN 4
#define USER_ENTRY_SIZE (1 + 1 + USERNAME_MAX_SIZE)
#define HELLO_HEADER_FIXED_LEN 3
#define LOG_ENTRY_WIRE_SIZE 586	 // 21 + 1 + 255 + 1 + 46 + 2 + 1 + 256 + 2 + 1 = 586 bytes
#define METRICS_RESPONSE_SIZE 78 // Size of metrics_t struct

// Address types
#define IPV4_ATYP 0x01
#define IPV6_ATYP 0x04
#define DOMAIN_ATYP 0x03

#define IPV4_LEN_BYTES 4
#define IPV6_LEN_BYTES 16
#define INET6_ADDRSTRLEN 46 // IPv6 address string length

// LIMITS
// Buffer size limits (in KB for admin interface)
#define MIN_BUFF_SIZE_KB 1
#define MAX_BUFF_SIZE_KB 64

// Timeout limits (in seconds)
#define MIN_TIMEOUT_SECONDS 1
#define MAX_TIMEOUT_SECONDS 60

// Internal buffer limits (in bytes)
#define BUFFER_SIZE_MIN 1024		// 1KB
#define BUFFER_SIZE_MAX (64 * 1024) // 64KB

// Only client uses metrics_t
typedef struct metrics_t {
	// Header
	uint8_t version;
	uint8_t server_state;

	uint32_t total_connections;
	uint16_t concurrent_connections;
	uint16_t max_concurrent_connections;

	uint64_t bytes_transferred_in;
	uint64_t bytes_transferred_out;
	uint64_t total_bytes_transferred;

	uint32_t total_errors;
	uint32_t uptime_seconds;
	uint16_t network_errors;
	uint16_t protocol_errors;
	uint16_t auth_errors;
	uint16_t system_errors;
	uint16_t timeout_errors;
	uint16_t memory_errors;
	uint16_t other_errors;

} metrics_t;

// Only server uses log_entry_t
typedef struct log_entry_t {
	char date[DATE_SIZE]; // date in ISO-8601 format YYYY-MM-DDTHH:MM:SS
	uint8_t ulen;
	char username[USERNAME_MAX_SIZE];
	char register_type; // always 'A'
	char origin_ip[INET6_ADDRSTRLEN];
	uint16_t origin_port;						   // origin port
	uint8_t destination_ATYP;					   // 0x01 for IPv4, 0x04 for IPv6, 0x03 for domain
	char destination_address[DOMAIN_MAX_SIZE + 1]; // destination address, if IPv4 or IPv6. in socks5 protocol domains
												   // need the first byte for domainLen so max len will be 255 + 1
	uint16_t destination_port;					   // origin port
	uint8_t status_code;
} log_entry_t;

// Only client uses user_list_entry
typedef struct user_list_entry {
	uint8_t ulen;
	char username[USERNAME_MAX_SIZE];
	uint8_t user_type;
	uint8_t package_id; // TODO capaz sacar?
	struct user_list_entry *next;
} user_list_entry;

#endif // CALSETTING_PROTOCOL_H
