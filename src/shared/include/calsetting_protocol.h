// shared/include/calsetting_protocol.h
#ifndef CALSETTING_PROTOCOL_H
#define CALSETTING_PROTOCOL_H

#include <stdint.h>
#include <netinet/in.h>

// Protocol version
#define CALSETTING_VERSION 0x01

// SERVER RESPONSE CODES
#define RESPONSE_SUCCESS_CLIENT     0x00    // Usuario autenticado
#define RESPONSE_SUCCESS_ADMIN      0x01    // Admin autenticado  
#define RESPONSE_AUTH_FAILURE       0x02    // Error de autenticación
#define RESPONSE_GENERAL_SERVER_FAILURE 0x03 // General server error
#define RESPONSE_WRONG_VERSION      0x04    // Versión incorrecta
#define RESPONSE_NOT_ALLOWED        0x05    // Not allowed

// Client-side error code (not sent over network)
#define RESPONSE_BAD_REQUEST        0x06    // Client validation error
                                            //not for server but used by lib to let the frontend know
// CLIENT RESPONSE CODES
#define HELLO_CLIENT_RESPONSE_CODE 0x00
#define HELLO_ADMIN_RESPONSE_CODE 0x01
#define HELLO_ERROR_RESPONSE_CODE 0x02

// Command codes (exactly matching your lib_client.h)
#define COMMAND_LOGS                0x00    // Logs
#define COMMAND_USER_LIST          0x01    // Lista de usuarios  
#define COMMAND_METRICS            0x02    // Métricas
#define COMMAND_CHANGE_BUFFER_SIZE 0x03    // Change Buffer Size
#define COMMAND_CHANGE_TIMEOUT     0x04    // Change Timeout

// User types
#define USER_TYPE_CLIENT           0x00
#define USER_TYPE_ADMIN            0x01

// Protocol constants
#define RESERVED_BYTE              0x00
#define REQUEST_SIZE               4
#define DATE_SIZE                  21
#define USERNAME_MAX_SIZE          255
#define DOMAIN_MAX_SIZE            255

// Address types
#define IPV4_ATYP                  0x01
#define IPV6_ATYP                  0x04
#define DOMAIN_ATYP                0x03

#define IPV4_LEN_BYTES             4
#define IPV6_LEN_BYTES             16

// Configuration limits
#define MIN_BUFF_SIZE_KB           1
#define MAX_BUFF_SIZE_KB           64    // Updated to match server (64KB max)
#define MIN_TIMEOUT_SECONDS        1
#define MAX_TIMEOUT_SECONDS        60    // Updated to match server (60s max)

// Fixed header lengths
#define HELLO_HEADER_FIXED_LEN                    3
#define LOGS_RESPONSE_HEADER_FIXED_LEN           4
#define GET_USERS_RESPONSE_HEADER_FIXED_LEN      4
#define CHANGE_SERVER_SETTINGS_RESPONSE_HEADER_FIXED_LEN 3


// typedef struct __attribute__((packed)) {
//     uint8_t version;                    // Protocol version
//     uint8_t server_state;               // 1 = running, 0 = stopping
    
//     // Connection metrics (20 bytes)
//     uint32_t concurrent_connections;    // Current active connections
//     uint64_t total_connections;         // All-time total connections
//     uint32_t max_concurrent_connections; // Peak concurrent connections
    
//     // Transfer metrics (24 bytes)  
//     uint64_t bytes_transferred_in;      // Total bytes received
//     uint64_t bytes_transferred_out;     // Total bytes sent
//     uint64_t total_bytes_transferred;   // Sum of in + out
    
//     // General metrics (8 bytes)
//     uint32_t total_errors;              // All errors combined
//     uint32_t uptime_seconds;            // Server uptime in seconds
    
//     // Detailed error breakdown (28 bytes)
//     uint32_t network_errors;            // ERROR_TYPE_NETWORK
//     uint32_t protocol_errors;           // ERROR_TYPE_PROTOCOL  
//     uint32_t auth_errors;               // ERROR_TYPE_AUTH
//     uint32_t system_errors;             // ERROR_TYPE_SYSTEM
//     uint32_t timeout_errors;            // ERROR_TYPE_TIMEOUT
//     uint32_t memory_errors;             // ERROR_TYPE_MEMORY
//     uint32_t other_errors;              // ERROR_TYPE_OTHER
// } metrics_t;

// (mucho texto perdon)
// IMPORTANT: This struct is deliberately ordered and sized to ensure proper alignment.
// Fields and sizes were chosen to minimize padding and maintain alignment.
// If you modify this struct, double-check the alignment and total size to avoid misalignment or inefficient memory layout.
// Note: The `__attribute__((packed))` is used here to ensure no padding is added between fields.
// This guarantees that the memory layout matches the expected wire format when sending the struct as raw bytes.
// Reference: https://stackoverflow.com/questions/12304326/padded-structures-using-attribute-packed-is-it-really-worth-it
// 
// TODO: Consider manually writing each field directly to the buffer instead of sending the struct as raw bytes.
typedef struct __attribute__((packed)) {
    // Header
    uint8_t version;
    uint8_t server_state;
    uint16_t reserved;
    
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
    uint16_t reserved2; // to align to 8 bytes
} metrics_t; // total = 60 bytes

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
} log_strct;

typedef struct user_list_entry {
	uint8_t ulen;
	char username[USERNAME_MAX_SIZE];
	uint8_t user_type;
	uint8_t package_id;  //TODO capaz sacar?
	struct user_list_entry * next;
} user_list_entry;

#endif // CALSETTING_PROTOCOL_H