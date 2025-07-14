// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
//
// Created by nep on 7/4/25.
//

#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "buffer.h"
#include "lib_client.h"

metrics_t *handle_metrics_response(int sock, metrics_t *m);
void fill_log_struct(char *data, client_log_entry_t *log);
void fill_user_list_entry(char *data, user_list_entry *user);
uint8_t add_user_send_req(int sock, char *username, char *password, uint8_t user_type_command_code);
uint8_t remove_user_send_req(int sock, char *username);
static uint8_t user_type;

static uint8_t get_user_type() {
	return user_type;
}

int setup_tcp_client_socket(char *address, char *port) {
	struct addrinfo addrCriteria = {0};		// Criteria for address match
	addrCriteria.ai_family = AF_UNSPEC;		// v4 or v6 is OK
	addrCriteria.ai_socktype = SOCK_STREAM; // Only streaming sockets
	addrCriteria.ai_protocol = IPPROTO_TCP; // Only TCP protocol

	// Get address(es)
	struct addrinfo *servAddr; // Holder for returned list of server addrs
	int rtnVal = getaddrinfo(address, port, &addrCriteria, &servAddr);
	if (rtnVal != 0) {
		return -1;
	}
	int sock = -1;
	for (struct addrinfo *addr = servAddr; addr != NULL && sock == -1; addr = addr->ai_next) {
		// Create a reliable, stream socket using TCP
		sock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
		if (sock >= 0) {
			errno = 0;
			// Establish the connection to the server
			if (connect(sock, addr->ai_addr, addr->ai_addrlen) != 0) {
				close(sock); // Socket connection failed; try next address
				sock = -1;
			}
		}
	}

	freeaddrinfo(servAddr);
	user_type = USER_TYPE_CLIENT;
	return sock;
}

int send_all(int fd, char *msg, size_t len) {
	size_t total_sent = 0;
	while (total_sent < len) {
		ssize_t bytes_sent = send(fd, msg + total_sent, len - total_sent, 0);
		if (bytes_sent < 0) {
			if (errno == EINTR) {
				continue; // Interrupted, try again
			}
			return -1; // Error occurred
		}
		total_sent += bytes_sent;
	}

	return total_sent; // Return total bytes sent
}

int recv_all(int fd, char *buf, size_t len) {
	size_t total_received = 0;
	while (total_received < len) {
		ssize_t bytes_received = recv(fd, buf + total_received, len - total_received, 0);
		if (bytes_received < 0) {
			if (errno == EINTR) {
				continue; // Interrupted, try again
			}
			return -1; // Error occurred
		} else if (bytes_received == 0) {
			return total_received; // Connection closed
		}
		total_received += bytes_received;
	}

	return total_received; // Return total bytes received
}
// Because we manage the username and pass, strlen will always be okey for uint_8
int hello_send(char *username, char *password, int sock) {
	if (username == NULL || password == NULL || sock < 0) {
		return -1; // Invalid parameters
	}

	// Prepare the hello message
	uint8_t username_len = (uint8_t) strlen(username);
	uint8_t password_len = (uint8_t) strlen(password);
	uint16_t total_len = HELLO_HEADER_FIXED_LEN + username_len + password_len;
	char msg[HELLO_HEADER_FIXED_LEN + username_len + password_len];
	char *msg_ptr = msg;
	msg_ptr[0] = 0x01;
	msg_ptr[1] = username_len;
	msg_ptr[2] = password_len;
	msg_ptr += 3;

	memcpy(msg_ptr, username, username_len);
	msg_ptr += username_len;
	memcpy(msg_ptr, password, password_len);

	if (send_all(sock, msg, total_len) < 0) {
		return -1; // Failed to send
	}
	return 0; // success
}

int hello_read(int sock) {
	char buff[2] = {0};
	if (recv_all(sock, buff, 2) < 0) {
		return -1; // Failed to read
	}
	user_type = buff[1] == RESPONSE_SUCCESS_ADMIN ? USER_TYPE_ADMIN : USER_TYPE_CLIENT; // 1 for admin, 0 for client
	return buff[1];																		// returns hello_response code
}

int request_send(uint8_t command_code, uint8_t arg_1, uint8_t arg_2, int sock) {
	char request[REQUEST_SIZE];
	request[0] = CALSETTING_VERSION;
	request[1] = command_code;
	request[2] = arg_1;
	request[3] = arg_2;

	int result = send_all(sock, request, REQUEST_SIZE);

	if (result != REQUEST_SIZE) {
		return -1;
	}
	return 0;
}

uint8_t handle_add_client(int sock, char *username, char *password) {
	if (get_user_type() != USER_TYPE_ADMIN) {
		return RESPONSE_NOT_ALLOWED;
	}
	uint8_t r = add_user_send_req(sock, username, password, COMMAND_ADD_CLIENT);
	if (r != 0) {
		return r; // Failed to send request
	}
	char response[RESPONSE_HEADER_LEN];
	if (recv_all(sock, response, RESPONSE_HEADER_LEN) != RESPONSE_HEADER_LEN) {
		return RESPONSE_GENERAL_SERVER_FAILURE; // Failed to read response
	}
	return response[1]; // Return the response code
}

uint8_t handle_add_admin(int sock, char *username, char *password) {
	if (get_user_type() != USER_TYPE_ADMIN) {
		return RESPONSE_NOT_ALLOWED;
	}
	uint8_t r = add_user_send_req(sock, username, password, COMMAND_ADD_ADMIN);
	if (r != 0) {
		return r;
	}
	char response[RESPONSE_HEADER_LEN];
	if (recv_all(sock, response, RESPONSE_HEADER_LEN) != RESPONSE_HEADER_LEN) {
		return RESPONSE_GENERAL_SERVER_FAILURE; // Failed to read response
	}
	return response[1]; // Return the response code
}

uint8_t add_user_send_req(int sock, char *username, char *password, uint8_t user_type_command_code) {
	if (sock < 0) {
		return RESPONSE_BAD_REQUEST; // Invalid socket
	}
	const unsigned int raw_len_usrname = strlen(username);
	const unsigned int raw_len_pwd = strlen(password);
	if (raw_len_usrname > USERNAME_MAX_SIZE || raw_len_pwd > PASSWORD_MAX_SIZE || raw_len_usrname == 0 ||
		raw_len_pwd == 0) {
		return RESPONSE_BAD_REQUEST; // Username too long
	}
	uint8_t username_len = raw_len_usrname;
	uint8_t password_len = raw_len_pwd;
	char data[username_len + password_len + REQUEST_SIZE];
	char *data_ptr = data;
	data_ptr[0] = CALSETTING_VERSION;
	data_ptr[1] = user_type_command_code;
	data_ptr[2] = username_len;
	data_ptr[3] = password_len;
	data_ptr += REQUEST_SIZE;
	memcpy(data_ptr, username, username_len);
	data_ptr += username_len;
	memcpy(data_ptr, password, password_len);
	if (send_all(sock, data, username_len + password_len + REQUEST_SIZE) !=
		username_len + password_len + REQUEST_SIZE) {
		return RESPONSE_GENERAL_SERVER_FAILURE; // Failed to send request
	}
	return 0;
}

uint8_t handle_remove_user(int sock, char *username) {
	uint8_t req_result = remove_user_send_req(sock, username);
	if (req_result != 0) {
		return req_result;
	}
	char response[RESPONSE_HEADER_LEN];
	if (recv_all(sock, response, RESPONSE_HEADER_LEN) != RESPONSE_HEADER_LEN) {
		return RESPONSE_GENERAL_SERVER_FAILURE;
	}
	return response[1];
}

uint8_t remove_user_send_req(int sock, char *username) {
	if (sock < 0) {
		return RESPONSE_GENERAL_SERVER_FAILURE; // Invalid socket
	}
	const unsigned int raw_len_usrname = strlen(username);
	if (raw_len_usrname > USERNAME_MAX_SIZE || raw_len_usrname == 0) {
		return RESPONSE_BAD_REQUEST; // Username too long
	}
	uint8_t username_len = raw_len_usrname;

	char data[username_len + REQUEST_SIZE];
	char *data_ptr = data;
	data_ptr[0] = CALSETTING_VERSION;
	data_ptr[1] = COMMAND_REMOVE_USER;
	data_ptr[2] = username_len;
	data_ptr[3] = RESERVED_BYTE;
	data_ptr += REQUEST_SIZE;
	memcpy(data_ptr, username, username_len);
	if (send_all(sock, data, username_len + REQUEST_SIZE) != username_len + REQUEST_SIZE) {
		return RESPONSE_GENERAL_SERVER_FAILURE; // Failed to send request
	}
	return 0;
}

uint8_t handle_change_buffer_size(int sock, uint8_t new_size) {
	if (sock < 0) {
		return RESPONSE_GENERAL_SERVER_FAILURE; // Invalid socket
	}

	if (new_size < MIN_BUFF_SIZE_KB || new_size > MAX_BUFF_SIZE_KB) {
		return RESPONSE_BAD_REQUEST; // Invalid buffer size
	}

	int send_result = request_send(COMMAND_CHANGE_BUFFER_SIZE, new_size, RESERVED_BYTE, sock);

	if (send_result != 0) {
		return RESPONSE_GENERAL_SERVER_FAILURE;
	}
	char response[RESPONSE_HEADER_LEN];
	int recv_result = recv_all(sock, response, RESPONSE_HEADER_LEN);
	if (recv_result != RESPONSE_HEADER_LEN) {
		return RESPONSE_GENERAL_SERVER_FAILURE;
	}
	return response[1];
}

uint8_t handle_change_timeout(int sock, uint8_t new_timeout) {
	if (sock < 0) {
		return RESPONSE_BAD_REQUEST; // Invalid socket
	}

	if (new_timeout < MIN_TIMEOUT_SECONDS || new_timeout > MAX_TIMEOUT_SECONDS) {
		return RESPONSE_BAD_REQUEST; // Invalid Timeout
	}

	if (request_send(COMMAND_CHANGE_TIMEOUT, new_timeout, RESERVED_BYTE, sock) != 0) {
		return RESPONSE_GENERAL_SERVER_FAILURE; // TODO check error codes for send error
	}

	char response[RESPONSE_HEADER_LEN];
	if (recv_all(sock, response, RESPONSE_HEADER_LEN) != RESPONSE_HEADER_LEN) {
		return RESPONSE_GENERAL_SERVER_FAILURE; // Failed to read response
	}
	return response[1]; // Return the response code
}

server_current_config *handle_get_current_config(int sock, server_current_config *config) {
	if (config == NULL) {
		return NULL; // Invalid config pointer
	}
	if (sock < 0) {
		return NULL; // Invalid socket
	}

	if (request_send(COMMAND_GET_CURRENT_CONFIG, RESERVED_BYTE, RESERVED_BYTE, sock) != 0) {
		return NULL; // Failed to send request
	}

	char response[RESPONSE_HEADER_LEN + 2];
	if (recv_all(sock, response, RESPONSE_HEADER_LEN + 2) != RESPONSE_HEADER_LEN + 2) {
		return NULL; // Failed to read current config
	}

	if (response[1] != RESPONSE_SUCCESS) {
		return NULL; // Command failed, status not success
	}

	config->buffer_size_kb = response[4];
	config->timeout_seconds = response[5];
	return config; // Return the filled server_current_config structure
}

metrics_t *handle_metrics(int sock, metrics_t *m) {
	// send the request for metrics
	if (request_send(COMMAND_METRICS, RESERVED_BYTE, RESERVED_BYTE, sock) != 0) {
		return NULL; // Failed to send request
	}
	// handle the response
	return handle_metrics_response(sock, m);
}

metrics_t *handle_metrics_response(int sock, metrics_t *m) {
	if (sock < 0 || m == NULL) {
		return NULL;
	}

	uint8_t response[METRICS_RESPONSE_SIZE];
	if (recv_all(sock, (char *) response, METRICS_RESPONSE_SIZE) != METRICS_RESPONSE_SIZE) {
		return NULL;
	}

	int offset = 0;

	m->version = response[offset++];
	m->server_state = response[offset++];

	uint32_t temp32;
	uint64_t temp64;

	// 32-bit concurrent_connections
	memcpy(&temp32, &response[offset], 4);
	m->concurrent_connections = ntohl(temp32);
	offset += 4;

	// 64-bit total_connections
	memcpy(&temp64, &response[offset], 8);
	m->total_connections = be64toh(temp64);
	offset += 8;

	// 32-bit max_concurrent_connections
	memcpy(&temp32, &response[offset], 4);
	m->max_concurrent_connections = ntohl(temp32);
	offset += 4;

	// 64-bit bytes_transferred_in
	memcpy(&temp64, &response[offset], 8);
	m->bytes_transferred_in = be64toh(temp64);
	offset += 8;

	// 64-bit bytes_transferred_out
	memcpy(&temp64, &response[offset], 8);
	m->bytes_transferred_out = be64toh(temp64);
	offset += 8;

	// 64-bit total_bytes_transferred
	memcpy(&temp64, &response[offset], 8);
	m->total_bytes_transferred = be64toh(temp64);
	offset += 8;

	// Continue with all the 32-bit error fields...
	memcpy(&temp32, &response[offset], 4);
	m->total_errors = ntohl(temp32);
	offset += 4;

	memcpy(&temp32, &response[offset], 4);
	m->uptime_seconds = ntohl(temp32);
	offset += 4;

	memcpy(&temp32, &response[offset], 4);
	m->network_errors = ntohl(temp32);
	offset += 4;

	memcpy(&temp32, &response[offset], 4);
	m->protocol_errors = ntohl(temp32);
	offset += 4;

	memcpy(&temp32, &response[offset], 4);
	m->auth_errors = ntohl(temp32);
	offset += 4;

	memcpy(&temp32, &response[offset], 4);
	m->system_errors = ntohl(temp32);
	offset += 4;

	memcpy(&temp32, &response[offset], 4);
	m->timeout_errors = ntohl(temp32);
	offset += 4;

	memcpy(&temp32, &response[offset], 4);
	m->memory_errors = ntohl(temp32);
	offset += 4;

	memcpy(&temp32, &response[offset], 4);
	m->other_errors = ntohl(temp32);

	return m;
}

client_log_entry_t *handle_log(int sock, uint8_t n, uint8_t offset) {
	if (request_send(COMMAND_LOGS, n, offset, sock) != 0) {
		errno = ENOTCONN;
		return NULL;
	}

	char header[RESPONSE_HEADER_LEN] = {0};
	if (recv_all(sock, header, RESPONSE_HEADER_LEN) != RESPONSE_HEADER_LEN) {
		errno = ENOTCONN;
		return NULL;
	}

	if (header[1] != RESPONSE_SUCCESS) {
		// should show on console the exact response code that was received
		errno = ENOTCONN;
		return NULL;
	}

	uint8_t nlogs = header[3];
	if (nlogs == 0) {
		return NULL;
	}

	client_log_entry_t *head = NULL;
	client_log_entry_t *current = NULL;

	for (uint8_t i = 0; i < nlogs; i++) {
		char wire_data[LOG_ENTRY_WIRE_SIZE];

		if (recv_all(sock, wire_data, LOG_ENTRY_WIRE_SIZE) != LOG_ENTRY_WIRE_SIZE) {
			free_log_list(head);
			return NULL;
		}

		client_log_entry_t *new_entry = malloc(sizeof(client_log_entry_t));
		if (!new_entry) {
			free_log_list(head);
			return NULL;
		}
		new_entry->next = NULL;

		// Fill the entry using the same parsing logic
		fill_log_struct(wire_data, new_entry);

		if (!head) {
			head = new_entry;
			current = head;
		} else {
			current->next = new_entry;
			current = new_entry;
		}
	}

	return head;
}

user_list_entry *handle_get_users(uint8_t n, uint8_t offset, int sock) {
	if (request_send(COMMAND_USER_LIST, n, offset, sock) != 0) {
		errno = ENOTCONN;
		return NULL; // Failed to send request
	}

	char header[RESPONSE_HEADER_LEN] = {0};
	if (recv_all(sock, header, RESPONSE_HEADER_LEN) != RESPONSE_HEADER_LEN) {
		errno = ENOTCONN;
		return NULL;
	}

	uint8_t nusers = header[3];
	if (nusers == 0) {
		return NULL;
	}

	user_list_entry *head = NULL;
	user_list_entry *current = NULL;

	for (uint8_t i = 0; i < nusers; i++) {
		char user_entry[USER_ENTRY_SIZE];
		if (recv_all(sock, user_entry, USER_ENTRY_SIZE) != USER_ENTRY_SIZE) {
			free_user_list(head);
			errno = ENOTCONN;
			return NULL;
		}

		uint8_t ulen = user_entry[0];
		uint8_t user_type = user_entry[1];
		char *username_data = &user_entry[2];

		// Create new user entry
		user_list_entry *new_user = malloc(sizeof(user_list_entry));
		if (!new_user) {
			free_user_list(head);
			errno = ENOTCONN;
			return NULL;
		}

		new_user->ulen = ulen;
		memcpy(new_user->username, username_data, ulen);
		new_user->username[ulen] = '\0';
		new_user->user_type = user_type;
		new_user->package_id = 0; // TODO: not being used atm
		new_user->next = NULL;

		if (head == NULL) {
			head = new_user;
			current = head;
		} else {
			current->next = new_user;
			current = new_user;
		}
	}

	return head;
}

void fill_log_struct(char *data, client_log_entry_t *log) {
	char *ptr = data;

	// Date (21 bytes fixed)
	memcpy(log->date, ptr, DATE_SIZE);
	log->date[DATE_SIZE - 1] = '\0';
	ptr += 21;

	// Username length (1 byte)
	log->ulen = *ptr++;

	// Username (255 bytes fixed, regardless of actual length)
	memcpy(log->username, ptr, USERNAME_MAX_SIZE);
	log->username[log->ulen] = '\0';
	ptr += 255;

	// Register type (1 byte)
	log->register_type = *ptr++;

	// Origin IP (46 bytes fixed - INET6_ADDRSTRLEN)
	memcpy(log->origin_ip, ptr, INET6_ADDRSTRLEN);
	log->origin_ip[INET6_ADDRSTRLEN - 1] = '\0';
	ptr += 46;

	// Origin port (2 bytes, network order)
	uint16_t origin_port_net;
	memcpy(&origin_port_net, ptr, sizeof(uint16_t));
	log->origin_port = ntohs(origin_port_net);
	ptr += sizeof(uint16_t);

	// Destination ATYP (1 byte)
	log->destination_ATYP = *ptr++;

	memcpy(log->destination_address, ptr, DOMAIN_MAX_SIZE + 1);
	log->destination_address[DOMAIN_MAX_SIZE] = '\0';
	ptr += 256;

	// Destination port (2 bytes, network order)
	uint16_t dest_port_net;
	memcpy(&dest_port_net, ptr, sizeof(uint16_t));
	log->destination_port = ntohs(dest_port_net);
	ptr += sizeof(uint16_t);

	// Status code (1 byte)
	log->status_code = *ptr++;
}

void fill_user_list_entry(char *data, user_list_entry *user) {
	user->ulen = *data++;
	memcpy(user->username, data, user->ulen);
	user->username[user->ulen] = '\0';
	data += user->ulen;
	user->user_type = *data++;
	user->package_id = *data++; // Set the package ID
}

void free_log_list(client_log_entry_t *node) {
	if (node == NULL) {
		return; // Nothing to free
	}
	free_log_list(node->next);
	free(node);
}

void free_user_list(user_list_entry *node) {
	if (node == NULL) {
		return; // Nothing to free
	}
	free_user_list(node->next);
	free(node);
}
