//
// Created by nep on 7/4/25.
//

#include "lib_client.h"
#include "buffer.h"

#include <bits/socket.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define HELLO_HEADER_FIXED_LEN 3
#define LOGS_RESPONSE_HEADER_FIXED_LEN 4
#define GET_USERS_RESPONSE_HEADER_FIXED_LEN 4
#define CHANGE_SERVER_SETTINGS_RESPONSE_HEADER_FIXED_LEN 3

metrics_t * handle_metrics_response(int sock, metrics_t * m);
void fill_log_struct(char * data, log_strct * log);
void fill_user_list_entry(char * data, user_list_entry * user, uint8_t pack_id);

static uint8_t user_type;

static uint8_t get_user_type() {
	return user_type;
}

int setup_tcp_client_Socket(char * address, char * port) {
	struct addrinfo addrCriteria = {0};                   // Criteria for address match
	addrCriteria.ai_family = AF_UNSPEC;             // v4 or v6 is OK
	addrCriteria.ai_socktype = SOCK_STREAM;         // Only streaming sockets
	addrCriteria.ai_protocol = IPPROTO_TCP;         // Only TCP protocol

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
			if ( connect(sock, addr->ai_addr, addr->ai_addrlen) != 0) {
				close(sock); 	// Socket connection failed; try next address
				sock = -1;
			}
		}
	}

	freeaddrinfo(servAddr);
	user_type = USER_TYPE_CLIENT;
	return sock;
}

int send_all(int fd, char * msg, size_t len) {
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

int recv_all(int fd, char * buf, size_t len) {
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

int hello_send(char * username, char * password, int sock) {
	if (username == NULL || password == NULL || sock < 0) {
		return -1; // Invalid parameters
	}

	// Prepare the hello message
	uint8_t username_len = strlen(username);
	uint8_t password_len = strlen(password);
	uint16_t total_len = HELLO_HEADER_FIXED_LEN + username_len + password_len;
	char msg[HELLO_HEADER_FIXED_LEN + username_len + password_len];
	char * msg_ptr = msg;
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
	user_type = buff[1] == 1? USER_TYPE_ADMIN : USER_TYPE_CLIENT; // 1 for admin, 0 for client
	return buff[1]; //returns hello_response code
}

int request_send(uint8_t command_code, uint8_t arg_1, uint8_t arg_2, int sock) {
	if (command_code > COMMAND_CHANGE_TIMEOUT || command_code < COMMAND_LOGS) {
		return RESPONSE_BAD_REQUEST; // Invalid command code
	}
	char request[REQUEST_SIZE];
	request[0] = CALSETTING_VERSION; // Protocol version
	request[1] = command_code;
	request[2] = arg_1;
	request[3] = arg_2;
	if (send_all(sock, request, REQUEST_SIZE) != REQUEST_SIZE) {
		return -1;
	}
	return 0; // success
}

uint8_t handle_change_buffer_size(int sock, uint8_t new_size) {
	if (user_type != USER_TYPE_ADMIN) {
		return RESPONSE_NOT_ALLOWED; // Only admin can change timeout
	}
	if (sock < 0) {
		return RESPONSE_BAD_REQUEST; // Invalid socket
	}

	if (new_size < MIN_BUFF_SIZE_KB || new_size > MAX_BUFF_SIZE_KB) {
		return RESPONSE_BAD_REQUEST; // Invalid buffer size
	}

	if (request_send(COMMAND_CHANGE_BUFFER_SIZE,new_size , RESERVED_BYTE, sock) != 0) {
		return RESPONSE_GENERAL_SERVER_FAILURE; // TODO check error codes for send error
	}

	char response[CHANGE_SERVER_SETTINGS_RESPONSE_HEADER_FIXED_LEN];
	if (recv_all(sock, response, CHANGE_SERVER_SETTINGS_RESPONSE_HEADER_FIXED_LEN) != CHANGE_SERVER_SETTINGS_RESPONSE_HEADER_FIXED_LEN) {
		return RESPONSE_GENERAL_SERVER_FAILURE; // Failed to read response
	}

	return response[1]; // Return the response code
}

uint8_t handle_change_timeout(int sock, uint8_t new_timeout) {
	if (user_type != USER_TYPE_ADMIN) {
		return RESPONSE_NOT_ALLOWED; // Only admin can change timeout
	}

	if (sock < 0) {
		return RESPONSE_BAD_REQUEST; // Invalid socket
	}

	if (new_timeout< MIN_TIMEOUT_SECONDS || new_timeout > MAX_TIMEOUT_SECONDS) {
		return RESPONSE_BAD_REQUEST; // Invalid Timeout
	}

	if (request_send(COMMAND_CHANGE_TIMEOUT,new_timeout , RESERVED_BYTE, sock) != 0) {
		return RESPONSE_GENERAL_SERVER_FAILURE; // TODO check error codes for send error
	}

	char response[CHANGE_SERVER_SETTINGS_RESPONSE_HEADER_FIXED_LEN];
	if (recv_all(sock, response, CHANGE_SERVER_SETTINGS_RESPONSE_HEADER_FIXED_LEN) != CHANGE_SERVER_SETTINGS_RESPONSE_HEADER_FIXED_LEN) {
		return RESPONSE_GENERAL_SERVER_FAILURE; // Failed to read response
	}
	return response[1]; // Return the response code
}

metrics_t * handle_metrics(int sock, metrics_t * m) {
	//send the request for metrics
	if (request_send(COMMAND_METRICS, RESERVED_BYTE, RESERVED_BYTE, sock) != 0) {
		return NULL; // Failed to send request
	}
	//handle the response
	return handle_metrics_response(sock, m);
}

metrics_t * handle_metrics_response(int sock, metrics_t * m) {
	if (sock < 0 || m == NULL) {
		return NULL; // Invalid parameters
	}

	// char response[sizeof(metrics_t)];
	// char * response_ptr = response;
	// uint32_t four_byte_temp;
	// uint16_t two_byte_temp;
	metrics_t response;

    if (recv_all(sock, &response, sizeof(metrics_t)) != sizeof(metrics_t)) {
		return NULL; // Failed to read metrics
	}

	m->version = response.version;
    m->server_state = response.server_state;

    m->total_connections = ntohl(response.total_connections);
    m->concurrent_connections = ntohs(response.concurrent_connections);
    m->max_concurrent_connections = ntohs(response.max_concurrent_connections);

    m->bytes_transferred_in = be64toh(response.bytes_transferred_in);
    m->bytes_transferred_out = be64toh(response.bytes_transferred_out);
    m->total_bytes_transferred = be64toh(response.total_bytes_transferred);

    m->total_errors = ntohl(response.total_errors);
    m->uptime_seconds = ntohl(response.uptime_seconds);

    m->network_errors = ntohs(response.network_errors);
    m->protocol_errors = ntohs(response.protocol_errors);
    m->auth_errors = ntohs(response.auth_errors);
    m->system_errors = ntohs(response.system_errors);
    m->timeout_errors = ntohs(response.timeout_errors);
    m->memory_errors = ntohs(response.memory_errors);
    m->other_errors = ntohs(response.other_errors);

	// m->version = *response_ptr++;
	// m->server_state = *response_ptr++;

	// memcpy(&four_byte_temp, response_ptr, sizeof(uint32_t));
	// m->n_current_connections = ntohl(four_byte_temp);
	// response_ptr += sizeof(uint32_t);

	// memcpy(&four_byte_temp, response_ptr, sizeof(uint32_t));
	// m->n_total_connections = ntohl(four_byte_temp);
	// response_ptr += sizeof(uint32_t);

	// memcpy(&four_byte_temp, response_ptr, sizeof(uint32_t));
	// m->n_total_bytes_received = ntohl(four_byte_temp);
	// response_ptr += sizeof(uint32_t);

	// memcpy(&four_byte_temp, response_ptr, sizeof(uint32_t));
	// m->n_total_bytes_sent = ntohl(four_byte_temp);
	// response_ptr += sizeof(uint32_t);

	// memcpy(&two_byte_temp, response_ptr, sizeof(uint16_t));
	// m->n_timeouts = ntohs(two_byte_temp);
	// response_ptr += sizeof(uint16_t);

	// memcpy(&two_byte_temp, response_ptr, sizeof(uint16_t));
	// m->n_server_errors = ntohs(two_byte_temp);
	// response_ptr += sizeof(uint16_t);

	// memcpy(&two_byte_temp, response_ptr, sizeof(uint16_t));
	// m->n_bad_requests = ntohs(two_byte_temp);
	// response_ptr += sizeof(uint16_t);

	return m; // Return the filled metrics structure
}

log_strct * handle_log(int sock, uint8_t n, uint8_t offset) {
	//send the request for metrics
	if (request_send(COMMAND_LOGS, n, offset, sock) != 0) {
		return NULL; // Failed to send request
	}
	char response[sizeof(log_strct)] = {0};
	char * response_ptr = response;
	uint32_t four_byte_temp;
	uint16_t two_byte_temp;

	if (recv_all(sock, response, LOGS_RESPONSE_HEADER_FIXED_LEN) != LOGS_RESPONSE_HEADER_FIXED_LEN) {
		return NULL; // Failed to read metrics
	}
	uint8_t nlogs = response[2];
	if (nlogs == 0) {
		return NULL; // No logs available
	}

	log_strct * head = malloc(sizeof(log_strct));
	head->next = NULL;

	if (recv_all(sock, response_ptr, sizeof(log_strct)) != sizeof(log_strct)) {
		free_log_list(head);
		return NULL; // Failed to read log. should not happen
	}
	fill_log_struct(response_ptr, head);
	response_ptr += sizeof(log_strct);
	nlogs--;
	log_strct * current_log_ptr = head;

	for (;nlogs > 0; nlogs--) {
		if (recv_all(sock, response_ptr, sizeof(log_strct)) != sizeof(log_strct)) {
			free_log_list(head);
			return NULL; // Failed to read log. should not happen
		}
		current_log_ptr->next = malloc(sizeof(log_strct));
		fill_log_struct(response_ptr, current_log_ptr->next);
		response_ptr += sizeof(log_strct);
		current_log_ptr = current_log_ptr->next;
	}
	return head;
}

user_list_entry * handle_get_users(uint8_t n, uint8_t offset,int sock) {
	if (request_send(COMMAND_USER_LIST, n, offset, sock) != 0) {
		return NULL; // Failed to send request
	}
	char response[sizeof(user_list_entry)] = {0};
	char * response_ptr = response;
	uint32_t four_byte_temp;
	uint16_t two_byte_temp;

	if (recv_all(sock, response, GET_USERS_RESPONSE_HEADER_FIXED_LEN) != GET_USERS_RESPONSE_HEADER_FIXED_LEN) {
		return NULL; // Failed to read metrics
	}
	uint8_t nusers = response[2];
	if (nusers == 0) {
		return NULL; // No logs available
	}
	user_list_entry * head = malloc(sizeof(user_list_entry));
	head->next = NULL;
	
	if (recv_all(sock, response_ptr, sizeof(user_list_entry)) != sizeof(user_list_entry)) {
		free_user_list(head);
		return NULL; // Failed to read user. should not happen
	}
	fill_user_list_entry(response_ptr, head, 0);
	response_ptr += sizeof(user_list_entry);
	user_list_entry * current_usr_ptr = head;

	for (uint8_t i = 1; i < nusers; i++) {
		if (recv_all(sock, response_ptr, sizeof(user_list_entry)) != sizeof(user_list_entry)) {
			free_user_list(head);
			return NULL; // Failed to read log. should not happen
		}
		current_usr_ptr->next = malloc(sizeof(user_list_entry));
		fill_user_list_entry(response_ptr, current_usr_ptr->next, i);
		response_ptr += sizeof(user_list_entry);
		current_usr_ptr = current_usr_ptr->next;
	}
	return head;
}

void fill_log_struct(char * data, log_strct * log) {
	memcpy(log->date,data,DATE_SIZE);
	data += DATE_SIZE;
	log->ulen = *data++;

	memcpy(log->username, data, log->ulen);
	data += log->ulen;
	log->register_type = *data++;  //should be 'A' always

	memcpy(log->origin_ip, data, IPV6_LEN_BYTES);
	data += IPV6_LEN_BYTES;

	uint16_t two_byte_temp;
	memcpy(&two_byte_temp, data, sizeof(uint16_t));
	log->origin_port = ntohs(two_byte_temp);
	data += sizeof(uint16_t);

	//TODO chequear address len que este bien o mal.
	log->destination_ATYP = *data++;
	if (log->destination_ATYP == DOMAIN_ATYP) {
		uint8_t domain_len = *data++;
		memcpy(log->destination_address, data, domain_len);
		log->destination_address[domain_len] = '\0'; // Null-terminate the string
		data += domain_len;
	} else if (log->destination_ATYP == IPV4_ATYP) {
		memcpy(log->destination_address, data, IPV4_LEN_BYTES);
		data += IPV4_LEN_BYTES;
	}
	else {
		memcpy(log->destination_address, data, IPV6_LEN_BYTES);
		data += IPV6_LEN_BYTES;
	}

	memcpy(&two_byte_temp, data, sizeof(uint16_t));
	log->destination_port = ntohs(two_byte_temp);
	data += sizeof(uint16_t);

	log->status_code = *data++;
}

void fill_user_list_entry(char * data, user_list_entry * user, uint8_t pack_id) {
	user->ulen = *data++;
	memcpy(user->username, data, user->ulen);
	data += user->ulen;
	user->user_type = *data++;
	user->package_id = pack_id; // Set the package ID
}

void free_log_list(log_strct * node) {
	if (node == NULL) {
		return; // Nothing to free
	}
	free_log_list(node->next);
	free(node);
}

void free_user_list(user_list_entry * node) {
	if (node == NULL) {
		return; // Nothing to free
	}
	free_user_list(node->next);
	free(node);
}
