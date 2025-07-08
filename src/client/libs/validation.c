#include <arpa/inet.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../include/ui_adapter.h"
#include "../include/validation.h"

#define MAX_USERNAME_LEN 24
#define MIN_USERNAME_LEN 3
#define MAX_PASSWORD_LEN 24
#define MIN_PASSWORD_LEN 4
#define MIN_BUFFER_SIZE 1
#define MAX_BUFFER_SIZE 255
#define MIN_TIMEOUT 1
#define MAX_TIMEOUT 255
#define MIN_PORT 1
#define MAX_PORT 65535

int validate_input(const char *input, int min_len, int max_len, const char *error_prefix) {
	if (!input || strlen(input) == 0) {
		char msg[256];
		snprintf(msg, sizeof(msg), "%s cannot be empty", error_prefix);
		ui_show_message("Error", msg);
		return 0;
	}

	size_t len = strlen(input);

	if (len < (size_t) min_len) {
		char msg[256];
		snprintf(msg, sizeof(msg), "%s must be at least %d characters long", error_prefix, min_len);
		ui_show_message("Error", msg);
		return 0;
	}

	if (len >= (size_t) max_len) {
		char msg[256];
		snprintf(msg, sizeof(msg), "%s must be less than %d characters long", error_prefix, max_len);
		ui_show_message("Error", msg);
		return 0;
	}

	return 1;
}

int validate_username(const char *username) {
	if (!validate_input(username, MIN_USERNAME_LEN, MAX_USERNAME_LEN, "Username")) {
		return 0;
	}

	for (size_t i = 0; i < strlen(username); i++) {
		if (!isalnum((unsigned char) username[i]) && username[i] != '_') {
			ui_show_message("Error", "Username can only contain letters, numbers, and underscores");
			return 0;
		}
	}

	return 1;
}

int validate_password(const char *password) {
	if (!validate_input(password, MIN_PASSWORD_LEN, MAX_PASSWORD_LEN, "Password")) {
		return 0;
	}

	int has_letter = 0;
	int has_number = 0;

	for (size_t i = 0; i < strlen(password); i++) {
		if (isalpha((unsigned char) password[i])) {
			has_letter = 1;
		} else if (isdigit((unsigned char) password[i])) {
			has_number = 1;
		}
	}

	if (!has_letter || !has_number) {
		ui_show_message("Error", "Password must contain at least one letter and one number");
		return 0;
	}

	return 1;
}

int validate_numeric_only(const char *input, const char *field_name) {
	if (!input || strlen(input) == 0) {
		char msg[256];
		snprintf(msg, sizeof(msg), "%s cannot be empty", field_name);
		ui_show_message("Error", msg);
		return 0;
	}

	for (size_t i = 0; i < strlen(input); i++) {
		if (!isdigit((unsigned char) input[i])) {
			char msg[256];
			snprintf(msg, sizeof(msg), "%s must contain only numbers", field_name);
			ui_show_message("Error", msg);
			return 0;
		}
	}

	return 1;
}

int validate_numeric_range(const char *input, long min_value, long max_value, const char *value_name, long *result) {
	if (!validate_numeric_only(input, value_name)) {
		return 0;
	}

	char *endptr;
	long value = strtol(input, &endptr, 10);

	if (*endptr != '\0') {
		char msg[256];
		snprintf(msg, sizeof(msg), "Invalid %s format", value_name);
		ui_show_message("Error", msg);
		return 0;
	}

	if (value < min_value) {
		char msg[256];
		snprintf(msg, sizeof(msg), "%s must be at least %ld", value_name, min_value);
		ui_show_message("Error", msg);
		return 0;
	}

	if (value > max_value) {
		char msg[256];
		snprintf(msg, sizeof(msg), "%s cannot exceed %ld", value_name, max_value);
		ui_show_message("Error", msg);
		return 0;
	}

	*result = value;
	return 1;
}

int validate_buffer_size(const char *input, uint8_t *buffer_size) {
	long value;
	if (!validate_numeric_range(input, MIN_BUFFER_SIZE, MAX_BUFFER_SIZE, "Buffer size", &value)) {
		return 0;
	}

	if (value < 4) {
		char warning_msg[256];
		snprintf(warning_msg, sizeof(warning_msg),
				 "Warning: Buffer size %ld KB is very small. Recommended minimum is 4 KB.", value);
		ui_show_message("Warning", warning_msg);
	}

	*buffer_size = (uint8_t) value;
	return 1;
}

int validate_timeout(const char *input, uint8_t *timeout_value) {
	long value;
	if (!validate_numeric_range(input, MIN_TIMEOUT, MAX_TIMEOUT, "Timeout", &value)) {
		return 0;
	}

	*timeout_value = (uint8_t) value;
	return 1;
}

int validate_alphanumeric(const char *input, const char *field_name) {
	if (!input || strlen(input) == 0) {
		char msg[256];
		snprintf(msg, sizeof(msg), "%s cannot be empty", field_name);
		ui_show_message("Error", msg);
		return 0;
	}

	for (size_t i = 0; i < strlen(input); i++) {
		if (!isalnum((unsigned char) input[i])) {
			char msg[256];
			snprintf(msg, sizeof(msg), "%s can only contain letters and numbers", field_name);
			ui_show_message("Error", msg);
			return 0;
		}
	}

	return 1;
}

int validate_ipv4_address(const char *ip_address) {
	if (!ip_address || strlen(ip_address) == 0) {
		ui_show_message("Error", "IP address cannot be empty");
		return 0;
	}

	struct sockaddr_in sa;
	int result = inet_pton(AF_INET, ip_address, &(sa.sin_addr));

	if (result != 1) {
		ui_show_message("Error", "Invalid IPv4 address format");
		return 0;
	}

	return 1;
}

int validate_port(const char *port_str, uint16_t *port) {
	long value;
	if (!validate_numeric_range(port_str, MIN_PORT, MAX_PORT, "Port", &value)) {
		return 0;
	}

	*port = (uint16_t) value;
	return 1;
}