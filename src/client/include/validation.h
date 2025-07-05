#ifndef VALIDATION_H
#define VALIDATION_H

#include <stdint.h>

int validate_input(const char *input, int min_len, int max_len, const char *error_prefix);

int validate_username(const char *username);

int validate_password(const char *password);

int validate_buffer_size(const char *input, uint8_t *buffer_size);

int validate_timeout(const char *input, uint8_t *timeout_value);

int validate_numeric_range(const char *input, long min_value, long max_value, const char *value_name, long *result);

int validate_alphanumeric(const char *input, const char *field_name);

int validate_numeric_only(const char *input, const char *field_name);

int validate_ipv4_address(const char *ip_address);

int validate_port(const char *port_str, uint16_t *port);

#endif