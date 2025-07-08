#ifndef MANAGEMENT_UTILS_H
#define MANAGEMENT_UTILS_H

#include "management.h"

// Standard 4-byte response header: VER | STATUS | CMD | ARG
bool write_response_header(buffer *wb, uint8_t status, uint8_t command, uint8_t arg);
bool write_simple_response_header(buffer *wb, uint8_t status, uint8_t command);

// Network byte order helpers
bool response_write_uint16_be(buffer *wb, uint16_t value);
bool response_write_uint32_be(buffer *wb, uint32_t value);
bool response_write_uint64_be(buffer *wb, uint64_t value);

// Permission check that handles response automatically
bool require_admin_permission(management_session *session, uint8_t command);

#endif