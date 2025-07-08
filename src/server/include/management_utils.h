#ifndef MANAGEMENT_UTILS_H
#define MANAGEMENT_UTILS_H

#include "management.h"

// Standard 4-byte response header: VER | STATUS | CMD | ARG
void write_response_header(buffer *wb, uint8_t status, uint8_t command, uint8_t arg);
void write_simple_response_header(buffer *wb, uint8_t status, uint8_t command);

// Network byte order helpers
void write_uint8(buffer *wb, uint8_t value);
void write_uint16(buffer *wb, uint16_t value);
void write_uint32(buffer *wb, uint32_t value);
void write_uint64(buffer *wb, uint64_t value);

// Permission check that handles response automatically
bool require_admin_permission(management_session *session, uint8_t command);

#endif