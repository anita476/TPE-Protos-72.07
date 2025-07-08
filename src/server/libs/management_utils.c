#include "management_utils.h"
#include "logger.h"
#include <arpa/inet.h>
#include <string.h>

void write_response_header(buffer *wb, uint8_t status, uint8_t command, uint8_t arg) {
    if (buffer_writeable_bytes(wb) < 4) {
        log(ERROR, "[MANAGEMENT] No buffer space for 4-byte response header");
        return;
    }
    
    buffer_write(wb, CALSETTING_VERSION);  // VER
    buffer_write(wb, status);              // STATUS
    buffer_write(wb, command);             // CMD
    buffer_write(wb, arg);                 // ARG/COUNT/RESERVED
}

void write_simple_response_header(buffer *wb, uint8_t status, uint8_t command) {
    // Use 0 as reserved byte for simple responses
    return write_response_header(wb, status, command, 0);
}
void write_uint8(buffer *wb, uint8_t value) {
    buffer_write(wb, value);
}

void write_uint16(buffer *wb, uint16_t value) {
    uint16_t net_value = htons(value);
    buffer_write(wb, (net_value >> 8) & 0xFF);
    buffer_write(wb, net_value & 0xFF);
}

void write_uint32(buffer *wb, uint32_t value) {
    uint32_t net_value = htonl(value);
    buffer_write(wb, (net_value >> 24) & 0xFF);
    buffer_write(wb, (net_value >> 16) & 0xFF);
    buffer_write(wb, (net_value >> 8) & 0xFF);
    buffer_write(wb, net_value & 0xFF);
}

void write_uint64(buffer *wb, uint64_t value) {
    uint64_t net_value = htobe64(value);
    for (int i = 7; i >= 0; i--) {
        buffer_write(wb, (net_value >> (i * 8)) & 0xFF);
    }
}
