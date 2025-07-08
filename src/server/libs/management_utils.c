#include "management_utils.h"
#include "logger.h"
#include <arpa/inet.h>
#include <string.h>

// TODO: change name to prepare_response_header
bool write_response_header(buffer *wb, uint8_t status, uint8_t command, uint8_t arg) {
    if (buffer_writeable_bytes(wb) < 4) {
        log(ERROR, "[MANAGEMENT] No buffer space for 4-byte response header");
        return false;
    }
    
    buffer_write(wb, CALSETTING_VERSION);  // VER
    buffer_write(wb, status);              // STATUS
    buffer_write(wb, command);             // CMD
    buffer_write(wb, arg);                 // ARG/COUNT/RESERVED

    return true;
}

bool write_simple_response_header(buffer *wb, uint8_t status, uint8_t command) {
    // Use 0 as reserved byte for simple responses
    return write_response_header(wb, status, command, 0);
}

// bool require_admin_permission(management_session *session, uint8_t command) {
//     if (session->user_type != USER_TYPE_ADMIN) {
//         log(INFO, "[MANAGEMENT] Non-admin user %s attempted admin command 0x%02x", 
//             session->username, command);
//         write_simple_response_header(session, RESPONSE_NOT_ALLOWED, command);
//         return false;
//     }
//     return true;
// }

// Keep the network byte order helpers - they're useful
bool response_write_uint16_be(buffer *wb, uint16_t value) {
    if (buffer_writeable_bytes(wb) < 2) {
        return false;
    }
    uint16_t net_value = htons(value);
    buffer_write(wb, (net_value >> 8) & 0xFF);
    buffer_write(wb, net_value & 0xFF);
    return true;
}

bool response_write_uint32_be(buffer *wb, uint32_t value) {
    if (buffer_writeable_bytes(wb) < 4) {
        return false;
    }
    uint32_t net_value = htonl(value);
    size_t writable;
    uint8_t *ptr = buffer_write_ptr(wb, &writable);
    memcpy(ptr, &net_value, 4);
    buffer_write_adv(wb, 4);
    return true;
}

bool response_write_uint64_be(buffer *wb, uint64_t value) {
    if (buffer_writeable_bytes(wb) < 8) {
        return false;
    }
    uint64_t net_value = htobe64(value);
    size_t writable;
    uint8_t *ptr = buffer_write_ptr(wb, &writable);
    memcpy(ptr, &net_value, 8);
    buffer_write_adv(wb, 8);
    return true;
}
