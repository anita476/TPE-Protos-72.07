#ifndef METRICS_H
#define METRICS_H

#include <stdint.h>
#include <time.h>

typedef enum {
    ERROR_TYPE_NETWORK,      // Network/connection errors
    ERROR_TYPE_PROTOCOL,     // Protocol/parsing errors
    ERROR_TYPE_AUTH,         // Authentication/authorization errors
    ERROR_TYPE_SYSTEM,       // System/resource errors
    ERROR_TYPE_TIMEOUT,      // Timeout errors
    ERROR_TYPE_OTHER         // Other unspecified errors
} error_type_t;

typedef struct {
    // Connections
    uint64_t total_connections;   
    uint32_t concurrent_connections;
    uint32_t max_concurrent_connections;
    
    // Bytes transferred
    uint64_t bytes_transferred_in;
    uint64_t bytes_transferred_out;
    uint64_t total_bytes_transferred;

    // Errors
    uint32_t error_counts[ERROR_TYPE_OTHER + 1];
    uint32_t total_errors;

    // Time
    time_t start_time;
} server_metrics;

void metrics_init(void);
void metrics_increment_connections(void);
void metrics_decrement_connections(void);
void metrics_add_bytes_in(uint64_t bytes);
void metrics_add_bytes_out(uint64_t bytes);
void metrics_increment_errors(error_type_t error_type);
server_metrics* metrics_get(void);
void metrics_cleanup(void);

#endif