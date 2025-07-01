#ifndef METRICS_H
#define METRICS_H

#include <stdint.h>

typedef struct {
    // Connections
    uint64_t total_connections;        
    uint32_t concurrent_connections;   
    uint32_t max_concurrent_connections; 
    
    // Bytes transferred
    uint64_t bytes_transferred_in;     
    uint64_t bytes_transferred_out;    
    uint64_t total_bytes_transferred;      
} server_metrics;

void metrics_init(void);
void metrics_increment_connection(void);
void metrics_decrement_connection(void);
void metrics_add_bytes_in(uint64_t bytes);
void metrics_add_bytes_out(uint64_t bytes);
server_metrics* metrics_get(void);
void metrics_cleanup(void);

#endif