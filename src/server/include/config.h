#ifndef _CONFIG_H_
#define _CONFIG_H_
#include <time.h>
#include "../../shared/include/calsetting_protocol.h"

// SOCKS5 configuration 
size_t g_socks5_buffer_size = 4096; // default buffer size (units bytes) 4KB
struct timespec g_select_timeout = {10,0}; // 10 second timeout
int g_connection_timeout = 30;       // 30 seconds

// Management configuration
size_t g_management_buffer_size = 8192; // 8KB management buffer (handles ~13 logs) 
// int g_logs_per_page = 20;

#endif