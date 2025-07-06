#ifndef _CONFIG_H_
#define _CONFIG_H_
#include <time.h>

size_t g_socks5_buffer_size = 4096; // default buffer size (units bytes)
struct timespec g_select_timeout = {10,0};
int g_connection_timeout = 30;       // 30 seconds default

#endif