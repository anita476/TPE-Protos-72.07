#ifndef _CONFIG_H_
#define _CONFIG_H_

#include "../../shared/include/calsetting_protocol.h"
#include <time.h>

extern size_t g_socks5_buffer_size;
extern struct timespec g_select_timeout;
extern int g_connection_timeout;
extern size_t g_management_buffer_size;

#endif
