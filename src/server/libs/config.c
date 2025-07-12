// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
#include "../include/config.h"

size_t g_socks5_buffer_size = 4096;
struct timespec g_select_timeout = {10, 0};

int g_connection_timeout = 30;
size_t g_management_buffer_size = 8192; // default management size, maybe could add config to change it later

struct user *users = NULL; // global users
uint8_t nusers = 0;