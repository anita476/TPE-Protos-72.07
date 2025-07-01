#ifndef _SOCKS5_UTILS_H_
#define _SOCKS5_UTILS_H_

#include "socks5_constants.h"
#include <stdint.h>

uint8_t map_getaddrinfo_error_to_socks5(int gai_error);
uint8_t map_connect_error_to_socks5(int connect_errno);

struct addrinfo *create_ipv6_addrinfo(const uint8_t ip[16], uint16_t port);
struct addrinfo *create_ipv4_addrinfo(uint32_t ip_host_order, uint16_t port);

#endif