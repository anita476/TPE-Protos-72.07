#ifndef _SOCKS5NIO_H_
#define _SOCKS5NIO_H_

void socksv5_pool_destroy(void);
void socksv5_passive_accept(struct selector_key *key);

#endif