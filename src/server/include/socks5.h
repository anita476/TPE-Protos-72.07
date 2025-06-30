//
// Created by nep on 6/29/25.
//

#ifndef SOCKS5_H
#define SOCKS5_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>

//capaz se le puede agregar el clientSocket aca en vez de en el main pero X
typedef struct socks5_request {
	uint8_t cmd; //command
	uint8_t atyp;
	char * dstAddress; //destination address
	uint16_t dstPort; //destination port

}socks5_request;

typedef struct socks5_response {
	uint8_t rep; //replyCode
	uint8_t atyp; //address type
	struct sockaddr * boundAddress; //bound address
	socklen_t boundLength;
	uint16_t boundPort; //bound port
	uint8_t remoteSocketFd; //active socket between server and destination
}socks5_response;

int handleHello(int clientSock);
int handleRequest(int clientSock, socks5_request *request);
int sendReply(socks5_response *response);
int connectToDestination(socks5_request *request, socks5_response *response);
#endif //SOCKS5_H
