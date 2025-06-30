//
// Created by nep on 6/29/25.
//

#ifndef TCPSERVERUTILS_H
#define TCPSERVERUTILS_H

#include <stdio.h>
#include <sys/socket.h>


// Create, bind, and listen a new TCP server socket
int setupTCPServerSocket(const char *service);

// Accept a new TCP connection on a server socket
int acceptTCPConnection(int servSock);

// Handle new TCP client
void handleTCPEchoClient(int clntSocket);
#endif //TCPSERVERUTILS_H
