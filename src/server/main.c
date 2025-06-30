#include "../include/args.h"
#include "include/tcpServerUtils.h"
#include "include/socks5.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>



int main(int argc, char **argv) {
	struct socks5args args;
	printf("Starting server...\n");
	parse_args(argc, argv, &args);
	printf("Im serving\n");

	char * servPort = argv[1];

	///Socket pasivo del socks5 tcp. va a escuchar en el puerto 1080 que es el de sock5 (dsp lo podemos hacer variable o lo que quieran)
	int servSock = setupTCPServerSocket("1080");

	if (servSock < 0 )
		return 1;

	///por ahora vamos a una implementacion MEGA simple que me pueda manejar 1 cliente que se conecte y listo. y sin autenticacion
	int clntSock = acceptTCPConnection(servSock);

	if (handleHello(clntSock) != 0) {
		printf("Error en hello\n");
		exit(1);
	}
	socks5_request request = {0};
	char dstAddr[256];
	request.dstAddress = dstAddr;

	if (handleRequest(clntSock, &request) != 0) {
		printf("Error en request\n");
		exit(1);
	}
	//usar la request struct paara conectarme al sv
	socks5_response response = {0};
	struct sockaddr boundAddress = {0};
	response.boundAddress = &boundAddress;
	if (connectToDestination(&request, &response) != 0) {
		printf("Error conectando al destino\n");
		exit(1);
	}
	if (sendReply(&response) != 0) {
		printf("Error enviando reply\n");
		exit(1);
	}


	///TODO while 1 ahora tendria que leer lo que me mande el cliente por el clientSock
	///y lo que mande el server por el response.remoteSocketFd y basicamente hacer de man in the middle e irle
	///pasando a uno lo que dice el otro, maniana lo hago




	// while (1) { // Run forever
	// 	// Wait for a client to connect.
	// 	int clntSock = acceptTCPConnection(servSock);
	// 	if (clntSock < 0)
	// 		printf("error\n");
	// 	else {
	// 		handleTCPEchoClient(clntSock);
	// 	}
	// }
	return 0;
}

