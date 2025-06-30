
#include "../include/logger.h"
#include "../include/util.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define MAXPENDING 5 // Maximum outstanding connection requests
#define BUFSIZE 256
#define MAX_ADDR_BUFFER 128

static char addrBuffer[MAX_ADDR_BUFFER];
/*
 ** Se encarga de resolver el número de puerto para service (puede ser un string con el numero o el nombre del servicio)
 ** y crear el socket pasivo, para que escuche en cualquier IP, ya sea v4 o v6
 */
int setupTCPServerSocket(const char *service) {
	// Construct the server address structure
	struct addrinfo addrCriteria;                   // Criteria for address match
	memset(&addrCriteria, 0, sizeof(addrCriteria)); // Zero out structure
	addrCriteria.ai_family = AF_UNSPEC;             // Any address family
	addrCriteria.ai_flags = AI_PASSIVE;             // Accept on any address/port
	addrCriteria.ai_socktype = SOCK_STREAM;         // Only stream sockets
	addrCriteria.ai_protocol = IPPROTO_TCP;         // Only TCP protocol

	struct addrinfo *servAddr; 			// List of server addresses
	///getaddrinfo con NULL toma la interfaz 0.0.0.0 osea que soy yo. si me quiero conectar a otra persona ahi
	///deberia ir nombre de dominio / ip de la otra persona por lo que entiendo
	int rtnVal = getaddrinfo(NULL, service, &addrCriteria, &servAddr);
	if (rtnVal != 0) {
		log(FATAL, "getaddrinfo() failed %s", gai_strerror(rtnVal));
		return -1;
	}
	///&addrCriteria es un puntero a la estructura que tiene los "hints". estos hints son basicamente filtros que
	///usa getAddrInfo para filtrar y reducir las direcciones posibles que te devuelve para matchear con los filtros.
	///servAddr va a ser el resultado que usa la misma estructura que las hints, y tiene un puntero al siguiente
	///entonces tenes una lista con todos los resultaods.

	int servSock = -1;
	// Intentamos ponernos a escuchar en alguno de los puertos asociados al servicio, sin especificar una IP en particular
	// Iteramos y hacemos el bind por alguna de ellas, la primera que funcione, ya sea la general para IPv4 (0.0.0.0) o IPv6 (::/0) .
	// Con esta implementación estaremos escuchando o bien en IPv4 o en IPv6, pero no en ambas
	for (struct addrinfo *addr = servAddr; addr != NULL && servSock == -1; addr = addr->ai_next) {
		errno = 0;
		// Create a TCP socket. esta usando los datos que le devolvio getAddrInfo
		servSock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
		if (servSock < 0) {
			log(DEBUG, "Cant't create socket on %s : %s ", printAddressPort(addr, addrBuffer), strerror(errno));
			continue;       // Socket creation failed; try next address
		}

		//ahora va a hacer el bind, que dice que ese fileDescriptor
		//va a estar en tal ip:puerto. addr->ai_addr es un puntero a una estructura sockadrr que supuestamente
		//contiene una direccion IP y un puerto todo junto. ai_addr es generico y se puede
		//castear a sockaddr_in o sockaddr_in6 dependiendo de si es ipv4 o ipv6.
		//literalmente seria
		//struct sockaddr_in * sockadr = (struct sockaddr_in *) addr->ai_addr;
		// Bind to ALL the address and set socket to listen
		if (bind(servSock, addr->ai_addr, addr->ai_addrlen) == 0 && listen(servSock, MAXPENDING) == 0) {
			// Print local address of socket
			struct sockaddr_storage localAddr;
			socklen_t addrSize = sizeof(localAddr);
			if (getsockname(servSock, (struct sockaddr *) &localAddr, &addrSize) >= 0) {
				printSocketAddress((struct sockaddr *) &localAddr, addrBuffer);
				log(INFO, "Binding to %s", addrBuffer);
			}
		} else {
			log(DEBUG, "Cant't bind %s", strerror(errno));
			close(servSock);  // Close and try with the next one
			servSock = -1;
		}
	}

	///para memory leaks, liberar la estructura de los resultados
	freeaddrinfo(servAddr);

	return servSock;
}

int acceptTCPConnection(int servSock) {
	struct sockaddr_storage clntAddr; // Client address
	// Set length of client address structure (in-out parameter)
	socklen_t clntAddrLen = sizeof(clntAddr);

	// Wait for a client to connect. este accept me va a bloquear hasta que alguien se conecte
	int clntSock = accept(servSock, (struct sockaddr *) &clntAddr, &clntAddrLen);
	if (clntSock < 0) {
		log(ERROR, "accept() failed");
		return -1;
	}

	// clntSock is connected to a client!
	printSocketAddress((struct sockaddr *) &clntAddr, addrBuffer);
	log(INFO, "Handling client %s", addrBuffer);

	return clntSock;
}

int handleTCPEchoClient(int clntSocket) {
	char buffer[BUFSIZE]; // Buffer for echo string
	// Receive message from client
	ssize_t numBytesRcvd = recv(clntSocket, buffer, BUFSIZE, 0);
	if (numBytesRcvd < 0) {
		log(ERROR, "recv() failed");
		return -1;   // TODO definir codigos de error
	}

	// Send received string and receive again until end of stream
	while (numBytesRcvd > 0) { // 0 indicates end of stream
		// Echo message back to client
		ssize_t numBytesSent = send(clntSocket, buffer, numBytesRcvd, 0);
		if (numBytesSent < 0) {
			log(ERROR, "send() failed");
			return -1;   // TODO definir codigos de error
		}
		else if (numBytesSent != numBytesRcvd) {
			log(ERROR, "send() sent unexpected number of bytes ");
			return -1;   // TODO definir codigos de error
		}

		// See if there is more data to receive
		numBytesRcvd = recv(clntSocket, buffer, BUFSIZE, 0);
		if (numBytesRcvd < 0) {
			log(ERROR, "recv() failed");
			return -1;   // TODO definir codigos de error
		}
	}

	close(clntSocket);
	return 0;
}

