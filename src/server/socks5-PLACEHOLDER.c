
// Socks5 functions implementation

#include "include/socks5.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>

/***************************************************** Use ONLY to understand socks protocol
******************************************************* these functions are BLOCKING !!! */

/// este es el primer paquete que tiene la pinta
/*
|VER | NMETHODS | METHODS  |
+----+----------+----------+
| 1  |    1     | 1 to 255 |
+----+----------+----------+
esto enrealidad se lee todo junto uno atras del otro. por convencion sabemos que el primer byte es la version del
protocolo (5), el segundo es la cantidad de metodos de autenticacion que soporta el cliente y luego vienen los metodos
de autenticacion en si que es un byte atras de otro (cada metodo por convencion es un valor distinto, 0 es para no auth,
2 es usernamePassword)


luego yo tengo que devolver un paquete con la version del protocolo (5) y el metodo de autenticacion que elegido
(en este caso 0)
*/
int handleHello(int clientSock) {
	/// leo 2 bytes, serian version del protocolo y NMethods.
	uint8_t buf[258];
	int n = recv(clientSock, buf, 2, 0);
	if (n != 2 || buf[0] != 0x05) {
		/* error */
	}
	int nmethods = buf[1];

	/// leo nmethod bytes y voy a esperar que el cliente acepte noAuth, sino exploto (mando FF como metodo que quiere
	/// decir todo mal)
	n = recv(clientSock, buf, nmethods, 0);
	bool noAuth = false;
	for (int i = 0; i < nmethods; i++) {
		if (buf[i] == 0x00) {
			noAuth = true;
		}
	}
	uint8_t reply[2] = {0x05, noAuth ? 0x00 : 0xFF};
	send(clientSock, reply, 2, 0);
	if (!noAuth) {
		/// en este caso cierro la conexion porque el cliente no acepta noAuth
		close(clientSock);
		return 1;
	}
	return 0;
}
/*
 Ahora vamos a esperar un paquete "request" con esta pinta
		+----+-----+-------+------+----------+----------+
		|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
		+----+-----+-------+------+----------+----------+
		| 1  |  1  | X'00' |  1   | Variable |    2     |
		+----+-----+-------+------+----------+----------+
	 Where:
		  o  VER    protocol version: X'05'
		  o  CMD
			 o  CONNECT X'01'
			 o  BIND X'02'
			 o  UDP ASSOCIATE X'03'
		  o  RSV    RESERVED
		  o  ATYP   address type of following address
			 o  IP V4 address: X'01'
			 o  DOMAINNAME: X'03'
			 o  IP V6 address: X'04'
		  o  DST.ADDR       desired destination address
		  o  DST.PORT desired destination port in network octet
			 order

	si es un nombre de dominio, el rfc aclara especificamente que el primer byte se usa para la longitud del string
	y que NO esta null terminated
 */
// la info queda toda en la request struct
int handleRequest(int clientSock, socks5_request *request) {
	// leo hasta ATYP inclusive y chequeo
	uint8_t hdr[4];
	if (recv(clientSock, hdr, 4, 0) != 4 || hdr[0] != 0x05) {
		close(clientSock);
		return 1;
	}

	request->cmd = hdr[1];
	request->atyp = hdr[3];
	const uint8_t atyp = request->atyp;
	char *dstAddr = request->dstAddress;
	uint16_t dstPort;

	// Me fijo si es ipv4 o ipv6 o un dominio segun la flag que me mando el cliente
	// no se si estoy usando bien el inet_ntop. supongo que me va a dejar la info en dstAddr que es el mismo lugar que
	// la struct tonces esta bien
	if (atyp == 0x01) { // IPv4
		uint32_t addr4;
		recv(clientSock, &addr4, 4, 0);
		inet_ntop(AF_INET, &addr4, dstAddr, sizeof(dstAddr));
	} else if (atyp == 0x03) { // nombre de dominio.
		uint8_t len;
		recv(clientSock, &len, 1, 0);
		recv(clientSock, dstAddr, len, 0);
		dstAddr[len] = '\0';
	} else if (atyp == 0x04) { // IPv6
		recv(clientSock, dstAddr, 16, 0);
		inet_ntop(AF_INET6, dstAddr, dstAddr, sizeof(dstAddr));
	} else {
		close(clientSock);
		return 1;
	}
	recv(clientSock, &(request->dstPort), 2, 0);

	/// hay que convertir de network short a host short, es lo del little endian y big endian pero no se si
	/// es este o tengo que usar htons, aunque creo que ntohs esta bien
	request->dstPort = ntohs(request->dstPort);

	return 0;
}

int connectToDestination(socks5_request *request, socks5_response *response) {
	struct addrinfo addrCriteria = {0}; // Criteria for address match
	switch (request->atyp) {
		case 0x01:
			addrCriteria.ai_family = AF_INET;
			break;
		case 0x04:
			addrCriteria.ai_family = AF_INET6;
			break;
		default:
			addrCriteria.ai_family = AF_UNSPEC;
	}
	addrCriteria.ai_socktype = SOCK_STREAM; // Only stream sockets
	addrCriteria.ai_protocol = IPPROTO_TCP;
	addrCriteria.ai_flags = 0;
	char portBuff[2];
	snprintf(portBuff, 2, "%d", request->dstPort);

	struct addrinfo *addrInfoResponse;
	int rtnVal = getaddrinfo(request->dstAddress, portBuff, &addrCriteria, &addrInfoResponse);
	if (rtnVal != 0) {
		printf("ERROR CONNECTING GETADDRINFO");
		return 1;
	}

	for (struct addrinfo *addr = addrInfoResponse; addr != NULL; addr = addr->ai_next) {
		struct sockaddr *address = addr->ai_addr;
		int sock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);

		// busca que hace getsockname pero para mandar el paquete de respuesta necesito un sockadrr para el bnd.addr
		// y parece que esa funcion me da lo que necesito
		if (connect(sock, addr->ai_addr, addr->ai_addrlen) == 0) {
			freeaddrinfo(addrInfoResponse);
			response->remoteSocketFd = sock;
			getsockname(response->remoteSocketFd, response->boundAddress, &(response->boundLength));
			return 0;
		}
		close(sock);
	}
	freeaddrinfo(addrInfoResponse);
	return 1;
}

/*
		*+----+-----+-------+------+----------+----------+
		|VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
		+----+-----+-------+------+----------+----------+
		| 1  |  1  | X'00' |  1   | Variable |    2     |
		+----+-----+-------+------+----------+----------+
	 Where:
		  o  VER    protocol version: X'05'
		  o  REP    Reply field:
			 o  X'00' succeeded
			 o  X'01' general SOCKS server failure
			 o  X'02' connection not allowed by ruleset
			 o  X'03' Network unreachable
			 o  X'04' Host unreachable
			 o  X'05' Connection refused
			 o  X'06' TTL expired
			 o  X'07' Command not supported
			 o  X'08' Address type not supported
			 o  X'09' to X'FF' unassigned
		  o  RSV    RESERVED
		  o  ATYP   address type of following address
			 o  IP V4 address: X'01'
			 o  DOMAINNAME: X'03'
			 o  IP V6 address: X'04'
		  o  BND.ADDR       server bound address
		  o  BND.PORT       server bound port in network octet order

   Fields marked RESERVED (RSV) must be set to X'00'.
 */
int sendReply(socks5_response *response) {
	uint8_t resp[256]; // buffer para la respuesta

	/// lleno los 4 primeros bytes
	size_t len = 0;
	resp[len++] = 0x05;
	resp[len++] = response->rep;
	resp[len++] = 0x00;
	resp[len++] = response->atyp;

	// lleno la parte variable segun si es ipv4, ipv6 o dominio, primero la ip y dsp la respuesta
	if (response->boundAddress->sa_family == AF_INET) { // IPV4
		struct sockaddr_in *addr = (struct sockaddr_in *) response->boundAddress;
		// copy 4‑byte IPv4 address
		memcpy(&resp[len], &addr->sin_addr.s_addr, 4);
		len += 4;

		// copy 2‑byte port (already in network byte order)
		memcpy(&resp[len], &addr->sin_port, 2);
		len += 2;
	}

	else if (response->boundAddress->sa_family == AF_INET6) {
		// IPV6
		struct sockaddr_in6 *addr = (struct sockaddr_in6 *) response->boundAddress;
		// copy 16‑byte IPv6 address
		memcpy(&resp[len], &addr->sin6_addr.s6_addr, 16);
		len += 16;

		// copy 2‑byte port
		memcpy(&resp[len], &addr->sin6_port, 2);
		len += 2;
	} else if (response->atyp == 0x04) {
		/// aca estaria devolviendo el dominio
		return -1; // no implementado
	}
	ssize_t sent = send(response->remoteSocketFd, resp, len, 0);
	return (sent == (ssize_t) len) ? 0 : -1;
}
