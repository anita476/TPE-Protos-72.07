#include "include/management.h"
#include "include/logger.h"

/*************************************Proper action*******************************************************/
/**************Fetch the info or change the config itself (called by the protocol handlers)***************/
static void handle_config_command(COMMAND cmd);

static void handle_config_command(COMMAND cmd) {
	switch (cmd) {
		case CMD_BUFFER_SOCKS5:
			break;
		case CMD_TIMEOUT:
			break;
		case CMD_ACCESS_LOG:
			break;
		case CMD_METRICS:
			break;
		default:
			log(ERROR, "Unknown command received in management handler: %d", cmd);
			break;
	}
}