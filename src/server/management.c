#include "include/management.h"
#include "include/config.h"
#include "include/logger.h"

/*************************************Proper action*******************************************************/
/**************Fetch the info or change the config itself (called by the protocol handlers)***************/
static void handle_config_command(COMMAND cmd, const char *arg, const int argc);

// char * is the easiest since the user writes to stdin
static void handle_config_command(COMMAND cmd, const char *arg, const int argc) {
	switch (cmd) {
		case CMD_BUFFER_SOCKS5:
			if (argc != 1) {
				log(ERROR, "CMD_BUFFER_SOCKS5 requires one argument, got %d", argc);
				return;
			}
			size_t new_size = strtoul(arg, NULL, 10);
			if (new_size > 0) { // TODO maybe have a min and max to protect the server integrity :p
				log(INFO, "Changing SOCKS5 buffer size to %zu bytes", new_size);
				g_socks5_buffer_size = new_size;
			}
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