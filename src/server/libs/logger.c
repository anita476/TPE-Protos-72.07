// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
#include "../include/logger.h"
#include "../../shared/include/calsetting_protocol.h"
#include <string.h>
#include <time.h>

// SOCKS5 / management logging system
log_entry_t recent_logs[MAX_RECENT_LOGS];
int log_count = 0;
int log_index = 0; // Circular buffer index

// Global logger
LOG_LEVEL current_level = DEBUG;
bool disabled = false;

void setLogLevel(LOG_LEVEL newLevel) {
	if (newLevel >= DEBUG && newLevel <= FATAL)
		current_level = newLevel;
}
void disableLogging() {
	disabled = true;
}
void enableLogging() {
	disabled = false;
}

char *levelDescription(LOG_LEVEL level) {
	static char *description[] = {"DEBUG", "INFO", "ERROR", "FATAL"};
	if (level < DEBUG || level > FATAL)
		return "";
	return description[level];
}

void add_access_log(const char *username, const char *client_ip, uint16_t client_port, uint8_t dest_atyp,
					const char *dest_addr, uint16_t dest_port, uint8_t status_code) {
	log_entry_t *entry = &recent_logs[log_index];
	memset(entry, 0, sizeof(log_entry_t));

	time_t now = time(NULL);
	struct tm *tm_info = localtime(&now);
	strftime(entry->date, sizeof(entry->date), "%Y-%m-%dT%H:%M:%S", tm_info);

	if (username) {
		strncpy(entry->username, username, sizeof(entry->username) - 1);
		entry->ulen = strlen(entry->username);
	} else {
		strcpy(entry->username, "anonymous");
		entry->ulen = 9;
	}

	// Register type (always 'A' for access)
	entry->register_type = 'A';

	if (client_ip) {
		strncpy(entry->origin_ip, client_ip, sizeof(entry->origin_ip) - 1);
	}
	entry->origin_port = client_port;

	entry->destination_ATYP = dest_atyp;
	if (dest_addr) {
		strncpy(entry->destination_address, dest_addr, sizeof(entry->destination_address) - 1);
	}
	entry->destination_port = dest_port;

	entry->status_code = status_code;

	// Update circular buffer
	log_index = (log_index + 1) % MAX_RECENT_LOGS;
	if (log_count < MAX_RECENT_LOGS) {
		log_count++;
	}

	// Also log to existing logger for visibility
	log(INFO, "[ACCESS] %s@%s:%d -> %s:%d (status=0x%02x)", entry->username, client_ip ? client_ip : "unknown",
		client_port, dest_addr ? dest_addr : "unknown", dest_port, status_code);
}
