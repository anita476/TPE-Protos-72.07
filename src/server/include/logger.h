

#ifndef LOGGER_H
#define LOGGER_H

#include "../../shared/include/calsetting_protocol.h" // for log_entry_t
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

/*
 *  Macros y funciones simples para log de errores.
 *  EL log se hace en forma simple
 *  Alternativa: usar syslog para un log mas completo. Ver sección 13.4 del libro de  Stevens
 */

typedef enum { DEBUG = 0, INFO, ERROR, FATAL } LOG_LEVEL;

extern LOG_LEVEL current_level;
extern bool disabled;

/**
 *  Minimo nivel de log a registrar. Cualquier llamada a log con un nivel mayor a newLevel sera ignorada
 **/
void setLogLevel(LOG_LEVEL newLevel);
void disableLogging();
void enableLogging();
char *levelDescription(LOG_LEVEL level);

int get_recent_logs(log_entry_t *buffer, int max_logs, int offset);
void add_access_log(const char *username, const char *client_ip, uint16_t client_port, uint8_t dest_atyp,
					const char *dest_addr, uint16_t dest_port, uint8_t status_code);

// Debe ser una macro para poder obtener nombre y linea de archivo.
// fprintf (stderr, "%s %s %s: %s:%d, ",__DATE__, __TIME__, levelDescription(level), __FILE__, __LINE__); <- took out
// date and time

#define log(level, fmt, ...)                                                                                           \
	{                                                                                                                  \
		if (!disabled && level >= current_level) {                                                                     \
			const char *color;                                                                                         \
			switch (level) {                                                                                           \
				case DEBUG:                                                                                            \
					color = "\033[34m";                                                                                \
					break; /* Blue */                                                                                  \
				case INFO:                                                                                             \
					color = "\033[32m";                                                                                \
					break; /* Green */                                                                                 \
				case ERROR:                                                                                            \
					color = "\033[33m";                                                                                \
					break; /* Yellow */                                                                                \
				case FATAL:                                                                                            \
					color = "\033[31m";                                                                                \
					break; /* Red */                                                                                   \
				default:                                                                                               \
					color = "\033[0m";                                                                                 \
					break;                                                                                             \
			}                                                                                                          \
			fprintf(stderr, "%s%s: %s:%d, ", color, levelDescription(level), __FILE__, __LINE__);                      \
			fprintf(stderr, fmt, ##__VA_ARGS__);                                                                       \
			fprintf(stderr, "\033[0m\n"); /* Reset color */                                                            \
			if (level == FATAL)                                                                                        \
				exit(1);                                                                                               \
		}                                                                                                              \
	}

#endif // LOGGER_H
