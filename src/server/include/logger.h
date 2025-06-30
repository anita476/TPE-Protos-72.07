

#ifndef LOGGER_H
#define LOGGER_H

#include <stdio.h>
#include <stdlib.h>

/*
*  Macros y funciones simples para log de errores.
*  EL log se hace en forma simple
*  Alternativa: usar syslog para un log mas completo. Ver sección 13.4 del libro de  Stevens
*/

typedef enum {DEBUG=0, INFO, ERROR, FATAL} LOG_LEVEL;

extern LOG_LEVEL current_level;

/**
*  Minimo nivel de log a registrar. Cualquier llamada a log con un nivel mayor a newLevel sera ignorada
**/
void setLogLevel(LOG_LEVEL newLevel);

char * levelDescription(LOG_LEVEL level);

// Debe ser una macro para poder obtener nombre y linea de archivo.
// fprintf (stderr, "%s %s %s: %s:%d, ",__DATE__, __TIME__, levelDescription(level), __FILE__, __LINE__); <- took out date and time

#define log(level, fmt, ...)   {if(level >= current_level) {\
    const char *color; \
    switch (level) { \
        case DEBUG: color = "\033[34m"; break; /* Blue */ \
        case INFO: color = "\033[32m"; break;  /* Green */ \
        case ERROR: color = "\033[33m"; break; /* Yellow */ \
        case FATAL: color = "\033[31m"; break; /* Red */ \
        default: color = "\033[0m"; break; \
    } \
fprintf (stderr, "%s%s: %s:%d, ", color, levelDescription(level), __FILE__, __LINE__); \
fprintf(stderr, fmt, ##__VA_ARGS__); \
fprintf(stderr,"\033[0m\n"); /* Reset color */ \
if ( level==FATAL) exit(1);}}


#endif //LOGGER_H
