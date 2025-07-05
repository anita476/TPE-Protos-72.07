#ifndef PAGINATION_H
#define PAGINATION_H

#include <stdint.h>

typedef struct {
    const char *title_format;
    const char *no_data_message;
    const char *no_more_data_message;
    const char *nav_prompt;
    void *(*fetch_func)(int items_per_page, int offset, int socket);    // Function to fetch data
    void (*display_func)(void *data, int count, int page);              // Function to display data
    void (*free_func)(void *data);                                      // Function to free data
    int (*count_func)(void *data);                                      // Function to count data
} pagination_config_t;

void handle_pagination(const pagination_config_t *config, int socket, int items_per_page);

#endif