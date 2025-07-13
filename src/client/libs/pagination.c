// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
#include "../include/pagination.h"
#include "../include/ui_adapter.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void handle_pagination(const pagination_config_t *config, int socket, int items_per_page) {
	printf("SOCKET: %d\n", socket);
	if (socket < 0) {
		ui_show_message("Error", "No server connection");
		return;
	}

	int current_page = 0;
	int continue_browsing = 1;

	while (continue_browsing) {
		errno = 0; // Reset errno before fetching data
		void *data = config->fetch_func(items_per_page, current_page * items_per_page, socket);
		if (errno == ENOTCONN) {
			return;
		}

		if (data == NULL) {
			const char *message = (current_page == 0) ? config->no_data_message : config->no_more_data_message;
			ui_show_message("Info", message);
			break;
		}

		int item_count = config->count_func(data);

		config->display_func(data, item_count, current_page);

		char nav_items[4][2][64];
		int nav_count = 0;

		if (current_page > 0) {
			snprintf(nav_items[nav_count][0], 64, "%d", nav_count + 1);
			snprintf(nav_items[nav_count][1], 64, "Previous page");
			nav_count++;
		}

		if (item_count == items_per_page) {
			snprintf(nav_items[nav_count][0], 64, "%d", nav_count + 1);
			snprintf(nav_items[nav_count][1], 64, "Next page");
			nav_count++;
		}

		snprintf(nav_items[nav_count][0], 64, "%d", nav_count + 1);
		snprintf(nav_items[nav_count][1], 64, "Back to menu");
		nav_count++;

		char title[128];
		snprintf(title, sizeof(title), config->title_format, current_page + 1);

		int selection = ui_get_menu_selection(title, config->nav_prompt, nav_items, nav_count);

		if (selection == -1) {
			continue_browsing = 0;
		} else if (current_page > 0 && selection == 1) {
			current_page--;
		} else if (item_count == items_per_page &&
				   ((current_page > 0 && selection == 2) || (current_page == 0 && selection == 1))) {
			current_page++;
		} else {
			continue_browsing = 0;
		}

		config->free_func(data);
	}
}