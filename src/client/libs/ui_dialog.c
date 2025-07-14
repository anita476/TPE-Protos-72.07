// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "../include/client_constants.h"
#include "../include/ui_dialog.h"

static int count_lines(const char *text) {
	int lines = 1;
	for (const char *p = text; *p; p++) {
		if (*p == '\n') {
			lines++;
		}
	}
	return lines;
}

static int read_temp_file_line(char *buffer, size_t buffer_size) {
	if (access("/tmp", W_OK) != 0) {
		perror("Cannot write to /tmp");
		return 0;
	}
	FILE *file = fopen(TEMP_FILE, "r");
	int ok = 0;
	if (file) {
		if (fgets(buffer, buffer_size, file)) {
			char *newline = strchr(buffer, '\n');
			if (newline)
				*newline = '\0';
			ok = 1;
		}
		fclose(file);
	}
	remove(TEMP_FILE);
	return ok;
}

static char *read_temp_file_as_string(char *buffer, size_t buffer_size) {
	if (read_temp_file_line(buffer, buffer_size)) {
		return buffer;
	}
	return NULL;
}

static int read_temp_file_as_int(void) {
	char result[TEMP_RESULT_SIZE];
	if (read_temp_file_line(result, sizeof(result))) {
		return atoi(result);
	}
	return -1;
}

void ui_dialog_show_message(const char *title, const char *message) {
	char command[BUFFER_M];
	int lines = count_lines(message);

	snprintf(command, sizeof(command), "dialog --title \"%s\" --msgbox \"%s\" %d %d 2>/dev/null", title, message,
			 (lines > DIALOG_MSGBOX_LINE_THRESHOLD) ? DIALOG_MSGBOX_HEIGHT_LONG : DIALOG_MSGBOX_HEIGHT_SHORT,
			 DIALOG_MSGBOX_WIDTH);
	system(command);
}

char *ui_dialog_get_input(const char *title, const char *text, int hidden) {
	static char result[MAX_INPUT];
	char command[BUFFER_S];

	if (hidden) {
		snprintf(command, sizeof(command), "dialog --title \"%s\" --passwordbox \"%s\" %d %d 2>%s", title, text,
				 DIALOG_INPUTBOX_HEIGHT, DIALOG_INPUTBOX_WIDTH, TEMP_FILE);
	} else {
		snprintf(command, sizeof(command), "dialog --title \"%s\" --inputbox \"%s\" %d %d 2>%s", title, text,
				 DIALOG_INPUTBOX_HEIGHT, DIALOG_INPUTBOX_WIDTH, TEMP_FILE);
	}

	int ret = system(command);
	if (ret == 0) {
		return read_temp_file_as_string(result, sizeof(result));
	}
	remove(TEMP_FILE);
	return NULL;
}

int ui_dialog_get_menu_selection(const char *title, const char *text, char items[][2][64], int count) {
	char command[BUFFER_XXL];
	char menu_items[BUFFER_XL] = "";

	for (int i = 0; i < count; i++) {
		char item[BUFFER_S];
		snprintf(item, sizeof(item), "\"%s\" \"%s\" ", items[i][0], items[i][1]);
		strncat(menu_items, item, sizeof(menu_items) - strlen(menu_items) - 1);
	}

	int menu_height = count + DIALOG_MENU_EXTRA_HEIGHT;
	int menu_width = DIALOG_MENU_WIDTH;

	snprintf(command, sizeof(command), "dialog --title \"%s\" --menu \"%s\" %d %d %d %s 2>%s", title, text,
			 menu_height > DIALOG_MENU_MAX_HEIGHT ? DIALOG_MENU_MAX_HEIGHT : menu_height, menu_width, count, menu_items,
			 TEMP_FILE);

	int ret = system(command);
	if (ret == 0) {
		return read_temp_file_as_int();
	}
	remove(TEMP_FILE);
	return -1;
}

int ui_dialog_get_confirmation(const char *title, const char *text) {
	char command[BUFFER_S];
	snprintf(command, sizeof(command), "dialog --title \"%s\" --yesno \"%s\" %d %d 2>/dev/null", title, text,
			 DIALOG_CONFIRM_HEIGHT, DIALOG_CONFIRM_WIDTH);
	return (system(command) == 0);
}