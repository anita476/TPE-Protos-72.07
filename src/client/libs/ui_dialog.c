#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ui_dialog.h"

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
    FILE *file = fopen(TEMP_FILE, "r");
    int ok = 0;
    if (file) {
        if (fgets(buffer, buffer_size, file)) {
            char *newline = strchr(buffer, '\n');
            if (newline) *newline = '\0';
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
    char result[16];
    if (read_temp_file_line(result, sizeof(result))) {
        return atoi(result);
    }
    return -1;
}

void ui_dialog_show_message(const char *title, const char *message) {
    char command[4096];
    int lines = count_lines(message);

    char formatted[3072];
    snprintf(formatted, sizeof(formatted), "\n%s", message);

    snprintf(command, sizeof(command), "dialog --title \"%s\" --msgbox \"%s\" %d 45 2>/dev/null",
             title, formatted, (lines > 6) ? 16 : 8);
    system(command);
}

char *ui_dialog_get_input(const char *title, const char *text, int hidden) {
    static char result[MAX_INPUT];
    char command[1024];

    if (hidden) {
        snprintf(command, sizeof(command), "dialog --title \"%s\" --passwordbox \"%s\" 8 35 2>%s", title, text, TEMP_FILE);
    } else {
        snprintf(command, sizeof(command), "dialog --title \"%s\" --inputbox \"%s\" 8 35 2>%s", title, text, TEMP_FILE);
    }

    int ret = system(command);
    if (ret == 0) {
        return read_temp_file_as_string(result, sizeof(result));
    }
    remove(TEMP_FILE);
    return NULL;
}

int ui_dialog_get_menu_selection(const char *title, const char *text, char items[][2][64], int count) {
    char command[8192];
    char menu_items[2048] = "";

    for (int i = 0; i < count; i++) {
        char item[256];
        snprintf(item, sizeof(item), "\"%s\" \"%s\" ", items[i][0], items[i][1]);
        strncat(menu_items, item, sizeof(menu_items) - strlen(menu_items) - 1);
    }

    int menu_height = count + 7;
    int menu_width = 45;

    snprintf(command, sizeof(command), "dialog --title \"%s\" --menu \"%s\" %d %d %d %s 2>%s",
             title, text, menu_height > 20 ? 20 : menu_height, menu_width, count, menu_items, TEMP_FILE);

    int ret = system(command);
    if (ret == 0) {
        return read_temp_file_as_int();
    }
    remove(TEMP_FILE);
    return -1;
}

int ui_dialog_get_confirmation(const char *title, const char *text) {
    char command[1024];
    snprintf(command, sizeof(command), "dialog --title \"%s\" --yesno \"%s\" 8 45 2>/dev/null", title, text);
    return (system(command) == 0);
}