#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ui_whiptail.h"

void ui_whiptail_show_message(const char *title, const char *message) {
    char command[1024];
    snprintf(command, sizeof(command), "whiptail --title \"%s\" --msgbox \"%s\" 8 45", title, message);
    system(command);
}

char *ui_whiptail_get_input(const char *title, const char *text, int hidden) {
    static char result[MAX_INPUT];
    char command[1024];

    if (hidden) {
        snprintf(command, sizeof(command), "whiptail --title \"%s\" --passwordbox \"%s\" 8 35 2>%s", title, text,
                 TEMP_FILE);
    } else {
        snprintf(command, sizeof(command), "whiptail --title \"%s\" --inputbox \"%s\" 8 35 2>%s", title, text,
                 TEMP_FILE);
    }

    int ret = system(command);
    if (ret == 0) {
        FILE *file = fopen(TEMP_FILE, "r");
        if (file) {
            if (fgets(result, sizeof(result), file)) {
                char *newline = strchr(result, '\n');
                if (newline) {
                    *newline = '\0';
                }
                fclose(file);
                remove(TEMP_FILE);
                return result;
            }
            fclose(file);
        }
    }
    remove(TEMP_FILE);
    return NULL;
}

int ui_whiptail_get_menu_selection(const char *title, const char *text, char items[][2][64], int count) {
    char command[2048];
    char menu_items[1024] = "";

    for (int i = 0; i < count; i++) {
        char item[256];
        snprintf(item, sizeof(item), "\"%s\" \"%s\" ", items[i][0], items[i][1]);
        strcat(menu_items, item);
    }

    snprintf(command, sizeof(command), "whiptail --title \"%s\" --menu \"%s\" 12 50 %d %s 2>%s", title, text, count,
             menu_items, TEMP_FILE);

    int ret = system(command);
    if (ret == 0) {
        FILE *file = fopen(TEMP_FILE, "r");
        if (file) {
            char result[16];
            if (fgets(result, sizeof(result), file)) {
                char *newline = strchr(result, '\n');
                if (newline)
                    *newline = '\0';
                fclose(file);
                remove(TEMP_FILE);
                return atoi(result);
            }
            fclose(file);
        }
    }
    remove(TEMP_FILE);
    return -1;
}

int ui_whiptail_get_confirmation(const char *title, const char *text) {
    char command[1024];
    snprintf(command, sizeof(command), "whiptail --title \"%s\" --yesno \"%s\" 8 45", title, text);
    return (system(command) == 0);
}