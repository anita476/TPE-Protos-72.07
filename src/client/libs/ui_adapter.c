#include <stdio.h>

#include "../include/ui_adapter.h"
#include "../include/ui_whiptail.h"
#include "../include/ui_console.h"

static int ui_mode = 0; // 0 = whiptail, 1 = console

void ui_init(int use_console) {
    ui_mode = use_console;
    if (use_console) {
        printf("Console UI initialized\n");
    } else {
        printf("Whiptail UI initialized\n");
    }
}

void ui_show_message(const char *title, const char *message) {
    if (ui_mode) {
        ui_console_show_message(title, message);
    } else {
        ui_whiptail_show_message(title, message);
    }
}

char *ui_get_input(const char *title, const char *text, int hidden) {
    if (ui_mode) {
        return ui_console_get_input(title, text, hidden);
    } else {
        return ui_whiptail_get_input(title, text, hidden);
    }
}

int ui_get_menu_selection(const char *title, const char *text, char items[][2][64], int count) {
    if (ui_mode) {
        return ui_console_get_menu_selection(title, text, items, count);
    } else {
        return ui_whiptail_get_menu_selection(title, text, items, count);
    }
}

int ui_get_confirmation(const char *title, const char *text) {
    if (ui_mode) {
        return ui_console_get_confirmation(title, text);
    } else {
        return ui_whiptail_get_confirmation(title, text);
    }
}