#ifndef UI_WHIPTAIL_H
#define UI_WHIPTAIL_H

#define MAX_INPUT 256
#define TEMP_FILE "/tmp/whiptail_input"

void ui_show_message(const char *title, const char *message);

char *ui_get_input(const char *title, const char *text, int hidden);

int ui_get_menu_selection(const char *title, const char *text, char items[][2][64], int count);

int ui_get_confirmation(const char *title, const char *text);

#endif