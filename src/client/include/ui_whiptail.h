#ifndef UI_WHIPTAIL_H
#define UI_WHIPTAIL_H

#define MAX_INPUT 256
#define TEMP_FILE "/tmp/whiptail_input"

void ui_whiptail_show_message(const char *title, const char *message);

char *ui_whiptail_get_input(const char *title, const char *text, int hidden);

int ui_whiptail_get_menu_selection(const char *title, const char *text, char items[][2][64], int count);

int ui_whiptail_get_confirmation(const char *title, const char *text);

#endif