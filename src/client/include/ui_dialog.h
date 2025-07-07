#ifndef UI_DIALOG_H
#define UI_DIALOG_H

#define MAX_INPUT 256
#define TEMP_FILE "/tmp/dialog_input"

void ui_dialog_show_message(const char *title, const char *message);

char *ui_dialog_get_input(const char *title, const char *text, int hidden);

int ui_dialog_get_menu_selection(const char *title, const char *text, char items[][2][64], int count);

int ui_dialog_get_confirmation(const char *title, const char *text);

#endif