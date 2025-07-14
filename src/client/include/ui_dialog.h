#ifndef UI_DIALOG_H
#define UI_DIALOG_H

#define MAX_INPUT 256
#define TEMP_FILE "/tmp/dialog_input"
#define TEMP_DIR "/tmp"

#define DIALOG_MENU_EXTRA_HEIGHT 7
#define DIALOG_MENU_MAX_HEIGHT 20
#define DIALOG_MENU_WIDTH 45
#define DIALOG_MSGBOX_HEIGHT_SHORT 8
#define DIALOG_MSGBOX_HEIGHT_LONG 16
#define DIALOG_MSGBOX_LINE_THRESHOLD 6
#define DIALOG_MSGBOX_WIDTH 45
#define DIALOG_INPUTBOX_HEIGHT 8
#define DIALOG_INPUTBOX_WIDTH 35
#define DIALOG_CONFIRM_HEIGHT 8
#define DIALOG_CONFIRM_WIDTH 45
#define TEMP_RESULT_SIZE 16

void ui_dialog_show_message(const char *title, const char *message);

char *ui_dialog_get_input(const char *title, const char *text, int hidden);

int ui_dialog_get_menu_selection(const char *title, const char *text, char items[][2][64], int count);

int ui_dialog_get_confirmation(const char *title, const char *text);

#endif