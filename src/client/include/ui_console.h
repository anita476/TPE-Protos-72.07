#ifndef UI_CONSOLE_H
#define UI_CONSOLE_H

#define CONSOLE_WIDTH 80
#define BOX_WIDTH 60
#define HEADER_PADDING 4
#define MENU_ITEM_LABEL_LEN 64
#define MENU_ITEM_FIELDS 2
#define INPUT_BUFFER_LEN 16
#define MIN_MENU_OPTION 1

void ui_console_show_message(const char *title, const char *message);

char *ui_console_get_input(const char *title, const char *text, int hidden);

int ui_console_get_menu_selection(const char *title, const char *text, char items[][2][64], int count);

int ui_console_get_confirmation(const char *title, const char *text);

void ui_clear_screen(void);

void ui_print_header(const char *title);

void ui_print_separator(void);

void ui_wait_for_key(const char *prompt);

#endif