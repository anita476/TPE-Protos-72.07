#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include "../include/ui_console.h"

#define CONSOLE_WIDTH 80
#define BOX_WIDTH 60

/* Draw functions */

void ui_clear_screen(void) {
    system("clear");
}

static void print_border_line(char left, char middle, char right, int width) {
    printf("%c", left);
    for (int i = 0; i < width - 2; i++) {
        printf("%c", middle);
    }
    printf("%c\n", right);
}

static void print_text_line(const char *text, int width) {
    int text_len = strlen(text);
    int padding = (width - 2 - text_len) / 2;
    
    printf("|");
    for (int i = 0; i < padding; i++) {
        printf(" ");
    }
    printf("%s", text);
    for (int i = 0; i < width - 2 - padding - text_len; i++) {
        printf(" ");
    }
    printf("|\n");
}

void ui_print_header(const char *title) {
    int title_len = strlen(title);
    int box_width = (title_len > BOX_WIDTH - 4) ? title_len + 4 : BOX_WIDTH;
    
    print_border_line('+', '-', '+', box_width);
    print_text_line(title, box_width);
    print_border_line('+', '-', '+', box_width);
}

void ui_print_separator(void) {
    for (int i = 0; i < BOX_WIDTH; i++) {
        printf("-");
    }
    printf("\n");
}

void ui_wait_for_key(const char *prompt) {
    printf("\n%s", prompt);
    fflush(stdout);
    getchar();
}

/* UI functions */

void ui_console_show_message(const char *title, const char *message) {
    ui_clear_screen();
    ui_print_header(title);
    printf("\n");
    
    char *msg_copy = strdup(message);
    char *line = strtok(msg_copy, "\n");
    
    while (line != NULL) {
        printf("  %s\n", line);
        line = strtok(NULL, "\n");
    }
    
    free(msg_copy);
    printf("\n");
    ui_wait_for_key("Press any key to continue...");
}

char *ui_console_get_input(const char *title, const char *text, int hidden) {
    (void)hidden;
    static char result[MAX_INPUT];

    ui_clear_screen();
    ui_print_header(title);
    printf("\n%s\n", text);
    printf("> ");
    fflush(stdout);

    if (fgets(result, MAX_INPUT, stdin) != NULL) {
        char *newline = strchr(result, '\n');
        if (newline) {
            *newline = '\0';
        }
    } else {
        return NULL;
    }

    return result;
}

int ui_console_get_menu_selection(const char *title, const char *text, char items[][2][64], int count) {
    int selected = 0;
    char input[16];
    
    ui_clear_screen();
    ui_print_header(title);
    printf("\n%s\n\n", text);
    
    for (int i = 0; i < count; i++) {
        printf("  %s. %s\n", items[i][0], items[i][1]);
    }
    
    printf("\nEnter your choice (1-%d): ", count);
    fflush(stdout);
    
    if (fgets(input, sizeof(input), stdin) != NULL) {
        selected = atoi(input);
        if (selected >= 1 && selected <= count) {
            return selected;
        }
    }
    
    return -1;
}

int ui_console_get_confirmation(const char *title, const char *text) {
    char input[16];
    
    ui_clear_screen();
    ui_print_header(title);
    printf("\n%s\n\n", text);
    printf("Do you want to continue? (y/N): ");
    fflush(stdout);
    
    if (fgets(input, sizeof(input), stdin) != NULL) {
        char ch = tolower(input[0]);
        return (ch == 'y' || ch == 'Y');
    }
    
    return 0; // Default: No
}