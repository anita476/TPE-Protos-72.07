#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dialog.h>

#define MAX_INPUT 256
#define MAX_USERS 10
#define MAX_USERNAME 24

typedef struct {
    char username[MAX_USERNAME];
    char role[16];
} User;

static User users[MAX_USERS] = {
    {"nep", "Administrator"},
    {"user1", "User"},
    {"user2", "User"},
    {"guest", "User"}
};

static int user_count = 4;

// Core helper functions
static void cleanup_dialog(void);
static void show_message(const char* title, const char* message);
static char* get_input(const char* title, const char* text, int hidden);
static int get_menu_selection(const char* title, const char* text, char items[][2][64], int count);
static int get_confirmation(const char* title, const char* text);
static int select_user(const char* title, const char* text, int exclude_admin);
static int validate_input(const char* input, int min_len, int max_len, const char* error_prefix);
static int find_user(const char* username);
static int verify_credentials(const char* username, const char* password);
static int get_username(char* username, int size);
static int get_password(char* password, int size);
static int confirm_exit(void);

// Menu functions
static void show_user_list(void);
static void show_metrics(void);
static void show_server_config(void);
static int add_user(void);
static int remove_user(void);
static int change_user_password(void);
static void manage_users(void);
static void configure_settings(void);
static void admin_menu(void);
static int authenticate(void);

static void cleanup_dialog() {
    if (dialog_vars.input_result) {
        free(dialog_vars.input_result);
        dialog_vars.input_result = NULL;
    }
    dlg_clear();
}

static void show_message(const char* title, const char* message) {
    char formatted_message[512];
    snprintf(formatted_message, sizeof(formatted_message), "\n%s", message);
    dialog_msgbox(title, formatted_message, 8, 50, 1);
    cleanup_dialog();
}

static char* get_input(const char* title, const char* text, int hidden) {
    static char result[MAX_INPUT];
    char formatted_text[512];
    snprintf(formatted_text, sizeof(formatted_text), "\n%s", text);
    int ret = dialog_inputbox(title, formatted_text, 9, 40, "", hidden);
    if (ret == 0 && dialog_vars.input_result) {
        strncpy(result, dialog_vars.input_result, sizeof(result) - 1);
        result[sizeof(result) - 1] = '\0';
        cleanup_dialog();
        return result;
    }
    cleanup_dialog();
    return NULL;
}

static int get_menu_selection(const char* title, const char* text, char items[][2][64], int count) {
    char *menu_items[count * 2];
    for (int i = 0; i < count; i++) {
        menu_items[i * 2] = items[i][0];
        menu_items[i * 2 + 1] = items[i][1];
    }
    
    char formatted_text[512];
    snprintf(formatted_text, sizeof(formatted_text), "\n%s", text);
    int choice = dialog_menu(title, formatted_text, 14, 50, count, count, menu_items);
    if (choice != 0) {
        cleanup_dialog();
        return -1;
    }
    
    int selected = dialog_vars.input_result ? atoi(dialog_vars.input_result) : 0;
    cleanup_dialog();
    return selected;
}

static int get_confirmation(const char* title, const char* text) {
    char formatted_text[512];
    snprintf(formatted_text, sizeof(formatted_text), "\n%s", text);
    int result = (dialog_yesno(title, formatted_text, 6, 40) == 0);
    cleanup_dialog();
    return result;
}

static int validate_input(const char* input, int min_len, int max_len, const char* error_prefix) {
    if (!input || strlen(input) == 0) {
        char msg[256];
        snprintf(msg, sizeof(msg), "%s cannot be empty", error_prefix);
        show_message("Error", msg);
        return 0;
    }
    size_t len = strlen(input);
    if (len < (size_t)min_len) {
        char msg[256];
        snprintf(msg, sizeof(msg), "%s must be at least %d characters long", error_prefix, min_len);
        show_message("Error", msg);
        return 0;
    }
    if (len >= (size_t)max_len) {
        char msg[256];
        snprintf(msg, sizeof(msg), "%s must be less than %d characters long", error_prefix, max_len);
        show_message("Error", msg);
        return 0;
    }
    return 1;
}

static int select_user(const char* title, const char* text, int exclude_admin) {
    char items[MAX_USERS][2][64];
    int count = 0;
    
    for (int i = 0; i < user_count; i++) {
        if (exclude_admin && strcmp(users[i].username, "nep") == 0) continue;
        
        snprintf(items[count][0], 64, "%d", count + 1);
        snprintf(items[count][1], 64, "%s (%s)", users[i].username, users[i].role);
        count++;
    }
    
    if (count == 0) {
        show_message("Info", "No users available for this operation.");
        return -1;
    }
    
    int selected = get_menu_selection(title, text, items, count);
    if (selected <= 0 || selected > count) return -1;
    
    int actual_index = 0;
    for (int i = 0; i < user_count; i++) {
        if (exclude_admin && strcmp(users[i].username, "nep") == 0) continue;
        actual_index++;
        if (actual_index == selected) return i;
    }
    return -1;
}

static int find_user(const char* username) {
    for (int i = 0; i < user_count; i++) {
        if (strcmp(users[i].username, username) == 0) {
            return i;
        }
    }
    return -1;
}

// TODO: Actually verify
static int verify_credentials(const char* username, const char* password) {
    return (strcmp(username, "admin") == 0 && strcmp(password, "admin") == 0) ||
           (strcmp(username, "nep") == 0 && strcmp(password, "nep") == 0);
}

static int get_username(char* username, int size) {
    char* input = get_input("Login", "Enter username:", 0);
    if (!input) return -1;
    strncpy(username, input, size - 1);
    username[size - 1] = '\0';
    return 0;
}

static int get_password(char* password, int size) {
    char* input = get_input("Login", "Enter password:", 1);
    if (!input) return -1;
    strncpy(password, input, size - 1);
    password[size - 1] = '\0';
    return 0;
}

static void show_server_config() {
    char config_info[1024];
    snprintf(config_info, sizeof(config_info),
        "\nSOCKS5 Port: 1080\n"
        "Admin Port: 8080\n"
        "Bind Address: 0.0.0.0\n"
        "Max Connections: 100\n"
        "Connection Timeout: 30 seconds\n"
        "Buffer Size: 8192 bytes\n\n"
        "Press OK to continue");
    
    dialog_msgbox("Server configuration", config_info, 13, 60, 1);
    cleanup_dialog();
}

static void show_user_list() {
    char users_info[1024];
    char user_list[512] = "";
    
    for (int i = 0; i < user_count; i++) {
        char user_line[64];
        snprintf(user_line, sizeof(user_line), "%d. %s (%s)\n", 
                i + 1, users[i].username, users[i].role);
        strcat(user_list, user_line);
    }
    
    snprintf(users_info, sizeof(users_info),
        "\n%s\nTotal users: %d\n\n"
        "Press OK to continue", user_list, user_count);
    
    dialog_msgbox("User list", users_info, 14, 50, 1);
    cleanup_dialog();
}

static void show_metrics() {
    char status_info[2048];
    
    snprintf(status_info, sizeof(status_info),
        "\nServer status: Running\n"
        "SOCKS5 port: Active\n"
        "Admin port: Active\n"
        "Current connections: 15\n"
        "Total connections: 1,234\n"
        "Bytes transferred: 2.5 GB\n"
        "Server uptime: 5 days, 12 hours\n"
        "Active users: %d\n\n"
        "Press OK to continue", user_count);
    
    dialog_msgbox("View metrics", status_info, 15, 60, 1);
    cleanup_dialog();
}

static void manage_users() {
    while (1) {
        char items[5][2][64] = {
            {"1", "List all users"},
            {"2", "Add new user"}, 
            {"3", "Remove user"},
            {"4", "Change user password"},
            {"5", "Back to main menu"}
        };
        
        int selected = get_menu_selection("Manage users", "Select an option:", items, 5);
        if (selected == -1 || selected == 5) return;
        
        switch (selected) {
            case 1: show_user_list(); break;
            case 2: add_user(); break;
            case 3: remove_user(); break;
            case 4: change_user_password(); break;
            default: show_message("Error", "Invalid option"); break;
        }
    }
}

static void configure_settings() {
    while (1) {
        char items[4][2][64] = {
            {"1", "Server configuration"},
            {"2", "Logging settings"},
            {"3", "Security settings"},
            {"4", "Back to main menu"}
        };
        
        int selected = get_menu_selection("Manage settings", "Select an option:", items, 4);
        if (selected == -1 || selected == 4) return;
        
        switch (selected) {
            case 1: show_server_config(); break;
            case 2: show_message("Info", "Logging settings not implemented yet"); break;
            case 3: show_message("Info", "Security settings not implemented yet"); break;
            default: show_message("Error", "Invalid option"); break;
        }
    }
}

static void admin_menu() {
    while (1) {
        char items[4][2][64] = {
            {"1", "View metrics"},
            {"2", "Manage users"},
            {"3", "Manage settings"},
            {"4", "Exit"}
        };
        
        int selected = get_menu_selection("Admin interface", "Select an option:", items, 4);
        if (selected == -1) break;
        
        switch (selected) {
            case 1: show_metrics(); break;
            case 2: manage_users(); break;
            case 3: configure_settings(); break;
            case 4: if (confirm_exit()) return; break;
            default: show_message("Error", "Invalid option"); break;
        }
    }
}

static int confirm_exit() {
    return get_confirmation("Confirm", "Are you sure you want to exit?");
}

static int authenticate() {
    char username[MAX_INPUT], password[MAX_INPUT];
    
    for (int attempts = 0; attempts < 3; attempts++) {
        if (get_username(username, sizeof(username)) != 0) {
            return 0;
        }
        if (strlen(username) == 0) {
            show_message("Error", "Username cannot be empty");
            continue;
        }
        
        if (get_password(password, sizeof(password)) != 0) {
            return 0;
        }
        if (strlen(password) == 0) {
            show_message("Error", "Password cannot be empty");
            continue;
        }
        
        if (verify_credentials(username, password)) {
            show_message("Success", "Authentication successful. Welcome to the admin panel.");
            return 1;
        }
        
        if (attempts < 2) {
            char error_msg[256];
            snprintf(error_msg, sizeof(error_msg), 
                "Incorrect credentials. Attempts remaining: %d", 2 - attempts);
            show_message("Error", error_msg);
        }
        
        memset(username, 0, sizeof(username));
        memset(password, 0, sizeof(password));
    }
    
    show_message("Error", "Maximum number of attempts reached. Access denied.");
    return 0;
}

static int add_user() {
    char username[MAX_INPUT], password[MAX_INPUT];
    
    char* input_username = get_input("Username", "Enter username:", 0);
    if (!input_username) return 0;
    strcpy(username, input_username);
    
    if (!validate_input(username, 3, MAX_USERNAME, "Username")) return 0;
    
    if (find_user(username) != -1) {
        show_message("Error", "Username already exists. Please choose a different username.");
        return 0;
    }
    
    char* input_password = get_input("Password", "Enter password:", 1);
    if (!input_password) return 0;
    strcpy(password, input_password);
    
    if (!validate_input(password, 4, 24, "Password")) return 0;
    
    char* confirm_password = get_input("Confirm password", "Confirm your password:", 1);
    if (!confirm_password || strcmp(password, confirm_password) != 0) {
        show_message("Error", "Passwords do not match. Please try again.");
        return 0;
    }
    
    if (user_count >= MAX_USERS) {
        show_message("Error", "Maximum number of users reached. Cannot add more users.");
        return 0;
    }
    
    strcpy(users[user_count].username, username);
    strcpy(users[user_count].role, "User");
    user_count++;
    
    char success_msg[512];
    snprintf(success_msg, sizeof(success_msg), 
        "User '%s' has been successfully added to the system.", username);
    show_message("Success", success_msg);
    
    return 1;
}

static int remove_user() {
    int user_index = select_user("Remove user", "Select user to remove:", 1);
    if (user_index == -1) {
        return 0;
    }
    
    char selected_user[MAX_USERNAME];
    strcpy(selected_user, users[user_index].username);
    
    char confirm_msg[256];
    snprintf(confirm_msg, sizeof(confirm_msg),
        "Are you sure you want to remove user '%s'?\n\nThis action cannot be undone.", selected_user);
    
    if (get_confirmation("Confirm removal", confirm_msg)) {
        for (int i = user_index; i < user_count - 1; i++) {
            users[i] = users[i + 1];
        }
        
        strcpy(users[user_count - 1].username, "");
        strcpy(users[user_count - 1].role, "");
        user_count--;
        
        char success_msg[256];
        snprintf(success_msg, sizeof(success_msg), 
            "User '%s' has been successfully removed from the system.", selected_user);
        show_message("Success", success_msg);
        return 1;
    }
    
    show_message("Info", "User removal cancelled.");
    return 0;
}

static int change_user_password() {
    int user_index = select_user("Change password", "Select user to change password:", 0);
    if (user_index == -1) {
        return 0;
    }
    
    char* selected_user = users[user_index].username;
    char prompt[256];
    snprintf(prompt, sizeof(prompt), "Enter new password for user '%s':", selected_user);
    
    char* new_password = get_input("New password", prompt, 1);
    if (!new_password || !validate_input(new_password, 4, 24, "Password")) return 0;
    
    char* confirm_password = get_input("Confirm password", "Confirm new password:", 1);
    if (!confirm_password || strcmp(new_password, confirm_password) != 0) {
        show_message("Error", "Passwords do not match. Please try again.");
        return 0;
    }
    
    char success_msg[256];
    snprintf(success_msg, sizeof(success_msg), 
        "Password for user '%s' has been successfully changed.", selected_user);
    show_message("Success", success_msg);
    
    return 1;
}

int main() {
    init_dialog(stdin, stdout);
    
    show_message("Welcome", "SOCKS5 server admin interface\n\nPress OK to continue");
    
    if (!authenticate()) {
        end_dialog();
        system("clear");
        return 0;
    }
    
    admin_menu();
    
    end_dialog();
    system("clear");
    
    return 0;
}