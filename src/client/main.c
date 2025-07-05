#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include "include/lib_client.h"
#include "include/ui_whiptail.h"
#include "include/validation.h"

#define MAX_USERS 10
#define MAX_USERNAME 24

#define ITEMS_PER_PAGE 10
#define MAX_DISPLAY_ITEMS 8

static int server_socket = -1;
static char server_address[256] = "localhost";
static char server_port[16] = "8080";

// Authentication functions
static int get_user_input(const char *title, const char *prompt, int is_password, char *output, int size);
static int get_username(char *username, int size);
static int get_password(char *password, int size);
static int authenticate(void);

// Pagination functions
static void display_paginated_users(user_list_entry *users, int total_count, int current_page);
static void display_paginated_logs(log_strct *logs, int total_count, int current_page);
static char* format_user_info(user_list_entry *user, int index);
static char* format_log_info(log_strct *log, int index);

// Server interaction functions
static void show_metrics(void);
static void show_logs(void);
static void show_user_list(void);
static void show_config(void);

// User management functions
static int find_user(const char *username);
static int select_user(const char *title, const char *text, int exclude_admin);
static int add_user(void);
static int remove_user(void);

// Server configuration functions
static void change_server_setting(const char *setting_name, const char *unit, int (*validate_func)(const char *, uint8_t *), uint8_t (*handle_func)(int, uint8_t));
static void change_buffer_size(void);
static void change_timeout(void);

// Menu functions
static void admin_menu(void);
static int confirm_exit(void);
static void manage_users(void);
static void configure_settings(void);

/* Authentication functions */

static int get_user_input(const char *title, const char *prompt, int is_password, char *output, int size) {
    char *input = ui_get_input(title, prompt, is_password);
    if (!input) {
        return -1;
    }
    strncpy(output, input, size - 1);
    output[size - 1] = '\0';
    return 0;
}

static int get_username(char *username, int size) {
    return get_user_input("Login", "Enter username:", 0, username, size);
}

static int get_password(char *password, int size) {
    return get_user_input("Login", "Enter password:", 1, password, size);
}

static int authenticate() {
    char username[MAX_INPUT], password[MAX_INPUT];

    server_socket = setup_tcp_client_Socket(server_address, server_port);
    if (server_socket < 0) {
        ui_show_message("Error", "Failed to connect to server");
        return 0;
    }

    for (int attempts = 0; attempts < 3; attempts++) {
        if (get_username(username, sizeof(username)) != 0) {
            close(server_socket);
            return 0;
        }
        if (strlen(username) == 0) {
            ui_show_message("Error", "Username cannot be empty");
            continue;
        }

        if (get_password(password, sizeof(password)) != 0) {
            close(server_socket);
            return 0;
        }
        if (strlen(password) == 0) {
            ui_show_message("Error", "Password cannot be empty");
            continue;
        }

        // Hello message
        if (hello_send(username, password, server_socket) != 0) {
            ui_show_message("Error", "Failed to send authentication");
            close(server_socket);
            return 0;
        }

        // Hello response
        int auth_result = hello_read(server_socket);
        if (auth_result == 1) { // Admin user
            ui_show_message("Success", "Authentication successful. Welcome to the admin panel.");
            return 1;
        } else if (auth_result == 0) { // Regular user
            ui_show_message("Info", "Authenticated as regular user. Admin privileges required.");
            close(server_socket);
            return 0;
        }

        if (attempts < 2) {
            char error_msg[256];
            snprintf(error_msg, sizeof(error_msg), "Incorrect credentials. Attempts remaining: %d", 2 - attempts);
            ui_show_message("Error", error_msg);
        }

        memset(username, 0, sizeof(username));
        memset(password, 0, sizeof(password));
    }

    ui_show_message("Error", "Maximum number of attempts reached. Access denied.");
    close(server_socket);
    return 0;
}

/* Pagination functions */

static void display_paginated_users(user_list_entry *users, int total_count, int current_page) {
    char users_info[2048];
    char user_list[1536] = "";
    user_list_entry *current = users;
    int count = 0;

    while (current != NULL && count < MAX_DISPLAY_ITEMS) {
        char *user_line = format_user_info(current, count + 1 + (current_page * ITEMS_PER_PAGE));
        strcat(user_list, user_line);
        current = current->next;
        count++;
    }

    snprintf(users_info, sizeof(users_info),
             "Server Users (Page %d):\n%s\nShowing %d users\n\n"
             "Press OK to continue",
             current_page + 1, user_list, count);

    ui_show_message("User List", users_info);
}

static char* format_user_info(user_list_entry *user, int index) {
    static char user_line[128];
    const char *role = (user->user_type == 1) ? "Administrator" : "User";
    snprintf(user_line, sizeof(user_line), "%d. %.*s (%s)\n", 
             index, user->ulen, user->username, role);
    return user_line;
}

static void display_paginated_logs(log_strct *logs, int total_count, int current_page) {
    char logs_info[2048];
    char log_list[1536] = "";
    log_strct *current = logs;
    int count = 0;

    while (current != NULL && count < MAX_DISPLAY_ITEMS) {
        char *log_line = format_log_info(current, count + 1 + (current_page * ITEMS_PER_PAGE));
        strcat(log_list, log_line);
        current = current->next;
        count++;
    }

    snprintf(logs_info, sizeof(logs_info), 
             "Server Logs (Page %d):\n%s\nShowing %d logs\n\n"
             "Press OK to continue", 
             current_page + 1, log_list, count);

    ui_show_message("Server Logs", logs_info);
}

static char* format_log_info(log_strct *log, int index) {
    static char log_line[600];
    snprintf(log_line, sizeof(log_line), "%d. %.*s -> %s:%d\n", 
             index, log->ulen, log->username, 
             log->destination_address, log->destination_port);
    return log_line;
}

/* Server interaction functions */

static void show_metrics() {
    if (server_socket < 0) {
        ui_show_message("Error", "No server connection");
        return;
    }
     
    metrics server_metrics;
    if (handle_metrics(server_socket, &server_metrics) == NULL) {
        ui_show_message("Error", "Failed to retrieve server metrics");
        return;
    }

    char status_info[2048];
    snprintf(status_info, sizeof(status_info),
             "Server status: %s\n"
             "Current connections: %u\n"
             "Total connections: %u\n"
             "Bytes received: %u\n"
             "Bytes sent: %u\n"
             "Timeouts: %u\n"
             "Server errors: %u\n"
             "Bad requests: %u\n\n"
             "Press OK to continue",
             server_metrics.server_state == 1 ? "Running" : "Stopped",
             server_metrics.n_current_connections,
             server_metrics.n_total_connections,
             server_metrics.n_total_bytes_received,
             server_metrics.n_total_bytes_sent,
             server_metrics.n_timeouts,
             server_metrics.n_server_errors,
             server_metrics.n_bad_requests);

    ui_show_message("View Metrics", status_info);
}

static void show_logs() {
    if (server_socket < 0) {
        ui_show_message("Error", "No server connection");
        return;
    }

    int current_page = 0;
    int continue_browsing = 1;

    while (continue_browsing) {
        log_strct *logs = handle_log(server_socket, ITEMS_PER_PAGE, current_page * ITEMS_PER_PAGE);
        
        if (logs == NULL) {
            if (current_page == 0) {
                ui_show_message("Info", "No logs available");
            } else {
                ui_show_message("Info", "No more logs available");
            }
            break;
        }

        int log_count = 0;
        log_strct *current = logs;
        while (current != NULL) {
            log_count++;
            current = current->next;
        }

        display_paginated_logs(logs, log_count, current_page);
        
        char nav_items[4][2][64];
        int nav_count = 0;
        
        if (current_page > 0) {
            snprintf(nav_items[nav_count][0], 64, "%d", nav_count + 1);
            snprintf(nav_items[nav_count][1], 64, "Previous page");
            nav_count++;
        }
        
        if (log_count == ITEMS_PER_PAGE) {
            snprintf(nav_items[nav_count][0], 64, "%d", nav_count + 1);
            snprintf(nav_items[nav_count][1], 64, "Next page");
            nav_count++;
        }
        
        snprintf(nav_items[nav_count][0], 64, "%d", nav_count + 1);
        snprintf(nav_items[nav_count][1], 64, "Back to menu");
        nav_count++;

        char title[128];
        snprintf(title, sizeof(title), "Server Logs - Page %d", current_page + 1);
        
        int selection = ui_get_menu_selection(title, "Choose navigation option:", nav_items, nav_count);
        
        if (selection == -1) {
            continue_browsing = 0;
        } else if (current_page > 0 && selection == 1) {
            current_page--;
        } else if (log_count == ITEMS_PER_PAGE && 
                   ((current_page > 0 && selection == 2) || (current_page == 0 && selection == 1))) {
            current_page++;
        } else {
            continue_browsing = 0;
        }
        
        free_log_list(logs);
    }
}

static void show_user_list() {
    if (server_socket < 0) {
        ui_show_message("Error", "No server connection");
        return;
    }

    int current_page = 0;
    int continue_browsing = 1;

    while (continue_browsing) {
        user_list_entry *users = handle_get_users(ITEMS_PER_PAGE, current_page * ITEMS_PER_PAGE, server_socket);
        
        if (users == NULL) {
            if (current_page == 0) {
                ui_show_message("Info", "No users available");
            } else {
                ui_show_message("Info", "No more users available");
            }
            break;
        }

        int user_count = 0;
        user_list_entry *current = users;
        while (current != NULL) {
            user_count++;
            current = current->next;
        }

        display_paginated_users(users, user_count, current_page);
        
        char nav_items[4][2][64];
        int nav_count = 0;
        
        if (current_page > 0) {
            snprintf(nav_items[nav_count][0], 64, "%d", nav_count + 1);
            snprintf(nav_items[nav_count][1], 64, "Previous page");
            nav_count++;
        }
        
        if (user_count == ITEMS_PER_PAGE) {
            snprintf(nav_items[nav_count][0], 64, "%d", nav_count + 1);
            snprintf(nav_items[nav_count][1], 64, "Next page");
            nav_count++;
        }
        
        snprintf(nav_items[nav_count][0], 64, "%d", nav_count + 1);
        snprintf(nav_items[nav_count][1], 64, "Back to menu");
        nav_count++;

        char title[128];
        snprintf(title, sizeof(title), "User List - Page %d", current_page + 1);
        
        int selection = ui_get_menu_selection(title, "Choose navigation option:", nav_items, nav_count);
        
        if (selection == -1) {
            continue_browsing = 0;
        } else if (current_page > 0 && selection == 1) {
            current_page--;
        } else if (user_count == ITEMS_PER_PAGE && 
                   ((current_page > 0 && selection == 2) || (current_page == 0 && selection == 1))) {
            current_page++;
        } else {
            continue_browsing = 0;
        }
        
        free_user_list(users);
    }
}

static void show_config() {
    char config_info[1024];
    snprintf(config_info, sizeof(config_info),
             "SOCKS5 Port: 1080\n"
             "Admin Port: 8080\n"
             "Bind Address: 0.0.0.0\n"
             "Max Connections: 100\n"
             "Connection Timeout: 30 seconds\n"
             "Buffer Size: 8192 bytes\n\n"
             "Press OK to continue");

    ui_show_message("Server Configuration", config_info);
}

/* User management functions */

static int find_user(const char *username) {
    if (!username || server_socket < 0) {
        return -1;
    }

    user_list_entry *users = handle_get_users(MAX_USERS, 0, server_socket);
    if (users == NULL) {
        return -1;
    }

    int index = 0;
    user_list_entry *current = users;
    
    while (current != NULL) {
        if (current->ulen == strlen(username) && 
            strncmp(current->username, username, current->ulen) == 0) {
            free_user_list(users);
            return index;
        }
        current = current->next;
        index++;
    }

    free_user_list(users);
    return -1;
}

static int select_user(const char *title, const char *text, int exclude_admin) {
    if (server_socket < 0) {
        ui_show_message("Error", "No server connection");
        return -1;
    }

    user_list_entry *users = handle_get_users(MAX_USERS, 0, server_socket);
    if (users == NULL) {
        ui_show_message("Info", "No users available for this operation.");
        return -1;
    }

    char items[MAX_USERS][2][64];
    int count = 0;
    user_list_entry *current = users;
    
    while (current != NULL && count < MAX_USERS) {
        if (exclude_admin && current->user_type == 1) {
            current = current->next;
            continue;
        }

        snprintf(items[count][0], 64, "%d", count + 1);
        const char *role = (current->user_type == 1) ? "Administrator" : "User";
        snprintf(items[count][1], 64, "%.*s (%s)", current->ulen, current->username, role);
        count++;
        current = current->next;
    }

    if (count == 0) {
        ui_show_message("Info", "No users available for this operation.");
        free_user_list(users);
        return -1;
    }

    int selected = ui_get_menu_selection(title, text, items, count);
    free_user_list(users);
    
    if (selected <= 0 || selected > count) {
        return -1;
    }

    return selected - 1;
}

static int add_user() {
	/*
	char username[MAX_INPUT], password[MAX_INPUT];

	char *input_username = get_input("Username", "Enter username:", 0);
	if (!input_username) {
		return 0;
	}
	strcpy(username, input_username);

	if (!validate_input(username, 3, MAX_USERNAME, "Username"))
		return 0;

	if (find_user(username) != -1) {
		show_message("Error", "Username already exists. Please choose a different username.");
		return 0;
	}

	char *input_password = get_input("Password", "Enter password:", 1);
	if (!input_password) {
		return 0;
	}
	strcpy(password, input_password);

	if (!validate_input(password, 4, 24, "Password"))
		return 0;

	char *confirm_password = get_input("Confirm password", "Confirm your password:", 1);
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
	snprintf(success_msg, sizeof(success_msg), "User '%s' has been successfully added to the system.", username);
	show_message("Success", success_msg);

	return 1;
	*/
}

static int remove_user() {
	/*
	int user_index = select_user("Remove user", "Select user to remove:", 1);
	if (user_index == -1) {
		return 0;
	}

	char selected_user[MAX_USERNAME];
	//strcpy(selected_user, users[user_index].username);

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
		snprintf(success_msg, sizeof(success_msg), "User '%s' has been successfully removed from the system.",
				 selected_user);
		show_message("Success", success_msg);
		return 1;
	}

	show_message("Info", "User removal cancelled.");
	return 0;
	*/
}

/* Server configuration functions */

static void change_server_setting(const char *setting_name, const char *unit, 
                                 int (*validate_func)(const char *, uint8_t *),
                                 uint8_t (*handle_func)(int, uint8_t)) {
    if (server_socket < 0) {
        ui_show_message("Error", "No server connection");
        return;
    }

    char prompt[256];
    snprintf(prompt, sizeof(prompt), "Enter new %s (%s):", setting_name, unit);
    
    char *input = ui_get_input(setting_name, prompt, 0);
    if (!input) {
        return;
    }

    uint8_t new_value;
    if (!validate_func(input, &new_value)) {
        return;
    }
    
    char confirm_msg[256];
    snprintf(confirm_msg, sizeof(confirm_msg), 
             "Are you sure you want to change %s to %d %s?", 
             setting_name, new_value, unit);
    
    if (!ui_get_confirmation("Confirm Change", confirm_msg)) {
        char cancel_msg[256];
        snprintf(cancel_msg, sizeof(cancel_msg), "%s change cancelled.", setting_name);
        ui_show_message("Info", cancel_msg);
        return;
    }

    uint8_t result = handle_func(server_socket, new_value);
    
    if (result == 0) {
        char success_msg[256];
        snprintf(success_msg, sizeof(success_msg), 
                 "%s successfully changed to %d %s.", 
                 setting_name, new_value, unit);
        ui_show_message("Success", success_msg);
    } else {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), 
                 "Failed to change %s. Error code: %d", 
                 setting_name, result);
        ui_show_message("Error", error_msg);
    }
}

static void change_buffer_size() {
    change_server_setting("buffer size", "KB", validate_buffer_size, handle_change_buffer_size);
}

static void change_timeout() {
    change_server_setting("timeout", "seconds", validate_timeout, handle_change_timeout);
}

/* Menu functions */

static void admin_menu() {
    while (1) {
        char items[5][2][64] = {
            {"1", "View metrics"}, 
            {"2", "View logs"}, 
            {"3", "Manage users"}, 
            {"4", "Manage settings"}, 
            {"5", "Exit"}
        };

        int selected = ui_get_menu_selection("Admin interface", "Select an option:", items, 5);
        if (selected == -1)
            break;

        switch (selected) {
            case 1:
                show_metrics();
                break;
            case 2:
                show_logs();
                break;
            case 3:
                manage_users();
                break;
            case 4:
                configure_settings();
                break;
            case 5:
                if (confirm_exit()) {
                    if (server_socket >= 0) {
                        close(server_socket);
                    }
                    return;
                }
                break;
            default:
                ui_show_message("Error", "Invalid option");
                break;
        }
    }
}

static int confirm_exit() {
    return ui_get_confirmation("Confirm", "Are you sure you want to exit?");
}

static void manage_users() {
    while (1) {
        char items[4][2][64] = {
            {"1", "List all users"}, {"2", "Add new user"}, {"3", "Remove user"}, {"4", "Back to main menu"}};

        int selected = ui_get_menu_selection("Manage users", "Select an option:", items, 4);
        if (selected == -1 || selected == 4)
            return;

        switch (selected) {
            case 1:
                show_user_list();
                break;
            case 2:
                add_user();
                break;
            case 3:
                remove_user();
                break;
            default:
                ui_show_message("Error", "Invalid option");
                break;
        }
    }
}

static void configure_settings() {
    while (1) {
        char items[3][2][64] = {
            {"1", "Change buffer size"},
            {"2", "Change timeout"},
            {"3", "Back to main menu"}
        };

        int selected = ui_get_menu_selection("Server Settings", "Select an option:", items, 3);
        if (selected == -1 || selected == 3)
            return;

        switch (selected) {
            case 1:
                change_buffer_size();
                break;
            case 2:
                change_timeout();
                break;
            default:
                ui_show_message("Error", "Invalid option");
                break;
        }
    }
}

/* Main */

int main() {
    ui_show_message("Welcome", "SOCKS5 server admin interface. \nPress OK to continue");

    if (!authenticate()) {
        system("clear");
        return 0;
    }

    admin_menu();

    if (server_socket >= 0) {
        close(server_socket);
    }

    system("clear");

    return 0;
}