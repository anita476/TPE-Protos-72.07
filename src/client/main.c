#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include "include/lib_client.h"

#define MAX_INPUT 256
#define MAX_USERS 10
#define MAX_USERNAME 24
#define TEMP_FILE "/tmp/whiptail_input"

static int server_socket = -1;
static char server_address[256] = "localhost";
static char server_port[16] = "8080";

// UI helper functions
static void show_message(const char *title, const char *message);
static char *get_input(const char *title, const char *text, int hidden);
static int get_menu_selection(const char *title, const char *text, char items[][2][64], int count);
static int get_confirmation(const char *title, const char *text);

// Authentication functions
static int get_username(char *username, int size);
static int get_password(char *password, int size);
static int authenticate(void);

// Validation functions
static int validate_input(const char *input, int min_len, int max_len, const char *error_prefix);
static int validate_buffer_size(const char *input, uint8_t *buffer_size);
static int validate_timeout(const char *input, uint8_t *timeout_value);

// Server interaction functions
static void show_metrics(void);
static void show_logs(void);
static void show_user_list(void);

// Server configuration functions
static void change_buffer_size(void);
static void change_timeout(void);
static void show_config(void);

// User management functions
static int find_user(const char *username);
static int select_user(const char *title, const char *text, int exclude_admin);
static int add_user(void);
static int remove_user(void);

// Menu functions
static void manage_users(void);
static void configure_settings(void);
static void admin_menu(void);
static int confirm_exit(void);

static void show_message(const char *title, const char *message) {
	char command[1024];
	snprintf(command, sizeof(command), "whiptail --title \"%s\" --msgbox \"%s\" 8 45", title, message);
	system(command);
}

static char *get_input(const char *title, const char *text, int hidden) {
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

static int get_menu_selection(const char *title, const char *text, char items[][2][64], int count) {
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

static int get_confirmation(const char *title, const char *text) {
	char command[1024];
	snprintf(command, sizeof(command), "whiptail --title \"%s\" --yesno \"%s\" 8 45", title, text);
	return (system(command) == 0);
}

static int validate_input(const char *input, int min_len, int max_len, const char *error_prefix) {
	if (!input || strlen(input) == 0) {
		char msg[256];
		snprintf(msg, sizeof(msg), "%s cannot be empty", error_prefix);
		show_message("Error", msg);
		return 0;
	}

	size_t len = strlen(input);

	if (len < (size_t) min_len) {
		char msg[256];
		snprintf(msg, sizeof(msg), "%s must be at least %d characters long", error_prefix, min_len);
		show_message("Error", msg);
		return 0;
	}

	if (len >= (size_t) max_len) {
		char msg[256];
		snprintf(msg, sizeof(msg), "%s must be less than %d characters long", error_prefix, max_len);
		show_message("Error", msg);
		return 0;
	}
	return 1;
}

static int validate_timeout(const char *input, uint8_t *timeout_value) {
    if (!input || strlen(input) == 0) {
        show_message("Error", "Timeout cannot be empty");
        return 0;
    }

    for (size_t i = 0; i < strlen(input); i++) {
        if (!isdigit((unsigned char)input[i])) {
            show_message("Error", "Timeout must contain only numbers");
            return 0;
        }
    }

    char *endptr;
    long value = strtol(input, &endptr, 10);
    
    if (*endptr != '\0') {
        show_message("Error", "Invalid timeout format");
        return 0;
    }

    if (value < 1) {
        show_message("Error", "Timeout must be at least 1 second");
        return 0;
    }

    if (value > 255) {
        show_message("Error", "Timeout cannot exceed 255 seconds");
        return 0;
    }

    *timeout_value = (uint8_t)value;
    return 1;
}

static int validate_buffer_size(const char *input, uint8_t *buffer_size) {
    if (!input || strlen(input) == 0) {
        show_message("Error", "Buffer size cannot be empty");
        return 0;
    }

    for (size_t i = 0; i < strlen(input); i++) {
        if (!isdigit((unsigned char)input[i])) {
            show_message("Error", "Buffer size must contain only numbers");
            return 0;
        }
    }

    char *endptr;
    long value = strtol(input, &endptr, 10);
    
    if (*endptr != '\0') {
        show_message("Error", "Invalid buffer size format");
        return 0;
    }

    if (value < 1) {
        show_message("Error", "Buffer size must be at least 1 KB");
        return 0;
    }

    if (value > 255) {
        show_message("Error", "Buffer size cannot exceed 255 KB");
        return 0;
    }

    if (value < 4) {
        char warning_msg[256];
        snprintf(warning_msg, sizeof(warning_msg), 
                 "Warning: Buffer size %ld KB is very small. Recommended minimum is 4 KB.", value);
        show_message("Warning", warning_msg);
    }

    *buffer_size = (uint8_t)value;
    return 1;
}

static int select_user(const char *title, const char *text, int exclude_admin) {
	/*
	char items[MAX_USERS][2][64];
	int count = 0;

	for (int i = 0; i < user_count; i++) {
		if (exclude_admin && strcmp(users[i].username, "nep") == 0)
			continue;

		snprintf(items[count][0], 64, "%d", count + 1);
		snprintf(items[count][1], 64, "%s (%s)", users[i].username, users[i].role);
		count++;
	}

	if (count == 0) {
		show_message("Info", "No users available for this operation.");
		return -1;
	}

	int selected = get_menu_selection(title, text, items, count);
	if (selected <= 0 || selected > count)
		return -1;

	int actual_index = 0;
	for (int i = 0; i < user_count; i++) {
		if (exclude_admin && strcmp(users[i].username, "nep") == 0)
			continue;
		actual_index++;
		if (actual_index == selected)
			return i;
	}
	return -1;
	*/
}

static int find_user(const char *username) {
	/*
	for (int i = 0; i < user_count; i++) {
		if (strcmp(users[i].username, username) == 0) {
			return i;
		}
	}
	return -1;
	*/
}

static int get_username(char *username, int size) {
	char *input = get_input("Login", "Enter username:", 0);
	if (!input) {
		return -1;
	}
	strncpy(username, input, size - 1);
	username[size - 1] = '\0';
	return 0;
}

static int get_password(char *password, int size) {
	char *input = get_input("Login", "Enter password:", 1);
	if (!input) {
		return -1;
	}
	strncpy(password, input, size - 1);
	password[size - 1] = '\0';
	return 0;
}

static void show_user_list() {
	if (server_socket < 0) {
        show_message("Error", "No server connection");
        return;
    }

	user_list_entry *users = handle_get_users(10, 0, server_socket);	// TODO: make this paginated
    if (users == NULL) {
        show_message("Info", "No users available or failed to retrieve user list");
        return;
    }

    char users_info[2048];
    char user_list[1536] = "";
    user_list_entry *current = users;
    int count = 0;

    while (current != NULL && count < 10) {
        char user_line[128];
        const char *role = (current->user_type == 1) ? "Administrator" : "User";
        snprintf(user_line, sizeof(user_line), "%d. %.*s (%s)\\n", 
                 count + 1, current->ulen, current->username, role);
        strcat(user_list, user_line);
        current = current->next;
        count++;
    }

    snprintf(users_info, sizeof(users_info),
             "Server Users:\\n%s\\nTotal users: %d\\n\\n"
             "Press OK to continue",
             user_list, count);

    char command[3072];
    snprintf(command, sizeof(command), "whiptail --title \"User List\" --msgbox \"%s\" 15 60", users_info);
    system(command);

    free_user_list(users);
}

static void show_metrics() {
	if (server_socket < 0) {
        show_message("Error", "No server connection");
        return;
    }
	 
	metrics server_metrics;
    if (handle_metrics(server_socket, &server_metrics) == NULL) {
        show_message("Error", "Failed to retrieve server metrics");
        return;
    }

    char status_info[2048];
    snprintf(status_info, sizeof(status_info),
             "Server status: %s\\n"
             "Current connections: %u\\n"
             "Total connections: %u\\n"
             "Bytes received: %u\\n"
             "Bytes sent: %u\\n"
             "Timeouts: %u\\n"
             "Server errors: %u\\n"
             "Bad requests: %u\\n\\n"
             "Press OK to continue",
             server_metrics.server_state == 1 ? "Running" : "Stopped",
             server_metrics.n_current_connections,
             server_metrics.n_total_connections,
             server_metrics.n_total_bytes_received,
             server_metrics.n_total_bytes_sent,
             server_metrics.n_timeouts,
             server_metrics.n_server_errors,
             server_metrics.n_bad_requests);

	char command[3072];
	snprintf(command, sizeof(command), "whiptail --title \"View Metrics\" --msgbox \"%s\" 13 50", status_info);
	system(command);
}

static void show_config() {
	char config_info[1024];
	snprintf(config_info, sizeof(config_info),
			 "SOCKS5 Port: 1080\\n"
			 "Admin Port: 8080\\n"
			 "Bind Address: 0.0.0.0\\n"
			 "Max Connections: 100\\n"
			 "Connection Timeout: 30 seconds\\n"
			 "Buffer Size: 8192 bytes\\n\\n"
			 "Press OK to continue");

	char command[2048];
	snprintf(command, sizeof(command), "whiptail --title \"Server Configuration\" --msgbox \"%s\" 12 50", config_info);
	system(command);
}

static void show_logs() {
    if (server_socket < 0) {
        show_message("Error", "No server connection");
        return;
    }

    log_strct *logs = handle_log(server_socket, 10, 0); // TODO: make this paginated
    if (logs == NULL) {
        show_message("Info", "No logs available");
        return;
    }

    char logs_info[2048];
    char log_list[1536] = "";
    log_strct *current = logs;
    int count = 0;

    while (current != NULL && count < 10) {
        char log_line[600];
        snprintf(log_line, sizeof(log_line), "%d. %s -> %s:%d\\n", 
                 count + 1, current->username, 
                 current->destination_address, current->destination_port);
        strcat(log_list, log_line);
        current = current->next;
        count++;
    }

    snprintf(logs_info, sizeof(logs_info), "Recent server logs:\\n%s\\nPress OK to continue", log_list);

    char command[3072];
    snprintf(command, sizeof(command), "whiptail --title \"Server logs\" --msgbox \"%s\" 15 60", logs_info);
    system(command);

    free_log_list(logs);
}

static void manage_users() {
	while (1) {
		char items[4][2][64] = {
			{"1", "List all users"}, {"2", "Add new user"}, {"3", "Remove user"}, {"4", "Back to main menu"}};

		int selected = get_menu_selection("Manage users", "Select an option:", items, 4);
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
				show_message("Error", "Invalid option");
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

        int selected = get_menu_selection("Server Settings", "Select an option:", items, 3);
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
                show_message("Error", "Invalid option");
                break;
        }
    }
}

static void change_buffer_size() {
    if (server_socket < 0) {
        show_message("Error", "No server connection");
        return;
    }

    char *input = get_input("Buffer Size", "Enter new buffer size (KB):", 0);
    if (!input) {
        return;
    }

    uint8_t new_size;
    if (!validate_buffer_size(input, &new_size)) {
        return;
    }
    
    char confirm_msg[256];
    snprintf(confirm_msg, sizeof(confirm_msg), 
             "Are you sure you want to change buffer size to %d KB?", new_size);
    
    if (!get_confirmation("Confirm Change", confirm_msg)) {
        show_message("Info", "Buffer size change cancelled.");
        return;
    }

    uint8_t result = handle_change_buffer_size(server_socket, new_size);
    
    if (result == 0) {
        char success_msg[256];
        snprintf(success_msg, sizeof(success_msg), 
                 "Buffer size successfully changed to %d KB.", new_size);
        show_message("Success", success_msg);
    } else {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), 
                 "Failed to change buffer size. Error code: %d", result);
        show_message("Error", error_msg);
    }
}

static void change_timeout() {
    if (server_socket < 0) {
        show_message("Error", "No server connection");
        return;
    }

    char *input = get_input("Timeout", "Enter new timeout (seconds):", 0);
    if (!input) {
        return;
    }

    uint8_t new_timeout;
    if (!validate_timeout(input, &new_timeout)) {
        return;
    }
    
    char confirm_msg[256];
    snprintf(confirm_msg, sizeof(confirm_msg), 
             "Are you sure you want to change timeout to %d seconds?", new_timeout);
    
    if (!get_confirmation("Confirm Change", confirm_msg)) {
        show_message("Info", "Timeout change cancelled.");
        return;
    }

    uint8_t result = handle_change_timeout(server_socket, new_timeout);
    
    if (result == 0) {
        char success_msg[256];
        snprintf(success_msg, sizeof(success_msg), 
                 "Timeout successfully changed to %d seconds.", new_timeout);
        show_message("Success", success_msg);
    } else {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), 
                 "Failed to change timeout. Error code: %d", result);
        show_message("Error", error_msg);
    }
}

static void admin_menu() {
    while (1) {
        char items[5][2][64] = {
            {"1", "View metrics"}, 
            {"2", "View logs"}, 
            {"3", "Manage users"}, 
            {"4", "Manage settings"}, 
            {"5", "Exit"}
        };

        int selected = get_menu_selection("Admin interface", "Select an option:", items, 5);
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
                show_message("Error", "Invalid option");
                break;
        }
    }
}

static int confirm_exit() {
	return get_confirmation("Confirm", "Are you sure you want to exit?");
}

static int authenticate() {
	char username[MAX_INPUT], password[MAX_INPUT];

	server_socket = setup_tcp_client_Socket(server_address, server_port);
    if (server_socket < 0) {
        show_message("Error", "Failed to connect to server");
        return 0;
    }

	for (int attempts = 0; attempts < 3; attempts++) {
		if (get_username(username, sizeof(username)) != 0) {
			close(server_socket);
			return 0;
		}
		if (strlen(username) == 0) {
			show_message("Error", "Username cannot be empty");
			continue;
		}

		if (get_password(password, sizeof(password)) != 0) {
			close(server_socket);
			return 0;
		}
		if (strlen(password) == 0) {
			show_message("Error", "Password cannot be empty");
			continue;
		}

		// Hello message
		if (hello_send(username, password, server_socket) != 0) {
            show_message("Error", "Failed to send authentication");
            close(server_socket);
            return 0;
        }

		// Hello response
		int auth_result = hello_read(server_socket);
        if (auth_result == 1) { // Admin user
            show_message("Success", "Authentication successful. Welcome to the admin panel.");
            return 1;
        } else if (auth_result == 0) { // Regular user
            show_message("Info", "Authenticated as regular user. Admin privileges required.");
            close(server_socket);
            return 0;
        }

		if (attempts < 2) {
			char error_msg[256];
			snprintf(error_msg, sizeof(error_msg), "Incorrect credentials. Attempts remaining: %d", 2 - attempts);
			show_message("Error", error_msg);
		}

		memset(username, 0, sizeof(username));
		memset(password, 0, sizeof(password));
	}

	show_message("Error", "Maximum number of attempts reached. Access denied.");
	close(server_socket);
	return 0;
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

int main() {
	show_message("Welcome", "SOCKS5 server admin interface. \nPress OK to continue");

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