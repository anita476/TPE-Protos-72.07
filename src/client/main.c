// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "include/client_constants.h"
#include "include/lib_client.h"
#include "include/pagination.h"
#include "include/ui_adapter.h"
#include "include/validation.h"

#define MAX_ATTEMPTS 3

#define MENU_ITEM_LABEL_LEN 64
#define MENU_ITEM_FIELDS 2

static int server_socket = -1;
static char server_address[256] = DEFAULT_SERVER_ADDRESS;
static char server_port[16] = DEFAULT_SERVER_PORT;
static int use_console_ui = UI_MODE_DIALOG;

// Connection functions
static int handle_connection_lost();

// Authentication functions
static int get_user_input(const char *title, const char *prompt, int is_password, char *output, int size);
static int get_username(char *username, int size);
static int get_password(char *password, int size);
static int authenticate(void);

// Pagination functions
static void *fetch_users(int items_per_page, int offset, int socket);
static void *fetch_logs(int items_per_page, int offset, int socket);
static void display_users(void *data, int count, int page);
static void display_logs(void *data, int count, int page);
static void free_users(void *data);
static void free_logs(void *data);
static int count_users(void *data);
static int count_logs(void *data);

// Server interaction functions
static void show_metrics(void);
static void show_logs(void);
static void show_users(void);
static void show_config(void);

// User management functions
static int add_user(void);
static int remove_user(void);

// Server configuration functions
static void change_server_setting(const char *setting_name, const char *unit,
								  int (*validate_func)(const char *, uint8_t *), uint8_t (*handle_func)(int, uint8_t));
static void change_buffer_size(void);
static void change_timeout(void);

// Menu functions
static void admin_menu(void);
static int confirm_exit(void);
static void manage_users(void);
static void configure_settings(void);

// Argument functions
static int parse_arguments(int argc, char *argv[]);
static void print_usage(void);

/* Connection functions */

static int handle_connection_lost() {
	if (ui_get_confirmation("Reconnect", "Connection with the server was lost. ¿Do you wish to reconnect?")) {
		if (server_socket >= 0) {
			close(server_socket);
			server_socket = -1;
		}
		if (authenticate()) {
			return 1;
		}
	}
	server_socket = -1;
	return 0;
}

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
	return get_user_input("Login", "Enter password (hidden only in Dialog GUI):", 1, password, size);
}

static int authenticate() {
	char username[MAX_INPUT], password[MAX_INPUT];

	for (int attempts = 0; attempts < MAX_ATTEMPTS; attempts++) {
		server_socket = setup_tcp_client_socket(server_address, server_port);
		if (server_socket < 0) {
			ui_show_message("Error", "Failed to connect to server");
			return 0;
		}

		if (get_username(username, sizeof(username)) != 0) {
			close(server_socket);
			return 0;
		}
		if (strlen(username) == 0) {
			ui_show_message("Error", "Username cannot be empty");
			close(server_socket);
			continue;
		}

		if (get_password(password, sizeof(password)) != 0) {
			close(server_socket);
			return 0;
		}
		if (strlen(password) == 0) {
			ui_show_message("Error", "Password cannot be empty");
			close(server_socket);
			continue;
		}

		if (hello_send(username, password, server_socket) != 0) {
			ui_show_message("Error", "Failed to send authentication");
			close(server_socket);
			return 0;
		}

		int auth_result = hello_read(server_socket);
		if (auth_result == RESPONSE_SUCCESS_ADMIN) {
			ui_show_message("Success", "Authentication successful. Welcome to the admin panel.");
			return 1;
		} else if (auth_result == RESPONSE_SUCCESS_CLIENT) {
			ui_show_message("Info", "Authenticated as regular user. Admin privileges required.");
			close(server_socket);
			return 0;
		}

		close(server_socket);

		if (attempts < MAX_ATTEMPTS - 1) {
			char error_msg[BUFFER_XS];
			snprintf(error_msg, sizeof(error_msg), "Incorrect credentials. Attempts remaining: %d",
					 MAX_ATTEMPTS - 1 - attempts);
			ui_show_message("Error", error_msg);
		}

		memset(username, 0, sizeof(username));
		memset(password, 0, sizeof(password));
	}

	ui_show_message("Error", "Maximum number of attempts reached. Access denied.");
	return 0;
}

/* Pagination functions */

static void *fetch_users(int items_per_page, int offset, int socket) {
	return handle_get_users(items_per_page, offset, socket);
}

static void *fetch_logs(int items_per_page, int offset, int socket) {
	return handle_log(socket, items_per_page, offset);
}

static int count_users(void *data) {
	int count = 0;
	user_list_entry *current = (user_list_entry *) data;
	while (current != NULL) {
		count++;
		current = current->next;
	}
	return count;
}

static int count_logs(void *data) {
	int count = 0;
	client_log_entry_t *current = (client_log_entry_t *) data;
	while (current != NULL) {
		count++;
		current = current->next;
	}
	return count;
}

static void display_users(void *data, int count, int page) {
	if (count == 0) {
		return;
	}

	char users_info[BUFFER_XXL];
	char user_list[BUFFER_XL] = "";
	user_list_entry *current = (user_list_entry *) data;
	int display_count = 0;
	int start_index = page * ITEMS_PER_PAGE;

	while (current != NULL && display_count < MAX_DISPLAY_ITEMS) {
		const char *role = (current->user_type == 1) ? "Administrator" : "User";
		char user_line[BUFFER_XS];
		snprintf(user_line, sizeof(user_line), "%d. %.*s (%s)\n", start_index + display_count + 1, current->ulen,
				 current->username, role);
		strncat(user_list, user_line, sizeof(user_list) - strlen(user_list) - 1);
		current = current->next;
		display_count++;
	}

	snprintf(users_info, sizeof(users_info),
			 "Server users (Page %d):\n%s\n"
			 "Showing %d of %d users on this page\n\n"
			 "Press OK to continue",
			 page + 1, user_list, display_count, count);

	ui_show_message("User list", users_info);
}

static void display_logs(void *data, int count, int page) {
	if (count == 0) {
		return;
	}

	char logs_info[BUFFER_XXL];
	char log_list[BUFFER_XL] = "";
	client_log_entry_t *current = (client_log_entry_t *) data;
	int display_count = 0;
	int start_index = page * ITEMS_PER_PAGE;

	while (current != NULL && display_count < MAX_DISPLAY_ITEMS) {
		char log_line[BUFFER_L];

		snprintf(log_line, sizeof(log_line),
				 "%d.\n"
				 "  Date: %s\n"
				 "  User: %s\n"
				 "  Type: %c\n"
				 "  Origin IP: %s\n"
				 "  Origin port: %d\n"
				 "  Destination: %s\n"
				 "  Destination port: %d\n"
				 "  Status code: %s\n\n",
				 start_index + display_count + 1, current->date, current->username, current->register_type,
				 current->origin_ip, current->origin_port, current->destination_address, current->destination_port,
				 current->status_code);

		strncat(log_list, log_line, sizeof(log_list) - strlen(log_list) - 1);
		current = current->next;
		display_count++;
	}

	snprintf(logs_info, sizeof(logs_info),
			 "Server logs (Page %d):\n%s\n"
			 "Showing %d of %d logs on this page\n\n"
			 "Press OK to continue",
			 page + 1, log_list, display_count, count);

	ui_show_message("Server logs", logs_info);
}

static void free_users(void *data) {
	free_user_list((user_list_entry *) data);
}

static void free_logs(void *data) {
	free_log_list((client_log_entry_t *) data);
}

/* Server interaction functions */

static void show_metrics() {
	metrics_t server_metrics;
	if (server_socket < 0) {
		if (handle_connection_lost()) {
			show_metrics();
		}
		return;
	}
	if (handle_metrics(server_socket, &server_metrics) == NULL) {
		if (handle_connection_lost()) {
			show_metrics();
		}
		return;
	}

	char status_info[BUFFER_XL];
	snprintf(status_info, sizeof(status_info),
			 "Server status: %s\n"
			 "Current connections: %u\n"
			 "Total connections: %u\n"
			 "Max concurrent connections: %u\n"
			 "Bytes received: %" PRIu64 "\n"
			 "Bytes sent: %" PRIu64 "\n"
			 "Total bytes: %" PRIu64 "\n"
			 "Total errors: %u\n"
			 "Uptime: %u seconds\n"
			 "Network errors: %u\n"
			 "Protocol errors: %u\n"
			 "Auth errors: %u\n"
			 "System errors: %u\n"
			 "Timeout errors: %u\n"
			 "Memory errors: %u\n"
			 "Other errors: %u\n\n"
			 "Press OK to continue",
			 server_metrics.server_state == 1 ? "Running" : "Stopped", server_metrics.concurrent_connections,
			 server_metrics.total_connections, server_metrics.max_concurrent_connections,
			 server_metrics.bytes_transferred_in, server_metrics.bytes_transferred_out,
			 server_metrics.total_bytes_transferred, server_metrics.total_errors, server_metrics.uptime_seconds,
			 server_metrics.network_errors, server_metrics.protocol_errors, server_metrics.auth_errors,
			 server_metrics.system_errors, server_metrics.timeout_errors, server_metrics.memory_errors,
			 server_metrics.other_errors);

	ui_show_message("Server metrics", status_info);
}

static void show_users() {
	if (server_socket < 0) {
		if (handle_connection_lost()) {
			show_users();
		}
		return;
	}

	pagination_config_t config = {.title_format = "User list - Page %d",
								  .no_data_message = "No users available",
								  .no_more_data_message = "No more users available",
								  .nav_prompt = "Choose navigation option:",
								  .fetch_func = fetch_users,
								  .display_func = display_users,
								  .free_func = free_users,
								  .count_func = count_users};

	handle_pagination(&config, server_socket, ITEMS_PER_PAGE);

	if (errno == ENOTCONN) {
		server_socket = -1;
		if (handle_connection_lost()) {
			show_users();
		}
	}
}

static void show_logs() {
	if (server_socket < 0) {
		if (handle_connection_lost()) {
			show_logs();
		}
		return;
	}

	pagination_config_t config = {.title_format = "Server logs - Page %d",
								  .no_data_message = "No logs available",
								  .no_more_data_message = "No more logs available",
								  .nav_prompt = "Choose navigation option:",
								  .fetch_func = fetch_logs,
								  .display_func = display_logs,
								  .free_func = free_logs,
								  .count_func = count_logs};

	handle_pagination(&config, server_socket, ITEMS_PER_PAGE);

	if (errno == ENOTCONN) {
		server_socket = -1;
		if (handle_connection_lost()) {
			show_logs();
		}
	}
}

static void show_config() {
	if (server_socket < 0) {
		if (handle_connection_lost()) {
			show_config();
		}
		return;
	}
	server_current_config server_config;
	if (handle_get_current_config(server_socket, &server_config) == NULL) {
		if (handle_connection_lost()) {
			show_config();
		}
		return;
	}

	char config_info[BUFFER_L];

	snprintf(config_info, sizeof(config_info),
			 "Current connection:\n"
			 "Server address: %s\n"
			 "Admin port: %s\n\n"
			 "Server configuration:\n"
			 "Connection timeout: %u seconds\n"
			 "Buffer size: %u KB\n\n"
			 "Press OK to continue",
			 server_address, server_port, server_config.timeout_seconds, server_config.buffer_size_kb);

	ui_show_message("Server Configuration", config_info);
}

/* User management functions */

static int add_user() {
	char username[MAX_INPUT], password[MAX_INPUT];
	if (server_socket < 0) {
		if (handle_connection_lost()) {
			return add_user();
		} else {
			return 0;
		}
	}

	if (get_user_input("Username", "Enter username:", 0, username, sizeof(username)) != 0) {
		return 0;
	}

	if (!validate_username(username)) {
		return 0;
	}

	if (get_user_input("Password", "Enter password:", 1, password, sizeof(password)) != 0) {
		return 0;
	}

	if (!validate_password(password)) {
		return 0;
	}

	char confirm_password[MAX_INPUT];
	if (get_user_input("Confirm password", "Confirm your password:", 1, confirm_password, sizeof(confirm_password)) !=
		0) {
		return 0;
	}

	if (strcmp(password, confirm_password) != 0) {
		ui_show_message("Error", "Passwords do not match. Please try again.");
		return 0;
	}

	int result = handle_add_client(server_socket, username, password);
	if (result == RESPONSE_GENERAL_SERVER_FAILURE) {
		if (handle_connection_lost()) {
			return add_user();
		}
		return 0;
	}
	if (result != RESPONSE_SUCCESS) {
		if (result == RESPONSE_USER_ALREADY_EXISTS) {
			ui_show_message("Error", "User already exists.");
			return 0;
		}
		ui_show_message("Error", "Failed to add user. Please try again.");
		return 0;
	}

	char success_msg[BUFFER_M];
	snprintf(success_msg, sizeof(success_msg), "User '%s' has been successfully added to the system.", username);
	ui_show_message("Success", success_msg);

	return 1;
}

static int remove_user() {
	char selected_user[MAX_USERNAME_LEN];
	if (server_socket < 0) {
		if (handle_connection_lost()) {
			return remove_user();
		} else {
			return 0;
		}
	}

	if (get_user_input("Remove user", "Enter the username to remove:", 0, selected_user, sizeof(selected_user)) != 0) {
		ui_show_message("Info", "User removal cancelled.");
		return 0;
	}

	char confirm_msg[BUFFER_XS];
	snprintf(confirm_msg, sizeof(confirm_msg),
			 "Are you sure you want to remove user '%s'?\n\nThis action cannot be undone.", selected_user);

	if (ui_get_confirmation("Confirm removal", confirm_msg)) {
		int result = handle_remove_user(server_socket, selected_user);
		if (result == RESPONSE_GENERAL_SERVER_FAILURE) {
			if (handle_connection_lost()) {
				return remove_user();
			}
			return 0;
		}
		if (result == RESPONSE_SUCCESS) {
			char success_msg[BUFFER_XS];
			snprintf(success_msg, sizeof(success_msg), "User '%s' has been successfully removed from the system.",
					 selected_user);
			ui_show_message("Success", success_msg);
			return 1;
		} else if (result == RESPONSE_USER_NOT_FOUND) {
			ui_show_message("Error", "User not found.");
		} else if (result == RESPONSE_NOT_ALLOWED) {
			ui_show_message("Error", "You are not allowed to remove this user.");
		} else {
			ui_show_message("Error", "Failed to remove user. Please try again.");
		}
		return 0;
	}

	ui_show_message("Info", "User removal cancelled.");
	return 0;
}

/* Server configuration functions */

static void change_server_setting(const char *setting_name, const char *unit,
								  int (*validate_func)(const char *, uint8_t *), uint8_t (*handle_func)(int, uint8_t)) {
	if (server_socket < 0) {
		if (handle_connection_lost()) {
			change_server_setting(setting_name, unit, validate_func, handle_func);
		}
		return;
	}

	char prompt[BUFFER_XS];
	snprintf(prompt, sizeof(prompt), "Enter new %s (%s):", setting_name, unit);

	char *input = ui_get_input(setting_name, prompt, 0);
	if (!input) {
		return;
	}

	uint8_t new_value;
	if (!validate_func(input, &new_value)) {
		return;
	}

	char confirm_msg[BUFFER_XS];
	snprintf(confirm_msg, sizeof(confirm_msg), "Are you sure you want to change %s to %d %s?", setting_name, new_value,
			 unit);

	if (!ui_get_confirmation("Confirm change", confirm_msg)) {
		char cancel_msg[BUFFER_XS];
		snprintf(cancel_msg, sizeof(cancel_msg), "%s change cancelled.", setting_name);
		ui_show_message("Info", cancel_msg);
		return;
	}

	uint8_t result = handle_func(server_socket, new_value);
	if (result == RESPONSE_GENERAL_SERVER_FAILURE) {
		if (handle_connection_lost()) {
			change_server_setting(setting_name, unit, validate_func, handle_func);
		}
		return;
	}

	if (result == RESPONSE_SUCCESS || result == RESPONSE_SUCCESS_ADMIN || result == RESPONSE_SUCCESS_CLIENT) {
		char success_msg[BUFFER_XS];
		snprintf(success_msg, sizeof(success_msg), "%s successfully changed to %d %s.", setting_name, new_value, unit);
		ui_show_message("Success", success_msg);
	} else {
		char error_msg[BUFFER_XS];
		snprintf(error_msg, sizeof(error_msg), "Failed to change %s. Error code: %d", setting_name, result);
		ui_show_message("Error", error_msg);
	}
}

static void change_buffer_size() {
	change_server_setting("Buffer size", "KB", validate_buffer_size, handle_change_buffer_size);
}

static void change_timeout() {
	change_server_setting("Timeout", "seconds", validate_timeout, handle_change_timeout);
}

/* Menu functions */
static int is_dialog_installed() {
	int i = system("which dialog > /dev/null 2>&1");
	return (i == 0);
}

static void admin_menu() {
	while (1) {
		char items[5][MENU_ITEM_FIELDS][MENU_ITEM_LABEL_LEN] = {
			{"1", "View metrics"}, {"2", "View logs"}, {"3", "Manage users"}, {"4", "Manage settings"}, {"5", "Exit"}};

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
		char items[4][MENU_ITEM_FIELDS][MENU_ITEM_LABEL_LEN] = {
			{"1", "List all users"}, {"2", "Add new user"}, {"3", "Remove user"}, {"4", "Back to main menu"}};

		int selected = ui_get_menu_selection("Manage users", "Select an option:", items, 4);
		if (selected == -1 || selected == 4)
			return;

		switch (selected) {
			case 1:
				show_users();
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
		char items[4][MENU_ITEM_FIELDS][MENU_ITEM_LABEL_LEN] = {{"1", "Show configurations"},
																{"2", "Change buffer size"},
																{"3", "Change timeout"},
																{"4", "Back to main menu"}};

		int selected = ui_get_menu_selection("Server settings", "Select an option:", items, 4);
		if (selected == -1 || selected == 4)
			return;

		switch (selected) {
			case 1:
				show_config();
				break;
			case 2:
				change_buffer_size();
				break;
			case 3:
				change_timeout();
				break;
			default:
				ui_show_message("Error", "Invalid option");
				break;
		}
	}
}

/* Argument functions */

static int parse_arguments(int argc, char *argv[]) {
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--host") == 0) {
			if (i + 1 >= argc) {
				fprintf(stderr, "Error: Option %s requires an argument\n", argv[i]);
				return -1;
			}
			strncpy(server_address, argv[i + 1], sizeof(server_address) - 1);
			server_address[sizeof(server_address) - 1] = '\0';
			i++;
		} else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--port") == 0) {
			if (i + 1 >= argc) {
				fprintf(stderr, "Error: Option %s requires an argument\n", argv[i]);
				return -1;
			}

			char *endptr;
			long port = strtol(argv[i + 1], &endptr, 10);
			if (*endptr != '\0' || port < MIN_PORT || port > MAX_PORT) {
				fprintf(stderr, "Error: Invalid port number '%s'. Must be between 1 and 65535\n", argv[i + 1]);
				return -1;
			}

			strncpy(server_port, argv[i + 1], sizeof(server_port) - 1);
			server_port[sizeof(server_port) - 1] = '\0';
			i++;
		} else if (strcmp(argv[i], "--console") == 0) {
			use_console_ui = UI_MODE_CONSOLE;
		} else if (strcmp(argv[i], "--help") == 0) {
			print_usage();
			return 1;
		} else {
			fprintf(stderr, "Error: Unknown option '%s'\n", argv[i]);
			print_usage();
			return -1;
		}
	}
	return 0;
}

static void print_usage(void) {
	printf("Usage: client [-h host] [-p port] [--console]\n");
	printf("Options:\n");
	printf("  -h host      Server hostname or IP address (default: %s)\n", DEFAULT_SERVER_ADDRESS);
	printf("  -p port      Server port number (default: %s)\n", DEFAULT_SERVER_PORT);
	printf("  --console    Use console UI instead of Dialog\n");
	printf("  --help       Show this help message\n");
	printf("\nExample:\n");
	printf("  client -h 192.168.1.100 -p 9090\n");
	printf("  client --console\n");
	printf("  client -h server.com -p 8080 --console\n");
}

/* Main */

int main(int argc, char *argv[]) {
	int parse_result = parse_arguments(argc, argv);
	if (parse_result != 0) {
		return (parse_result == 1) ? 0 : 1;
	}

	if (use_console_ui != UI_MODE_CONSOLE && !is_dialog_installed()) {
		fprintf(stderr, "Error: Dialog is not installed. Please install it to use the interactive UI.\n");
		fprintf(stderr, "You can also use --console to enter console UI mode.\n");
		return 2;
	}

	ui_init(use_console_ui);

	char welcome_msg[BUFFER_M];
	snprintf(welcome_msg, sizeof(welcome_msg),
			 "SOCKS5 server admin interface\n\n"
			 "UI Mode: %s\n"
			 "Connecting to: %s:%s\n\n"
			 "Press OK to continue",
			 use_console_ui ? "Console" : "Dialog", server_address, server_port);

	ui_show_message("Welcome", welcome_msg);

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