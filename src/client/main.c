#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_INPUT 256
#define MAX_USERS 10
#define MAX_USERNAME 24
#define TEMP_FILE "/tmp/whiptail_input"

typedef struct {
	char username[MAX_USERNAME];
	char role[16];
} User;

static User users[MAX_USERS] = {{"nep", "Administrator"}, {"user1", "User"}, {"user2", "User"}, {"guest", "User"}};

static int user_count = 4;

// Helper functions
static void show_message(const char *title, const char *message);
static char *get_input(const char *title, const char *text, int hidden);
static int get_menu_selection(const char *title, const char *text, char items[][2][64], int count);
static int get_confirmation(const char *title, const char *text);
static int select_user(const char *title, const char *text, int exclude_admin);
static int validate_input(const char *input, int min_len, int max_len, const char *error_prefix);
static int find_user(const char *username);
static int verify_credentials(const char *username, const char *password);
static int get_username(char *username, int size);
static int get_password(char *password, int size);
static int confirm_exit(void);

// Menu functions
static void show_user_list(void);
static void show_metrics(void);
static void show_server_config(void);
static int add_user(void);
static int remove_user(void);
static void manage_users(void);
static void configure_settings(void);
static void admin_menu(void);
static int authenticate(void);

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
				if (newline)
					*newline = '\0';
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

static int select_user(const char *title, const char *text, int exclude_admin) {
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
}

static int find_user(const char *username) {
	for (int i = 0; i < user_count; i++) {
		if (strcmp(users[i].username, username) == 0) {
			return i;
		}
	}
	return -1;
}

static int verify_credentials(const char *username, const char *password) {
	return (strcmp(username, "admin") == 0 && strcmp(password, "admin") == 0) ||
		   (strcmp(username, "nep") == 0 && strcmp(password, "nep") == 0);
}

static int get_username(char *username, int size) {
	char *input = get_input("Login", "Enter username:", 0);
	if (!input)
		return -1;
	strncpy(username, input, size - 1);
	username[size - 1] = '\0';
	return 0;
}

static int get_password(char *password, int size) {
	char *input = get_input("Login", "Enter password:", 1);
	if (!input)
		return -1;
	strncpy(password, input, size - 1);
	password[size - 1] = '\0';
	return 0;
}

static void show_server_config() {
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

static void show_user_list() {
	char users_info[1024];
	char user_list[512] = "";

	for (int i = 0; i < user_count; i++) {
		char user_line[64];
		snprintf(user_line, sizeof(user_line), "%d. %s (%s)\\n", i + 1, users[i].username, users[i].role);
		strcat(user_list, user_line);
	}

	snprintf(users_info, sizeof(users_info),
			 "%s\\nTotal users: %d\\n\\n"
			 "Press OK to continue",
			 user_list, user_count);

	char command[2048];
	snprintf(command, sizeof(command), "whiptail --title \"User List\" --msgbox \"%s\" 10 50", users_info);
	system(command);
}

static void show_metrics() {
	char status_info[2048];

	snprintf(status_info, sizeof(status_info),
			 "Server status: Running\\n"
			 "SOCKS5 port: Active\\n"
			 "Admin port: Active\\n"
			 "Current connections: 15\\n"
			 "Total connections: 1,234\\n"
			 "Bytes transferred: 2.5 GB\\n"
			 "Server uptime: 5 days, 12 hours\\n"
			 "Active users: %d\\n\\n"
			 "Press OK to continue",
			 user_count);

	char command[3072];
	snprintf(command, sizeof(command), "whiptail --title \"View Metrics\" --msgbox \"%s\" 13 50", status_info);
	system(command);
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
		char items[4][2][64] = {{"1", "Server configuration"},
								{"2", "Logging settings"},
								{"3", "Security settings"},
								{"4", "Back to main menu"}};

		int selected = get_menu_selection("Manage settings", "Select an option:", items, 4);
		if (selected == -1 || selected == 4)
			return;

		switch (selected) {
			case 1:
				show_server_config();
				break;
			case 2:
				show_message("Info", "Logging settings not implemented yet");
				break;
			case 3:
				show_message("Info", "Security settings not implemented yet");
				break;
			default:
				show_message("Error", "Invalid option");
				break;
		}
	}
}

static void admin_menu() {
	while (1) {
		char items[4][2][64] = {{"1", "View metrics"}, {"2", "Manage users"}, {"3", "Manage settings"}, {"4", "Exit"}};

		int selected = get_menu_selection("Admin interface", "Select an option:", items, 4);
		if (selected == -1)
			break;

		switch (selected) {
			case 1:
				show_metrics();
				break;
			case 2:
				manage_users();
				break;
			case 3:
				configure_settings();
				break;
			case 4:
				if (confirm_exit())
					return;
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
			snprintf(error_msg, sizeof(error_msg), "Incorrect credentials. Attempts remaining: %d", 2 - attempts);
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

	char *input_username = get_input("Username", "Enter username:", 0);
	if (!input_username)
		return 0;
	strcpy(username, input_username);

	if (!validate_input(username, 3, MAX_USERNAME, "Username"))
		return 0;

	if (find_user(username) != -1) {
		show_message("Error", "Username already exists. Please choose a different username.");
		return 0;
	}

	char *input_password = get_input("Password", "Enter password:", 1);
	if (!input_password)
		return 0;
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
		snprintf(success_msg, sizeof(success_msg), "User '%s' has been successfully removed from the system.",
				 selected_user);
		show_message("Success", success_msg);
		return 1;
	}

	show_message("Info", "User removal cancelled.");
	return 0;
}

int main() {
	show_message("Welcome", "SOCKS5 server admin interface. \nPress OK to continue");

	if (!authenticate()) {
		system("clear");
		return 0;
	}

	admin_menu();

	system("clear");

	return 0;
}