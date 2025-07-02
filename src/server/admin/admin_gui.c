#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>

#define MAX_INPUT 256
#define MAX_COMMAND 4096
#define MAX_USERS 10
#define MAX_USERNAME 24

typedef struct {
    char username[MAX_USERNAME];
    char role[16];
} User;

User users[MAX_USERS] = {
    {"nep", "Administrator"},
    {"user1", "User"},
    {"user2", "User"},
    {"guest", "User"},
    {"", ""},
    {"", ""},
    {"", ""},
    {"", ""},
    {"", ""},
    {"", ""}
};

int user_count = 4;

int execute_dialog(const char* dialog_cmd, char* result, size_t result_size);
void clear_screen(void);
void show_error(const char* message);
void show_info(const char* message);
int get_username(char* username, size_t size);
int get_password(char* password, size_t size);
int verify_credentials(const char* username, const char* password);
void show_metrics(void);
void manage_users(void);
void configure_settings(void);
void admin_menu(void);
int confirm_exit(void);
int authenticate(void);
int add_user(void);
int remove_user(void);
int change_user_password(void);
int find_user(const char* username);
int get_user_count(void);

int execute_dialog(const char* dialog_cmd, char* result, size_t result_size) {
    FILE* fp;
    int status;
    
    fp = popen(dialog_cmd, "r");
    if (fp == NULL) {
        return -1;
    }
    
    if (result && result_size > 0) {
        if (fgets(result, result_size, fp) != NULL) {
            size_t len = strlen(result);
            if (len > 0 && result[len-1] == '\n') {
                result[len-1] = '\0';
            }
        }
    }
    
    status = pclose(fp);
    return WEXITSTATUS(status);
}

void clear_screen() {
    system("clear");
}

void show_error(const char* message) {
    char cmd[MAX_COMMAND];
    snprintf(cmd, sizeof(cmd), 
        "dialog --title \"Error\" --msgbox \"\\n%s\" 8 50", message);
    system(cmd);
}

void show_info(const char* message) {
    char cmd[MAX_COMMAND];
    snprintf(cmd, sizeof(cmd), 
        "dialog --title \"Information\" --msgbox \"\\n%s\" 8 50", message);
    system(cmd);
}

int get_username(char* username, size_t size) {
    char cmd[MAX_COMMAND];
    snprintf(cmd, sizeof(cmd), 
        "dialog --title \"Username\" --inputbox \"\\nEnter username:\" 9 40 3>&1 1>&2 2>&3 3>&-");
    
    return execute_dialog(cmd, username, size);
}

int get_password(char* password, size_t size) {
    char cmd[MAX_COMMAND];
    snprintf(cmd, sizeof(cmd), 
        "dialog --title \"Password\" --clear --insecure --passwordbox \"\\nEnter password:\" 9 40 3>&1 1>&2 2>&3 3>&-");
    
    return execute_dialog(cmd, password, size);
}

int verify_credentials(const char* username, const char* password) {
    return (strcmp(username, "nep") == 0 && strcmp(password, "nep") == 0);
}

void show_metrics() {
    char cmd[MAX_COMMAND];
    char status_info[2048];
    
    snprintf(status_info, sizeof(status_info),
        "\\nServer status: Running\\n"
        "SOCKS5 port: Active\\n"
        "Admin port: Active\\n"
        "Current connections: 15\\n"
        "Total connections: 1,234\\n"
        "Bytes transferred: 2.5 GB\\n"
        "Server uptime: 5 days, 12 hours\\n"
        "Active users: %d\\n\\n"
        "Press OK to continue", user_count);
    
    snprintf(cmd, sizeof(cmd), 
        "dialog --title \"View metrics\" --msgbox \"%s\" 15 60", status_info);
    system(cmd);
}

void manage_users() {
    while (1) {
        char cmd[MAX_COMMAND];
        char choice[16];
        
        snprintf(cmd, sizeof(cmd),
            "dialog --title \"Manage users\" --menu \"\\nSelect an option:\" 13 50 5 "
            "1 \"List all users\" "
            "2 \"Add new user\" "
            "3 \"Remove user\" "
            "4 \"Change user password\" "
            "5 \"Back to main menu\" 3>&1 1>&2 2>&3");
        
        if (execute_dialog(cmd, choice, sizeof(choice)) != 0) {
            break;
        }
        
        switch (atoi(choice)) {
            case 1: {
                char users_info[1024];
                char user_list[512] = "";
                
                for (int i = 0; i < user_count; i++) {
                    char user_line[64];
                    snprintf(user_line, sizeof(user_line), "%d. %s (%s)\\n", 
                            i + 1, users[i].username, users[i].role);
                    strcat(user_list, user_line);
                }
                
                snprintf(users_info, sizeof(users_info),
                    "\\n%s\\nTotal users: %d\\n\\n"
                    "Press OK to continue", user_list, user_count);
                
                snprintf(cmd, sizeof(cmd), 
                    "dialog --title \"User list\" --msgbox \"%s\" 14 50", users_info);
                system(cmd);
                break;
            }
            case 2:
                add_user();
                break;
            case 3:
                remove_user();
                break;
            case 4:
                change_user_password();
                break;
            case 5:
                return;
            default:
                show_error("Invalid option");
                break;
        }
    }
}

void configure_settings() {
    while (1) {
        char cmd[MAX_COMMAND];
        char choice[16];
        
        snprintf(cmd, sizeof(cmd),
            "dialog --title \"Manage settings\" --menu \"\\nSelect an option:\" 12 50 4 "
            "1 \"Server configuration\" "
            "2 \"Logging settings\" "
            "3 \"Security settings\" "
            "4 \"Back to main menu\" 3>&1 1>&2 2>&3");
        
        if (execute_dialog(cmd, choice, sizeof(choice)) != 0) {
            break;
        }
        
        switch (atoi(choice)) {
            case 1: {
                char config_info[1024];
                snprintf(config_info, sizeof(config_info),
                    "\\nSOCKS5 Port: 1080\\n"
                    "Admin Port: 8080\\n"
                    "Bind Address: 0.0.0.0\\n"
                    "Max Connections: 100\\n"
                    "Connection Timeout: 30 seconds\\n"
                    "Buffer Size: 8192 bytes\\n\\n"
                    "Press OK to continue");
                
                snprintf(cmd, sizeof(cmd), 
                    "dialog --title \"Server configuration\" --msgbox \"%s\" 13 60", config_info);
                system(cmd);
                break;
            }
            case 2:
                show_info("Logging settings not implemented yet");
                break;
            case 3:
                show_info("Security settings not implemented yet");
                break;
            case 4:
                return;
            default:
                show_error("Invalid option");
                break;
        }
    }
}

void admin_menu() {
    while (1) {
        char cmd[MAX_COMMAND];
        char choice[16];
        
        snprintf(cmd, sizeof(cmd),
            "dialog --title \"Admin interface\" --menu \"\\nSelect an option:\" 12 50 4 "
            "1 \"View metrics\" "
            "2 \"Manage users\" "
            "3 \"Manage settings\" "
            "4 \"Exit\" 3>&1 1>&2 2>&3");
        
        if (execute_dialog(cmd, choice, sizeof(choice)) != 0) {
            break;
        }
        
        switch (atoi(choice)) {
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
                if (confirm_exit()) {
                    return;
                }
                break;
            default:
                show_error("Invalid option");
                break;
        }
    }
}

int confirm_exit() {
    char cmd[MAX_COMMAND];
    snprintf(cmd, sizeof(cmd),
        "dialog --title \"Confirm\" --yesno \"\\nAre you sure you want to exit?\" 6 40");
    
    return (system(cmd) == 0); // 0 = Yes, 256 = No
}

int authenticate() {
    char username[MAX_INPUT];
    char password[MAX_INPUT];
    int attempts = 0;
    const int max_attempts = 3;
    
    while (attempts < max_attempts) {
        if (get_username(username, sizeof(username)) != 0) {
            return 0;
        }
        
        if (strlen(username) == 0) {
            show_error("Username cannot be empty");
            continue;
        }
        
        if (get_password(password, sizeof(password)) != 0) {
            return 0;
        }
        
        if (strlen(password) == 0) {
            show_error("Password cannot be empty");
            continue;
        }
        
        if (verify_credentials(username, password)) {
            show_info("Authentication successful. Welcome to the admin panel.");
            return 1;
        } else {
            attempts++;
            if (attempts < max_attempts) {
                char error_msg[256];
                snprintf(error_msg, sizeof(error_msg), 
                    "\\nIncorrect credentials. Attempts remaining: %d", 
                    max_attempts - attempts);
                show_error(error_msg);
            }
        }
        
        memset(username, 0, sizeof(username));
        memset(password, 0, sizeof(password));
    }
    
    show_error("Maximum number of attempts reached. Access denied.");
    return 0;
}

int add_user() {
    char username[MAX_INPUT];
    char password[MAX_INPUT];
    char confirm_password[MAX_INPUT];
    
    if (get_username(username, sizeof(username)) != 0) {
        return 0;
    }
    
    if (strlen(username) == 0) {
        show_error("Username cannot be empty");
        return 0;
    }
    
    if (strlen(username) < 3) {
        show_error("Username must be at least 3 characters long");
        return 0;
    }

    if (strlen(username) >= 24) {
        show_error("Username must be less than 24 characters long");
        return 0;
    }
    
    if (find_user(username) != -1) {
        show_error("Username already exists. Please choose a different username.");
        return 0;
    }
    
    if (get_password(password, sizeof(password)) != 0) {
        return 0;
    }
    
    if (strlen(password) == 0) {
        show_error("Password cannot be empty");
        return 0;
    }
    
    if (strlen(password) < 4) {
        show_error("Password must be at least 4 characters long");
        return 0;
    }

    if (strlen(password) >= 24) {
        show_error("Password must be less than 24 characters long");
        return 0;
    }
    
    char cmd[MAX_COMMAND];
    snprintf(cmd, sizeof(cmd), 
        "dialog --title \"Confirm password\" --clear --insecure --passwordbox \"\\nConfirm your password:\" 9 40 3>&1 1>&2 2>&3 3>&-");
    
    if (execute_dialog(cmd, confirm_password, sizeof(confirm_password)) != 0) {
        return 0;
    }
    
    if (strcmp(password, confirm_password) != 0) {
        show_error("Passwords do not match. Please try again.");
        return 0;
    }
    
    if (user_count < MAX_USERS) {
        strcpy(users[user_count].username, username);
        strcpy(users[user_count].role, "User");
        user_count++;
        
        char success_msg[512];
        snprintf(success_msg, sizeof(success_msg), 
            "User '%.20s' has been successfully added to the system.", username);
        show_info(success_msg);
    } else {
        show_error("Maximum number of users reached. Cannot add more users.");
    }
    
    memset(password, 0, sizeof(password));
    memset(confirm_password, 0, sizeof(confirm_password));
    
    return 1;
}

int remove_user() {
    char cmd[MAX_COMMAND];
    char choice[16];
    
    char menu_options[512] = "";
    int option_map[MAX_USERS];
    int option_count = 0;
    
    for (int i = 0; i < user_count; i++) {
        if (strcmp(users[i].username, "nep") != 0) {
            char option[64];
            snprintf(option, sizeof(option), "%d \"%s\" ", 
                    option_count + 1, users[i].username);
            strcat(menu_options, option);
            option_map[option_count] = i;
            option_count++;
        }
    }
    
    if (option_count == 0) {
        show_error("No users available to remove.");
        return 0;
    }
    
    char cancel_option[32];
    snprintf(cancel_option, sizeof(cancel_option), "%d \"Cancel\"", option_count + 1);
    strcat(menu_options, cancel_option);
    
    snprintf(cmd, sizeof(cmd),
        "dialog --title \"Remove user\" --menu \"\\nSelect user to remove:\" 14 50 %d %s 3>&1 1>&2 2>&3", 
        option_count + 1, menu_options);
    
    if (execute_dialog(cmd, choice, sizeof(choice)) != 0 || atoi(choice) == option_count + 1) {
        return 0;
    }
    
    int selected_index = atoi(choice) - 1;
    if (selected_index < 0 || selected_index >= option_count) {
        show_error("Invalid selection");
        return 0;
    }
    
    int user_index = option_map[selected_index];
    char selected_user[MAX_USERNAME];
    strcpy(selected_user, users[user_index].username);
    
    char confirm_msg[256];
    snprintf(confirm_msg, sizeof(confirm_msg),
        "\\nAre you sure you want to remove user '%s'?\\n\\nThis action cannot be undone.", selected_user);
    
    snprintf(cmd, sizeof(cmd),
        "dialog --title \"Confirm removal\" --yesno \"%s\" 10 50", confirm_msg);

    if (system(cmd) == 0) {
        for (int i = user_index; i < user_count - 1; i++) {
            users[i] = users[i + 1];
        }
        
        strcpy(users[user_count - 1].username, "");
        strcpy(users[user_count - 1].role, "");
        user_count--;
        
        char success_msg[256];
        snprintf(success_msg, sizeof(success_msg), 
            "User '%.20s' has been successfully removed from the system.", selected_user);
        show_info(success_msg);
        return 1;
    }
    
    show_info("User removal cancelled.");
    return 0;
}

int change_user_password() {
    char cmd[MAX_COMMAND];
    char choice[16];
    
    char menu_options[512] = "";
    int option_map[MAX_USERS];
    int option_count = 0;
    
    for (int i = 0; i < user_count; i++) {
        char option[64];
        snprintf(option, sizeof(option), "%d \"%s (%s)\" ", 
                option_count + 1, users[i].username, users[i].role);
        strcat(menu_options, option);
        option_map[option_count] = i;
        option_count++;
    }
    
    if (option_count == 0) {
        show_error("No users available.");
        return 0;
    }
    
    char cancel_option[32];
    snprintf(cancel_option, sizeof(cancel_option), "%d \"Cancel\"", option_count + 1);
    strcat(menu_options, cancel_option);
    
    snprintf(cmd, sizeof(cmd),
        "dialog --title \"Change password\" --menu \"\\nSelect user to change password:\" %d 50 %d %s 3>&1 1>&2 2>&3",
        14 + option_count, option_count + 1, menu_options);
    
    if (execute_dialog(cmd, choice, sizeof(choice)) != 0 || atoi(choice) == option_count + 1) {
        return 0;
    }
    
    int selected_index = atoi(choice) - 1;
    if (selected_index < 0 || selected_index >= option_count) {
        show_error("Invalid selection");
        return 0;
    }
    
    int user_index = option_map[selected_index];
    char* selected_user = users[user_index].username;
    
    char new_password[MAX_INPUT];
    char confirm_password[MAX_INPUT];
    
    snprintf(cmd, sizeof(cmd), 
        "dialog --title \"New password\" --clear --insecure --passwordbox \"\\nEnter new password for user '%s':\" 10 50 3>&1 1>&2 2>&3 3>&-", selected_user);
    
    if (execute_dialog(cmd, new_password, sizeof(new_password)) != 0) {
        return 0;
    }
    
    if (strlen(new_password) == 0) {
        show_error("Password cannot be empty");
        return 0;
    }
    
    if (strlen(new_password) < 4) {
        show_error("Password must be at least 4 characters long");
        return 0;
    }

    if (strlen(new_password) >= 24) {
        show_error("Password must be less than 24 characters long");
        return 0;
    }
    
    snprintf(cmd, sizeof(cmd), 
        "dialog --title \"Confirm password\" --clear --insecure --passwordbox \"\\nConfirm new password:\" 9 40 3>&1 1>&2 2>&3 3>&-");
    
    if (execute_dialog(cmd, confirm_password, sizeof(confirm_password)) != 0) {
        memset(new_password, 0, sizeof(new_password));
        return 0;
    }
    
    if (strcmp(new_password, confirm_password) != 0) {
        show_error("Passwords do not match. Please try again.");
        memset(new_password, 0, sizeof(new_password));
        memset(confirm_password, 0, sizeof(confirm_password));
        return 0;
    }
    
    // TODO: Actually change user password in system
    char success_msg[256];
    snprintf(success_msg, sizeof(success_msg), 
        "Password for user '%.20s' has been successfully changed.", selected_user);
    show_info(success_msg);
    
    memset(new_password, 0, sizeof(new_password));
    memset(confirm_password, 0, sizeof(confirm_password));
    
    return 1;
}

int find_user(const char* username) {
    for (int i = 0; i < user_count; i++) {
        if (strcmp(users[i].username, username) == 0) {
            return i;
        }
    }
    return -1;
}

int get_user_count() {
    return user_count;
}

int main() {
    if (system("which dialog > /dev/null 2>&1") != 0) {
        fprintf(stderr, "Error: The 'dialog' library is not installed.\n");
        fprintf(stderr, "Please run the install script: ./script/install.sh\n");
        return 1;
    }
    
    clear_screen();
    
    // Welcome message
    char welcome_cmd[MAX_COMMAND];
    snprintf(welcome_cmd, sizeof(welcome_cmd),
        "dialog --title \"Welcome\" --msgbox \"\\nSOCKS5 Server\\nAdmin Interface\\n\\nPress OK to continue\" 10 40");
    system(welcome_cmd);
    
    // Authentication
    if (!authenticate()) {
        clear_screen();
        printf("Access denied.\n");
        return 1;
    }
    
    admin_menu();
    
    // Goodbye message
    clear_screen();
    printf("Goodbye!\n");
    
    return 0;
}