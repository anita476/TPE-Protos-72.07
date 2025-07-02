#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>

#define MAX_INPUT 256
#define MAX_COMMAND 4096

int execute_dialog(const char* dialog_cmd, char* result, size_t result_size);
void clear_screen(void);
void show_error(const char* message);
void show_info(const char* message);
int get_username(char* username, size_t size);
int get_password(char* password, size_t size);
int verify_credentials(const char* username, const char* password);
void show_system_status(void);
void manage_users(void);
void configure_settings(void);
void admin_menu(void);
int confirm_exit(void);
int authenticate(void);

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
        "dialog --title \"Error\" --msgbox \"%s\" 8 50", message);
    system(cmd);
}

void show_info(const char* message) {
    char cmd[MAX_COMMAND];
    snprintf(cmd, sizeof(cmd), 
        "dialog --title \"Información\" --msgbox \"%s\" 8 50", message);
    system(cmd);
}

int get_username(char* username, size_t size) {
    char cmd[MAX_COMMAND];
    snprintf(cmd, sizeof(cmd), 
        "dialog --title \"Username\" --inputbox \"Enter your username:\" 8 40 3>&1 1>&2 2>&3 3>&-");
    
    return execute_dialog(cmd, username, size);
}

int get_password(char* password, size_t size) {
    char cmd[MAX_COMMAND];
    snprintf(cmd, sizeof(cmd), 
        "dialog --title \"Password\" --clear --insecure --passwordbox \"Enter your password:\" 8 40 3>&1 1>&2 2>&3 3>&-");
    
    return execute_dialog(cmd, password, size);
}

int verify_credentials(const char* username, const char* password) {
    return (strcmp(username, "nep") == 0 && strcmp(password, "nep") == 0);
}

void show_system_status() {
    char cmd[MAX_COMMAND];
    char status_info[2048];
    
    snprintf(status_info, sizeof(status_info),
        "Server Status: Running\\n"
        "SOCKS5 Port: Active\\n"
        "Admin Port: Active\\n"
        "Current Connections: 15\\n"
        "Total Connections: 1,234\\n"
        "Bytes Transferred: 2.5 GB\\n"
        "Server Uptime: 5 days, 12 hours\\n"
        "Active Users: 8\\n"
        "Press OK to continue");
    
    snprintf(cmd, sizeof(cmd), 
        "dialog --title \"System Status\" --msgbox \"%s\" 20 60", status_info);
    system(cmd);
}

void manage_users() {
    while (1) {
        char cmd[MAX_COMMAND];
        char choice[16];
        
        snprintf(cmd, sizeof(cmd),
            "dialog --title \"Manage Users\" --menu \"Select an option:\" 15 50 5 "
            "1 \"List all users\" "
            "2 \"Add new user\" "
            "3 \"Remove user\" "
            "4 \"Change user password\" "
            "5 \"Back to main menu\" 3>&1 1>&2 2>&3");
        
        // Cancelled
        if (execute_dialog(cmd, choice, sizeof(choice)) != 0) {
            break;
        }
        
        switch (atoi(choice)) {
            case 1: {
                char users_info[1024];
                snprintf(users_info, sizeof(users_info),
                    "=== USER LIST ===\\n\\n"
                    "1. nep (Administrator)\\n"
                    "2. user1 (Active)\\n"
                    "3. user2 (Inactive)\\n"
                    "4. guest (Temporary)\\n\\n"
                    "Total users: 4\\n\\n"
                    "Press OK to continue");
                
                snprintf(cmd, sizeof(cmd), 
                    "dialog --title \"User List\" --msgbox \"%s\" 15 50", users_info);
                system(cmd);
                break;
            }
            case 2:
                show_info("Add user functionality not implemented yet");
                break;
            case 3:
                show_info("Remove user functionality not implemented yet");
                break;
            case 4:
                show_info("Change password functionality not implemented yet");
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
            "dialog --title \"Configure Settings\" --menu \"Select an option:\" 15 50 4 "
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
                    "=== SERVER CONFIGURATION ===\\n\\n"
                    "SOCKS5 Port: 1080\\n"
                    "Admin Port: 8080\\n"
                    "Bind Address: 0.0.0.0\\n"
                    "Max Connections: 100\\n"
                    "Connection Timeout: 30 seconds\\n"
                    "Buffer Size: 8192 bytes\\n\\n"
                    "Press OK to continue");
                
                snprintf(cmd, sizeof(cmd), 
                    "dialog --title \"Server Configuration\" --msgbox \"%s\" 15 60", config_info);
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
            "dialog --title \"Admin Interface\" --menu \"Choose an option:\" 15 50 4 "
            "1 \"View System Status\" "
            "2 \"Manage Users\" "
            "3 \"Configure Settings\" "
            "4 \"Exit\" 3>&1 1>&2 2>&3");
        
        // Cancelled
        if (execute_dialog(cmd, choice, sizeof(choice)) != 0) {
            break;
        }
        
        switch (atoi(choice)) {
            case 1:
                show_system_status();
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
        "dialog --title \"Confirm\" --yesno \"Are you sure you want to exit?\" 6 40");
    
    return (system(cmd) == 0); // 0 = Yes, 256 = No
}

int authenticate() {
    char username[MAX_INPUT];
    char password[MAX_INPUT];
    int attempts = 0;
    const int max_attempts = 3;
    
    while (attempts < max_attempts) {
        // Cancelled
        if (get_username(username, sizeof(username)) != 0) {
            return 0;
        }
        
        if (strlen(username) == 0) {
            show_error("Username cannot be empty");
            continue;
        }
        
        // Cancelled
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
                    "Incorrect credentials. Attempts remaining: %d", 
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
        "dialog --title \"Welcome\" --msgbox \"SOCKS5 Server\\nAdmin Interface\\n\\nPress OK to continue\" 8 40");
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