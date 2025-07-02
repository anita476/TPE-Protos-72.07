

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
// #include <dialog.h>

uint8_t checkUser(char * username, char * password) {
	//return strcmp("nep",username) == 0 && strcmp("123", password) == 0;
	int validU = strcmp("nep",username);
	int validP = strcmp("123", password);
	return validP==0 && validU==0;
}
int main(void) {
	// Client

	// int ret;
 //    char usr[64] = {0};
 //    char pass[64] = {0};
 //    char option[16] = {0};
 //
 //    /* Initialize the dialog library to use stdin/stdout */
 //    init_dialog(stdin, stdout);
 //
 //    /* Input box for username */
 //    ret = dialog_inputbox(
 //        "Username",             /* title */
 //        "Enter your username:", /* prompt */
 //        0,                       /* height (0 = autosize) */
 //        0,                       /* width  (0 = autosize) *//* menu height (unused)  */
 //        usr,0                      /* buffer to store result */
 //    );
 //    if (ret != 0) {
 //        /* User pressed Cancel or ESC */
 //        end_dialog();
 //        return 1;
 //    }
 //
 //    /* Password box (insecure disables shadow) */
 //    ret = dialog_inputbox(
 //        "Password",              /* title */
 //        "Enter your password:",  /* prompt */
 //        0,                        /* height */
 //        0,                        /* width */
 //        pass,                        /* insecure (no shadow) */
 //        1                     /* buffer to store result */
 //    );
 //    if (ret != 0) {
 //        end_dialog();
 //        return 1;
 //    }
 //
 //    /* Validate credentials */
 //    if (strcmp(usr, "nep") != 0 || strcmp(pass, "nep") != 0) {
 //        dialog_msgbox(
 //            "Error",                               /* title */
 //            "Username or password cannot be empty.",
 //            0,                                      /* height */
 //            0,                                      /* width */
 //            1                                       /* pause on show */
 //        );
 //        end_dialog();
 //        return 1;
 //    }
 //
 //    // /* Menu for admin interface */
 //    // ret = dialog_menu(
 //    //     "Admin Interface",      /* title */
 //    //     "Choose an option:",    /* prompt */
 //    //     0,                       /* height */
 //    //     0,                       /* width *//* menu height (number of items) */
 //    //     1, "View System Status",
 //    //     2, "Manage Users",
 //    //     3, "Configure Settings",
 //    //     4, "Exit"
 //    // );
 //    end_dialog();
 //
 //    if (ret == 0) {
 //        /* Print selected option tag */
 //        printf("%s\n", option);
 //    }
 //
 //    return (ret == 0) ? 0 : 1;


	// char raw_buffer_read[256] = {0};
	// char raw_buffer_write[256] = {0};
	//
	// char * raw_buffer_read_ptr = raw_buffer_read;
	// char * raw_buffer_write_ptr = raw_buffer_write;
	//
	// // buffer * buff_read;
	// // buffer_init(buff_read,sizeof(raw_buffer_read), raw_buffer_read );
	// // buffer * buff_write;
	// // buffer_init(buff_write, sizeof(raw_buffer_write), raw_buffer_write);
	// //
	// // uint8_t * rb = buffer_read_ptr(buff_read,10);
	//
	// uint8_t nread = read(STDIN_FILENO, raw_buffer_read_ptr, 20);
	// if (nread <= 0) {
	// 	perror("Read error");
	// 	return 1;
	// }
	// char username[20] = {0};
	// char password[20] = {0};
	// strncpy(username, raw_buffer_read_ptr, nread - 1);
	//
	// nread = read(STDIN_FILENO, raw_buffer_read_ptr, 20);
	// if (nread <= 0) {
	// 	perror("Read error");
	// 	return 1;
	// }
	// strncpy(password, raw_buffer_read_ptr, nread - 1);
	//
	//
	// uint8_t is_usr_valid = checkUser(username, password);
	// if (is_usr_valid == 0) {
	// 	printf("Invalid User!!!\n");
	// 	return 1;
	// }
	// printf("valid User!!!\n");
	//
	// // while (1) {
	// // 	uint8_t nread = read(STDIN_FILENO, raw_buffer_read_ptr, 256);
	// // 	if (nread <= 0) {
	// // 		perror("Read error");
	// // 		break;
	// // 	}
	// // 	raw_buffer_read_ptr += nread;
	// //
	// // }
	return 0;
}