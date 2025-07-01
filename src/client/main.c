

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

uint8_t checkUser(char * username, char * password) {
	//return strcmp("nep",username) == 0 && strcmp("123", password) == 0;
	int validU = strcmp("nep",username);
	int validP = strcmp("123", password);
	return validP==0 && validU==0;
}
int main(void) {
	// Client

	char raw_buffer_read[256] = {0};
	char raw_buffer_write[256] = {0};

	char * raw_buffer_read_ptr = raw_buffer_read;
	char * raw_buffer_write_ptr = raw_buffer_write;

	// buffer * buff_read;
	// buffer_init(buff_read,sizeof(raw_buffer_read), raw_buffer_read );
	// buffer * buff_write;
	// buffer_init(buff_write, sizeof(raw_buffer_write), raw_buffer_write);
	//
	// uint8_t * rb = buffer_read_ptr(buff_read,10);

	uint8_t nread = read(STDIN_FILENO, raw_buffer_read_ptr, 20);
	if (nread <= 0) {
		perror("Read error");
		return 1;
	}
	char username[20] = {0};
	char password[20] = {0};
	strncpy(username, raw_buffer_read_ptr, nread - 1);

	nread = read(STDIN_FILENO, raw_buffer_read_ptr, 20);
	if (nread <= 0) {
		perror("Read error");
		return 1;
	}
	strncpy(password, raw_buffer_read_ptr, nread - 1);


	uint8_t is_usr_valid = checkUser(username, password);
	if (is_usr_valid == 0) {
		printf("Invalid User!!!\n");
		return 1;
	}
	printf("valid User!!!\n");

	// while (1) {
	// 	uint8_t nread = read(STDIN_FILENO, raw_buffer_read_ptr, 256);
	// 	if (nread <= 0) {
	// 		perror("Read error");
	// 		break;
	// 	}
	// 	raw_buffer_read_ptr += nread;
	//
	// }
	return 0;
}