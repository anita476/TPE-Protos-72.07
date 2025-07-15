#ifndef MANAGEMENT_COMMANDS_H
#define MANAGEMENT_COMMANDS_H

#include "management.h"

// Command processing functions (extracted from main file)
void process_metrics_command(management_session *session);
void process_logs_command(management_session *session, uint8_t number, uint8_t offset);
void process_userlist_command(management_session *session, uint8_t number, uint8_t offset);
void process_change_buffer_command(management_session *session, uint8_t new_size);
void process_change_timeout_command(management_session *session, uint8_t new_timeout);
void process_add_user_command(management_session *session, uint8_t arg1, uint8_t arg2, uint8_t type);
void process_remove_user_command(management_session *session, uint8_t arg1);
void process_get_current_config_command(management_session *session);
void cleanup_session(management_session *session);

// Helper functions
uint8_t authenticate_user(const char *username, const char *password);
uint8_t add_user_to_system(const char *username, const char *password, uint8_t user_type);
uint8_t remove_user_from_system(const char *username);

void set_error_state(management_session *session, uint8_t error_code);
bool write_to_client(struct selector_key *key, bool should_close);

#endif // MANAGEMENT_COMMANDS_H
