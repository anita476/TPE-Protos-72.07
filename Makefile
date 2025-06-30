CC = gcc
CFLAGS = -Wall -Wextra -g -std=c11 -g -D_GNU_SOURCE -D_POSIX_C_SOURCE=200809L
# added -D_GNU_SOURCE -D_POSIX_C_SOURCE=200809L because of "implicit declaration of pselect"
# https://barnowl.mit.edu/ticket/166
# 
LDFLAGS = -pthread

SRC_DIR = src
SERVER_DIR = $(SRC_DIR)/server
CLIENT_DIR = $(SRC_DIR)/client
LIBS_DIR = $(SERVER_DIR)/libs
TEST_DIR = $(SERVER_DIR)/test
INCLUDE_DIR = $(SERVER_DIR)/include
OBJ_DIR = obj
BIN_DIR = bin

# server src files
SERVER_SRCS = $(SERVER_DIR)/main.c $(SERVER_DIR)/socks5.c
SERVER_OBJS = $(OBJ_DIR)/server-main.o $(patsubst $(SERVER_DIR)/%.c,$(OBJ_DIR)/%.o,$(filter-out $(SERVER_DIR)/main.c,$(SERVER_SRCS)))

# libraries source files
LIBS_SRCS = $(wildcard $(LIBS_DIR)/*.c)
LIBS_OBJS = $(patsubst $(LIBS_DIR)/%.c,$(OBJ_DIR)/%.o,$(LIBS_SRCS))

# client source files
CLIENT_SRCS = $(CLIENT_DIR)/main.c
CLIENT_OBJS = $(OBJ_DIR)/client-main.o

# tests
TEST_SRCS = $(wildcard $(TEST_DIR)/*.c)
TEST_BINS = $(TEST_SRCS:$(TEST_DIR)/%.c=$(BIN_DIR)/%)


all: server client


$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

#  compiles libs to .o files, then compiles socks5 and main
server: $(BIN_DIR) $(OBJ_DIR) $(LIBS_OBJS) $(SERVER_OBJS)
	$(CC) $(SERVER_OBJS) $(LIBS_OBJS) $(LDFLAGS) -o $(BIN_DIR)/server


client: $(BIN_DIR) $(OBJ_DIR) $(CLIENT_OBJS) $(LIBS_OBJS)
	$(CC) $(CLIENT_OBJS) $(LIBS_OBJS) $(LDFLAGS) -o $(BIN_DIR)/client

# compile all libs and tests (each test is its own binary)
test: $(BIN_DIR) $(OBJ_DIR) $(LIBS_OBJS) $(TEST_BINS)

# Compile server main
$(OBJ_DIR)/server-main.o: $(SERVER_DIR)/main.c
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -c $< -o $@

# Compile client main
$(OBJ_DIR)/client-main.o: $(CLIENT_DIR)/main.c
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -c $< -o $@

# compile everything else for the server
$(OBJ_DIR)/%.o: $(SERVER_DIR)/%.c
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -c $< -o $@

# compile LIBRARY object files
$(OBJ_DIR)/%.o: $(LIBS_DIR)/%.c
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -c $< -o $@

$(BIN_DIR)/%: $(TEST_DIR)/%.c $(LIBS_OBJS)
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) $< $(LIBS_OBJS) $(LDFLAGS) -lcheck -lm -lsubunit -o $@

#  for buffer_test exclude selector.o since it includes buffer.c directly
$(BIN_DIR)/buffer_test: $(TEST_DIR)/buffer_test.c $(filter-out obj/buffer.o,$(LIBS_OBJS))
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) $< $(filter-out obj/buffer.o,$(LIBS_OBJS)) $(LDFLAGS) -lcheck -lm -lsubunit -o $@

# same for selectoe test
$(BIN_DIR)/selector_test: $(TEST_DIR)/selector_test.c $(filter-out obj/selector.o,$(LIBS_OBJS))
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) $< $(filter-out obj/selector.o,$(LIBS_OBJS)) $(LDFLAGS) -lcheck -lm -lsubunit -o $@

clean:
	rm -rf $(BIN_DIR) $(OBJ_DIR)

.PHONY: all server client test clean
