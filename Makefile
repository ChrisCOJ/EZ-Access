# Directories
SRC_DIR := main/src
INC_DIR := main/include
BIN_SERVER := mqtt_server
BIN_CLIENT := test_client

# Source files for server and client
SRCS_SERVER := $(SRC_DIR)/mqtt_server.c $(SRC_DIR)/mqtt_com.c $(SRC_DIR)/mqtt_util.c
SRCS_CLIENT := $(SRC_DIR)/test_client.c

# Object files
OBJS_SERVER := $(SRCS_SERVER:.c=.o)
OBJS_CLIENT := $(SRCS_CLIENT:.c=.o)

# Compiler and flags
CC := gcc
CFLAGS := -I$(INC_DIR) -Wall -Wextra -pthread

# Default target: build both
all: $(BIN_SERVER) $(BIN_CLIENT)

# Server build
$(BIN_SERVER): $(OBJS_SERVER)
	$(CC) $(CFLAGS) -o $@ $^

# Client build
$(BIN_CLIENT): $(OBJS_CLIENT)
	$(CC) $(CFLAGS) -o $@ $^

# Compile all .c to .o
$(SRC_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean up
clean:
	rm -f $(SRC_DIR)/*.o $(BIN_SERVER) $(BIN_CLIENT)

.PHONY: all clean
