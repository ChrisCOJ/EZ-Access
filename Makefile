# Directories
SRC_DIR := main/src
INC_DIR := main/include
BIN_SERVER := mqtt_server
BIN_CLIENT := test_client

# Source files for server and client
SRCS_SERVER := $(SRC_DIR)/mqtt_server.c $(SRC_DIR)/mqtt_parser.c $(SRC_DIR)/mqtt_util.c
SRCS_CLIENT := $(SRC_DIR)/test_client.c $(SRC_DIR)/mqtt_parser.c

# Object files
OBJS_SERVER := $(SRCS_SERVER:.c=.o)
OBJS_CLIENT := $(SRCS_CLIENT:.c=.o)

# Compiler and flags
CC := gcc
CFLAGS := -I$(INC_DIR) -Wall -Wextra -pthread

# Test files
TEST_SRC := $(SRC_DIR)/mqtt_tests.c $(SRC_DIR)/mqtt_parser.c
TEST_BIN := mqtt_tests
TEST_OBJS := $(TEST_SRC:.c=.o)

# Default target: run tests, then build
all: test $(BIN_SERVER) $(BIN_CLIENT)

# Test target
test: $(TEST_BIN)
	@echo "Running tests..."
	@./$(TEST_BIN)

# Build test binary
$(TEST_BIN): $(TEST_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

# Server build
$(BIN_SERVER): $(OBJS_SERVER)
	$(CC) $(CFLAGS) -o $@ $^

# Client build
$(BIN_CLIENT): $(OBJS_CLIENT)
	$(CC) $(CFLAGS) -o $@ $^

# Compile .c to .o
$(SRC_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean
clean:
	rm -f $(SRC_DIR)/*.o $(BIN_SERVER) $(BIN_CLIENT) $(TEST_BIN)

.PHONY: all clean test
