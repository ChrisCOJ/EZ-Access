# Directories
SRC_DIR = main/src
INC_DIR = main/include
BUILD_DIR = ../build

# Tools
CC = gcc

# Output executable
TARGET = $(BUILD_DIR)/subscriber

# Static library path
LIB_PATH = $(BUILD_DIR)/libmqtt_protocol.a

# Source files (list manually)
SOURCES = \
    $(SRC_DIR)/test_subscriber.c

# Object files
OBJECTS = \
    $(BUILD_DIR)/test_subscriber.o

# Compiler flags
CFLAGS = -I$(INC_DIR) -I../mqtt_protocol_lib/main/include -Wall -Wextra -O2

# Default target
all: $(TARGET)

# Ensure build directory exists
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Compile manually
$(BUILD_DIR)/test_subscriber.o: $(SRC_DIR)/test_subscriber.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Link executable with static library
$(TARGET): $(OBJECTS) $(LIB_PATH)
	$(CC) $(OBJECTS) $(LIB_PATH) -o $(TARGET)

# Clean
clean:
	rm -rf $(BUILD_DIR)/test_subscriber.o $(TARGET)

.PHONY: all clean
