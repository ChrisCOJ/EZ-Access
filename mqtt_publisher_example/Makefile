# Directories
SRC_DIR = main/src
INC_DIR = main/include
BUILD_DIR = ../build

# Tools
CC = gcc

# Output executable
TARGET = $(BUILD_DIR)/publisher

# Static library path
LIB_PATH = $(BUILD_DIR)/libmqtt_protocol.a

# Source files (list manually)
SOURCES = \
    $(SRC_DIR)/test_publisher.c

# Object files
OBJECTS = \
    $(BUILD_DIR)/test_publisher.o

# Compiler flags
CFLAGS = -I$(INC_DIR) -I../mqtt_protocol_lib/main/include -Wall -Wextra -O2

# Default target
all: $(TARGET)

# Compile manually
$(BUILD_DIR)/test_publisher.o: $(SRC_DIR)/test_publisher.c
	$(CC) $(CFLAGS) -c $< -o $@

# Link executable with static library
$(TARGET): $(OBJECTS) $(LIB_PATH)
	$(CC) $(OBJECTS) $(LIB_PATH) -o $(TARGET)

# Run target
run: all
	$(TARGET)

# Clean
clean:
	rm -rf $(BUILD_DIR)/test_publisher.o $(TARGET)

.PHONY: all clean
