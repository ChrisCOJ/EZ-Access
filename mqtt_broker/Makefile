# Directories
SRC_DIR = main/src
INC_DIR = main/include
BUILD_DIR = ../build

# Tools
CC = gcc

# Output executable
TARGET = $(BUILD_DIR)/mqtt_server

# Static library path (built by mqtt_protocol_lib)
LIB_PATH = $(BUILD_DIR)/libmqtt_protocol.a

# Source files (manually listed)
SOURCES = \
    $(SRC_DIR)/mqtt_server.c

# Object files (manually mapped)
OBJECTS = \
    $(BUILD_DIR)/mqtt_server.o

# Compiler flags (include broker headers + protocol library headers)
CFLAGS = -I$(INC_DIR) -I../mqtt_protocol_lib/main/include -Wall -Wextra -O2

# Default target
all: $(TARGET)

# Compile source to object
$(BUILD_DIR)/mqtt_server.o: $(SRC_DIR)/mqtt_server.c
	$(CC) $(CFLAGS) -c $< -o $@

# Link executable with static library
$(TARGET): $(OBJECTS) $(LIB_PATH)
	$(CC) $(OBJECTS) $(LIB_PATH) -o $(TARGET)

# Run target
run: all
	$(TARGET)

# Clean
clean:
	rm -rf $(BUILD_DIR)/mqtt_server.o $(TARGET)

.PHONY: all clean
