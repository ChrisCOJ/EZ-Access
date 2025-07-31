# Directories
SRC_DIR = main/src
INC_DIR = main/include
BUILD_DIR = ../build

# Tools
CC = gcc
AR = ar
ARFLAGS = rcs

# Library name
LIB_NAME = libmqtt_protocol.a
LIB_PATH = $(BUILD_DIR)/$(LIB_NAME)

# List your source files manually
SOURCES = \
    $(SRC_DIR)/mqtt_client_api.c \
    $(SRC_DIR)/mqtt_parser.c \
    $(SRC_DIR)/mqtt_util.c

# Corresponding object files
OBJECTS = \
    $(BUILD_DIR)/mqtt_client_api.o \
    $(BUILD_DIR)/mqtt_parser.o \
    $(BUILD_DIR)/mqtt_util.o

# Compiler flags
CFLAGS = -I$(INC_DIR) -Wall -Wextra -O2

# Default target
all: $(LIB_PATH)

# Ensure build directory exists
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Compile each source file manually
$(BUILD_DIR)/mqtt_client_api.o: $(SRC_DIR)/mqtt_client_api.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/mqtt_parser.o: $(SRC_DIR)/mqtt_parser.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/mqtt_util.o: $(SRC_DIR)/mqtt_util.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Archive into static library
$(LIB_PATH): $(OBJECTS)
	$(AR) $(ARFLAGS) $@ $^

# Clean
clean:
	rm -rf $(BUILD_DIR)

.PHONY: all clean
