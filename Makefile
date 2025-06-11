# Compiler and flags
CC = gcc
LIBS = -L/usr/lib/x86_64-linux-gnu # $ pg_config --libdir
INCLUDES = -I/usr/include/postgresql
CFLAGS = --std=c17 -Wall -Werror -Wextra -O3 $(if $(DEBUG),-g) $(INCLUDES) $(LIBS) -lpq 

# Directories
SRC_DIR := src
OBJ_DIR := obj
BUILD_DIR := build

# Define binaries and their source locations
BINARIES := pg_watcher test
pg_watcher_SRCS := $(wildcard $(SRC_DIR)/postgresql/*.c)
test_SRCS := $(SRC_DIR)/test.c

# Auto-generate object files per binary
pg_watcher_OBJS := $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(pg_watcher_SRCS))
test_OBJS := $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(test_SRCS))

# Default target
all: $(addprefix $(BUILD_DIR)/,$(BINARIES))

# Generic pattern rule for compiling C to object files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

# Rule for each binary
$(BUILD_DIR)/pg_watcher: $(pg_watcher_OBJS)
	@mkdir -p $(BUILD_DIR)
	$(CC) -o $@ $^ $(CFLAGS) 

$(BUILD_DIR)/test: $(test_OBJS)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $^

# Add per-binary convenience targets: `make pg_watcher`, `make test`
$(BINARIES): %: $(BUILD_DIR)/%

# Clean
clean:
	rm -rf $(OBJ_DIR) $(BUILD_DIR)

.PHONY: all clean $(BINARIES)

