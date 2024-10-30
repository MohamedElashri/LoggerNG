# Makefile
CXX = g++
CXXFLAGS = -std=c++17 -pthread -I../../ -Wall -Wextra -O2

# Colors and formatting
BOLD = \033[1m
RED = \033[31m
GREEN = \033[32m
YELLOW = \033[33m
BLUE = \033[34m
MAGENTA = \033[35m
CYAN = \033[36m
RESET = \033[0m

# Example specific paths
BUILD_DIR = build
TARGET = $(BUILD_DIR)/example1

# Source and object files
SRC = main.cpp
OBJ = $(BUILD_DIR)/main.o

# Config file
CONFIG = config.json
CONFIG_DEST = $(BUILD_DIR)/$(CONFIG)

# Header dependencies
DEPS = ../../Logger.h ../../json.hpp

.PHONY: all clean debug copy_config

all: banner $(TARGET) copy_config
	@echo "$(GREEN)$(BOLD)Build completed successfully!$(RESET)"
	@echo "$(CYAN)Build directory contents:$(RESET)"
	@ls -lh $(BUILD_DIR)

banner:
	@echo "$(YELLOW)$(BOLD)====================================$(RESET)"
	@echo "$(YELLOW)$(BOLD)  Building Example Logger Project$(RESET)"
	@echo "$(YELLOW)$(BOLD)====================================$(RESET)"

$(BUILD_DIR):
	@echo "$(BLUE)Creating build directory...$(RESET)"
	@mkdir -p $(BUILD_DIR)

copy_config:
	@if [ -f $(CONFIG) ]; then \
		echo "$(CYAN)Copying $(BOLD)$(CONFIG)$(RESET)$(CYAN) to build directory...$(RESET)"; \
		cp $(CONFIG) $(CONFIG_DEST); \
		echo "$(GREEN)Config file copied successfully.$(RESET)"; \
	else \
		echo "$(YELLOW)Warning: $(CONFIG) not found, skipping...$(RESET)"; \
	fi

$(TARGET): $(OBJ)
	@echo "$(CYAN)Linking $(BOLD)$(notdir $@)$(RESET)"
	@echo "$(BLUE)→ Command: $(CXX) -o $(TARGET) $(OBJ) $(CXXFLAGS)$(RESET)"
	@$(CXX) -o $(TARGET) $(OBJ) $(CXXFLAGS)
	@echo "$(GREEN)Linking complete!$(RESET)"

$(OBJ): $(SRC) $(DEPS) | $(BUILD_DIR)
	@echo "$(CYAN)Compiling $(BOLD)$(SRC)$(RESET)"
	@echo "$(BLUE)→ Command: $(CXX) $(CXXFLAGS) -c $(SRC) -o $(OBJ)$(RESET)"
	@$(CXX) $(CXXFLAGS) -c $(SRC) -o $(OBJ)
	@echo "$(GREEN)Compilation complete!$(RESET)"

debug:
	@echo "$(MAGENTA)$(BOLD)Debug Information:$(RESET)"
	@echo "$(MAGENTA)Current directory: $(RESET)$$(pwd)"
	@echo "$(MAGENTA)Source file:       $(RESET)$(SRC)"
	@echo "$(MAGENTA)Object file:       $(RESET)$(OBJ)"
	@echo "$(MAGENTA)Target:            $(RESET)$(TARGET)"
	@echo "$(MAGENTA)Config:            $(RESET)$(CONFIG)"
	@echo "$(MAGENTA)Config dest:       $(RESET)$(CONFIG_DEST)"
	@echo "$(MAGENTA)Dependencies:      $(RESET)$(DEPS)"
	@echo "$(MAGENTA)Build contents:    $(RESET)"
	@if [ -d $(BUILD_DIR) ]; then \
		ls -lh $(BUILD_DIR); \
	else \
		echo "$(RED)Build directory does not exist$(RESET)"; \
	fi

clean:
	@echo "$(YELLOW)Cleaning build artifacts...$(RESET)"
	@rm -rf $(BUILD_DIR)
	@echo "$(GREEN)Clean complete!$(RESET)"