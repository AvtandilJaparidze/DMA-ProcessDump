# Compiler and flags
CXX := g++
CXXFLAGS := -std=c++17 -I../MemProcFS/includes -DLINUX

# Library configuration
LIB_DIR := libs
LDFLAGS := -L$(LIB_DIR) -Wl,-rpath='$$ORIGIN'
LDLIBS := -lpthread -l:leechcore.so -l:vmm.so

# Source and build directories
SRC_DIR := src
BUILD_DIR := build

# Source files and output binary
SOURCES := $(SRC_DIR)/main.cpp $(SRC_DIR)/memory.cpp
TARGET := $(BUILD_DIR)/ExecutableDumper

# Shared libraries to copy from libs/ to build/
LIB_FILES := $(wildcard $(LIB_DIR)/*.so) $(wildcard $(LIB_DIR)/*.db)

.PHONY: all prepare copy-libs clean

all: prepare copy-libs $(TARGET)

prepare:
	@echo "Creating build directory..."
	mkdir -p $(BUILD_DIR)

copy-libs: prepare
	@echo "Copying shared libraries from $(LIB_DIR) to $(BUILD_DIR)..."
	cp $(LIB_FILES) $(BUILD_DIR)

$(TARGET): $(SOURCES)
	@echo "Building executable with libs from $(LIB_DIR)..."
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $^ -o $@ $(LDLIBS)

clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)