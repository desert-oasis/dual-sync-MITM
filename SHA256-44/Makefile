# Compiler and flags
CXX = g++
CPPFLAGS = -O3 -Wall -std=c++11 -I include

# Directories
SRC_DIR = src
BIN_DIR = bin

# Source files and executable
SOURCES = $(wildcard $(SRC_DIR)/*.cpp)
EXECUTABLE = $(BIN_DIR)/SHA256

# Build target
all: $(EXECUTABLE)

# Link the executable
$(EXECUTABLE): $(SOURCES)
	@mkdir -p $(BIN_DIR)  # Create bin directory if it doesn't exist
	$(CXX) $(CPPFLAGS) -o $@ $^

# Clean up build artifacts
clean:
	rm -f $(EXECUTABLE)
	rm -f $(SRC_DIR)/*.o

.PHONY: all clean