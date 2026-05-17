.PHONY: all build run test clean

# Directory for compiled binaries (tracked via .keep, binaries ignored)
BIN_DIR := bin
BINARY := $(BIN_DIR)/find-xrp-addr

# Default target
all: build

# Build release binary and copy to bin/
build:
	@mkdir -p $(BIN_DIR)
	cargo build --release
	@cp target/release/find-xrp-addr $(BINARY)
	@echo "✅ Built and copied binary to $(BINARY)"

# Run the app (builds first). Pass args with ARGS="..."
# Example: make run ARGS="--find test --cores 4"
run: build
	@./$(BINARY) $(ARGS)

# Run unit tests (proves non-main() functions)
test:
	cargo test

# Clean build artifacts and bin/
clean:
	cargo clean
	@rm -rf $(BIN_DIR)
	@echo "🧹 Cleaned build artifacts and $(BIN_DIR)/"
