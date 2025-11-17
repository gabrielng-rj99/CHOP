.PHONY: build build-linux build-macos build-windows clean help run

BINARY_NAME=deploy-manager
CMD_DIR=cmd
OUTPUT_DIR=bin
VERSION=1.0.0
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
GIT_COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Default target
all: build

help:
	@echo "Contract Manager Deploy CLI - Build Targets"
	@echo "============================================="
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  build              Build binary for current OS"
	@echo "  build-linux        Build binary for Linux (x86_64)"
	@echo "  build-macos        Build binary for macOS (x86_64 + ARM64)"
	@echo "  build-windows      Build binary for Windows (x86_64)"
	@echo "  run                Build and run the binary"
	@echo "  clean              Remove build artifacts"
	@echo "  help               Show this help message"
	@echo ""
	@echo "Examples:"
	@echo "  make build"
	@echo "  make build-linux"
	@echo "  make run"
	@echo ""

# Create output directory
$(OUTPUT_DIR):
	@mkdir -p $(OUTPUT_DIR)

# Build for current OS
build: $(OUTPUT_DIR)
	@echo "Building $(BINARY_NAME) for current OS..."
	@go build -o $(OUTPUT_DIR)/$(BINARY_NAME) $(CMD_DIR)/main.go
	@echo "✓ Binary created: $(OUTPUT_DIR)/$(BINARY_NAME)"

# Build for Linux
build-linux: $(OUTPUT_DIR)
	@echo "Building $(BINARY_NAME) for Linux..."
	@GOOS=linux GOARCH=amd64 go build \
		-ldflags "-X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME) -X main.GitCommit=$(GIT_COMMIT)" \
		-o $(OUTPUT_DIR)/$(BINARY_NAME)-linux-amd64 $(CMD_DIR)/main.go
	@echo "✓ Binary created: $(OUTPUT_DIR)/$(BINARY_NAME)-linux-amd64"

# Build for macOS (Intel + Apple Silicon)
build-macos: $(OUTPUT_DIR)
	@echo "Building $(BINARY_NAME) for macOS..."
	@GOOS=darwin GOARCH=amd64 go build \
		-ldflags "-X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME) -X main.GitCommit=$(GIT_COMMIT)" \
		-o $(OUTPUT_DIR)/$(BINARY_NAME)-macos-amd64 $(CMD_DIR)/main.go
	@GOOS=darwin GOARCH=arm64 go build \
		-ldflags "-X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME) -X main.GitCommit=$(GIT_COMMIT)" \
		-o $(OUTPUT_DIR)/$(BINARY_NAME)-macos-arm64 $(CMD_DIR)/main.go
	@echo "✓ Binaries created:"
	@echo "  - $(OUTPUT_DIR)/$(BINARY_NAME)-macos-amd64"
	@echo "  - $(OUTPUT_DIR)/$(BINARY_NAME)-macos-arm64"

# Build for Windows
build-windows: $(OUTPUT_DIR)
	@echo "Building $(BINARY_NAME) for Windows..."
	@GOOS=windows GOARCH=amd64 go build \
		-ldflags "-X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME) -X main.GitCommit=$(GIT_COMMIT)" \
		-o $(OUTPUT_DIR)/$(BINARY_NAME)-windows-amd64.exe $(CMD_DIR)/main.go
	@echo "✓ Binary created: $(OUTPUT_DIR)/$(BINARY_NAME)-windows-amd64.exe"

# Build all platforms
build-all: build-linux build-macos build-windows
	@echo ""
	@echo "✓ All binaries built successfully!"
	@ls -lh $(OUTPUT_DIR)

# Run the binary
run: build
	@$(OUTPUT_DIR)/$(BINARY_NAME)

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(OUTPUT_DIR)
	@echo "✓ Clean complete"

# Install locally (optional)
install: build
	@echo "Installing $(BINARY_NAME)..."
	@cp $(OUTPUT_DIR)/$(BINARY_NAME) /usr/local/bin/$(BINARY_NAME)
	@chmod +x /usr/local/bin/$(BINARY_NAME)
	@echo "✓ Installed to /usr/local/bin/$(BINARY_NAME)"

# Uninstall locally (optional)
uninstall:
	@echo "Uninstalling $(BINARY_NAME)..."
	@rm -f /usr/local/bin/$(BINARY_NAME)
	@echo "✓ Uninstalled"
