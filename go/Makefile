# Zero Trust Agent (Go) Makefile

.PHONY: all build run test clean deps lint fmt

# Build variables
BINARY_NAME=zta-agent
BUILD_DIR=bin
CMD_DIR=cmd/zta-agent

all: deps build

# Download dependencies
deps:
	go mod download
	go mod tidy

# Build the binary
build:
	mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(BINARY_NAME) ./$(CMD_DIR)

# Run the agent
run: build
	./$(BUILD_DIR)/$(BINARY_NAME) -config config/policy.yaml

# Run without building (for development)
dev:
	go run ./$(CMD_DIR) -config config/policy.yaml

# Run tests
test:
	go test -v -race -cover ./...

# Run tests with coverage report
test-coverage:
	go test -v -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Format code
fmt:
	go fmt ./...

# Run linter
lint:
	golangci-lint run ./...

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)
	rm -f coverage.out coverage.html

# Install development tools
install-tools:
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Generate mocks (if needed)
generate:
	go generate ./...

# Build for multiple platforms
build-all:
	mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./$(CMD_DIR)
	GOOS=darwin GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 ./$(CMD_DIR)
	GOOS=darwin GOARCH=arm64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 ./$(CMD_DIR)
	GOOS=windows GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe ./$(CMD_DIR)

# Docker build
docker-build:
	docker build -t zta-agent-go:latest -f Dockerfile.go .

# Help
help:
	@echo "Available targets:"
	@echo "  all           - Download deps and build"
	@echo "  deps          - Download Go dependencies"
	@echo "  build         - Build the binary"
	@echo "  run           - Build and run the agent"
	@echo "  dev           - Run without building (go run)"
	@echo "  test          - Run tests"
	@echo "  test-coverage - Run tests with coverage report"
	@echo "  fmt           - Format code"
	@echo "  lint          - Run linter"
	@echo "  clean         - Clean build artifacts"
	@echo "  build-all     - Build for multiple platforms"
	@echo "  docker-build  - Build Docker image"
