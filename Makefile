.PHONY: all build test clean run deps

# Build configuration
VERSION := 0.1.0
BINARY := prometheus-remoteread-sls

# Go commands
GOCMD := go
GOBUILD := $(GOCMD) build
GOCLEAN := $(GOCMD) clean
GOTEST := $(GOCMD) test
GOMOD := $(GOCMD) mod
GOGET := $(GOCMD) get

# BuildDFLAGS := -X main.version flags
L=$(VERSION) -s -w

all: deps build

deps:
	$(GOMOD) download
	$(GOMOD) tidy

build: deps
	$(GOBUILD) -ldflags "$(LDFLAGS)" -o $(BINARY) .

test:
	$(GOTEST) -v ./...

clean:
	$(GOCLEAN)
	rm -f $(BINARY)

run: build
	./$(BINARY) -config config.yaml

docker-build:
	docker build -t prometheus-remoteread-sls:$(VERSION) .

install:
	$(GOBUILD) -ldflags "$(LDFLAGS)" -o /usr/local/bin/$(BINARY) .

# Development commands
fmt:
	$(GOCMD) fmt ./...

lint:
	@golangci-lint run ./... || echo "Install golangci-lint for linting"

# Help target
help:
	@echo "Available targets:"
	@echo "  all         - Download deps and build (default)"
	@echo "  build       - Build the binary"
	@echo "  test        - Run tests"
	@echo "  clean       - Clean build artifacts"
	@echo "  run         - Build and run the proxy"
	@echo "  deps        - Download dependencies"
	@echo "  docker-build - Build Docker image"
	@echo "  install     - Install binary to /usr/local/bin"
	@echo "  fmt         - Format code"
	@echo "  lint        - Run linter"
	@echo "  help        - Show this help"
