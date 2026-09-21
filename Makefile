.PHONY: build install test race vet lint fmt check-fmt check clean

BINARY := bin/ovpntui
DAEMON := bin/ovpntuid
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
INSTALL_DIR ?= $(HOME)/.local/bin
LDFLAGS := -s -w -X main.version=$(VERSION)

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/ovpntui
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(DAEMON) ./cmd/ovpntuid

install: build
	install -d "$(INSTALL_DIR)"
	install -m 755 $(BINARY) "$(INSTALL_DIR)/.ovpntui.new"
	install -m 755 $(DAEMON) "$(INSTALL_DIR)/.ovpntuid.new"
	mv -f "$(INSTALL_DIR)/.ovpntui.new" "$(INSTALL_DIR)/ovpntui"
	mv -f "$(INSTALL_DIR)/.ovpntuid.new" "$(INSTALL_DIR)/ovpntuid"

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

lint:
	golangci-lint run ./...

fmt:
	gofmt -w $$(find cmd internal -name '*.go' -type f)

check-fmt:
	@test -z "$$(gofmt -l cmd internal)" || { gofmt -l cmd internal; exit 1; }

check: check-fmt vet test build

clean:
	rm -f $(BINARY) $(DAEMON)
