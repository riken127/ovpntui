.PHONY: build test race lint fmt check clean

BINARY := bin/ovpntui
DAEMON := bin/ovpntuid

build:
	go build -trimpath -ldflags "-s -w" -o $(BINARY) ./cmd/ovpntui
	go build -trimpath -ldflags "-s -w" -o $(DAEMON) ./cmd/ovpntuid

test:
	go test ./...

race:
	go test -race ./...

lint:
	golangci-lint run ./...

fmt:
	gofmt -w $$(find cmd internal -name '*.go' -type f)

check: test lint

clean:
	rm -f $(BINARY) $(DAEMON)
