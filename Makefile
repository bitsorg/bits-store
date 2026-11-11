# One static binary: no cgo.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" \
	  -o bin/bits-store ./cmd/bits-store

image:
	docker build --build-arg VERSION=$(VERSION) -t bits-store:$(VERSION) .

test:
	go vet ./...
	go test ./...
	python3 -I testdata/tokens/vectors.py check

.PHONY: build image test
