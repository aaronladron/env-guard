.PHONY: build test test-race vet fmt fmt-check mod-verify check clean

build:
	mkdir -p bin
	go build -o bin/env-guard ./cmd/env-guard

test:
	go test ./...

test-race:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -w cmd internal

fmt-check:
	@test -z "$$(gofmt -l cmd internal)" || (gofmt -l cmd internal && exit 1)

mod-verify:
	go mod verify

check: mod-verify fmt-check vet test

clean:
	rm -rf bin dist
	go clean -testcache
