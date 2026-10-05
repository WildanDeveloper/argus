SHELL := /bin/bash
BIN   := ./bin
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.Version=$(VERSION)

.DEFAULT_GOAL := build

## build: compile all binaries statically
.PHONY: build
build:
	@mkdir -p $(BIN)
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN)/argus         ./cmd/argus
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN)/argusd        ./cmd/argusd
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN)/argus-worker  ./cmd/argus-worker

## install: build then install argus into GOBIN
.PHONY: install
install:
	go install -trimpath -ldflags "$(LDFLAGS)" ./cmd/argus

## test: unit tests with the race detector
.PHONY: test
test:
	go test -race -timeout 180s ./...

## test-short: unit tests without the race detector
.PHONY: test-short
test-short:
	go test ./...

## cover: coverage report with a threshold gate
.PHONY: cover
cover:
	go test -covermode=atomic -coverprofile=cover.out ./... >/dev/null
	go tool cover -func=cover.out | tail -1
	@total=$$(go tool cover -func=cover.out | awk '/^total:/ {print $$3}' | tr -d '%'); \
	if [ -z "$$total" ]; then echo "no coverage data"; exit 1; fi; \
	echo "threshold: 50%"; \
	awk -v t="$$total" 'BEGIN { exit (t+0 >= 50) ? 0 : 1 }' || { echo "coverage $$total% is below the 50% gate"; exit 1; }

## vet: go vet
.PHONY: vet
vet:
	go vet ./...

## fmt: gofmt every package
.PHONY: fmt
fmt:
	gofmt -w .

## fmt-check: fail if anything is unformatted
.PHONY: fmt-check
fmt-check:
	@out=$$(gofmt -l .); \
	if [ -n "$$out" ]; then echo "unformatted files:"; echo "$$out"; exit 1; fi

## lint: gofmt check, vet, and depguard-style import layering
.PHONY: lint
lint: fmt-check vet

## deps: confirm the layering rules of §4.5 hold
.PHONY: deps
deps:
	@echo "pkg/sdk must not import internal/ or modules/"
	@if go list -deps ./pkg/sdk | grep -E 'github.com/WildanDeveloper/argus/(internal|modules)/'; then \
		echo "LAYERING VIOLATION: pkg/sdk imports internal code"; exit 1; \
	else echo "ok"; fi
	@echo "modules/* must not import internal/ or other modules"
	@violations=$$(for p in $$(go list ./modules/...); do \
		go list -deps $$p | grep -E 'github.com/WildanDeveloper/argus/internal/' | sed "s|^|$$p -> |"; done); \
	if [ -n "$$violations" ]; then echo "$violations"; echo "LAYERING VIOLATION"; exit 1; \
	else echo "ok"; fi

## doctor: run the built binary's environment check
.PHONY: doctor
doctor: build
	$(BIN)/argus doctor

## modules-doctor: validate every module manifest
.PHONY: modules-doctor
modules-doctor: build
	$(BIN)/argus modules doctor

## clean
.PHONY: clean
clean:
	rm -rf $(BIN) cover.out

## help
.PHONY: help
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## /  /'