# Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
# SPDX-License-Identifier: AGPL-3.0-only

SHELL := /bin/bash
export GOWORK := off
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all build release test clean firewall help local-package

all: build

# ONE binary for both roles. The role is selected at runtime with
# `-role server|client` or the `cursus server` / `cursus client` subcommand.
build:
	@mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/cursus ./cmd/cursus
	@ls -lh bin/cursus

# Cross-compile for the three release targets produced by CI.
release:
	@mkdir -p bin
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/cursus-linux-amd64 ./cmd/cursus
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/cursus-linux-arm64 ./cmd/cursus
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/cursus-windows-amd64.exe ./cmd/cursus
	@ls -lh bin/cursus-*

test:
	go test ./... -count=1
	go test -race ./internal/... -count=1

# Print the exact firewall ports to open. No remote changes.
firewall: build
	@./bin/cursus -role server -config configs/cursus-server.yaml -firewall

# Local smoke package (only used for debugging CI packaging; releases are
# built and published exclusively by GitHub Actions).
local-package: build
	@echo "CI builds .deb / setup.exe; see .github/workflows/release.yml"

clean:
	rm -rf bin dist

help:
	@echo "make build     -> bin/cursus (single binary, -role server|client)"
	@echo "make release   -> linux amd64/arm64 + windows amd64 binaries"
	@echo "make test      -> unit + race tests"
	@echo "make firewall  -> print UDP/TCP ports to open"
	@echo "CI (tag push) -> .deb + setup.exe + GitHub Release"
