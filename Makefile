SHELL := /bin/bash
.DEFAULT_GOAL := help
.PHONY: $(shell sed -n -e '/^$$/ { n ; /^[^ .\#][^ ]*:/ { s/:.*$$// ; p ; } ; }' $(MAKEFILE_LIST))

# Smaller binaries: omit symbol table and DWARF debug info (harder to inspect with pprof unless rebuilt).
DIST_GO_LDFLAGS := -s -w

# Build vpnless-caddy and CLI
build: # Build Caddy and CLI
	@$(MAKE) --no-print-directory build-caddy-full
	@$(MAKE) --no-print-directory build-cli
	sudo setcap 'cap_net_bind_service=+ep' vpnless-caddy

# Build Caddy with vpnless module + caddy-docker-proxy
build-caddy-full: # Build vpnless-caddy with built-in docker-proxy defaults
	@echo "Building vpnless-caddy with built-in docker-proxy defaults..."
	go build -o vpnless-caddy ./cmd/vpnless-caddy

# Build the CLI tool
build-cli: # Build vpnless CLI binary
	@echo "Building CLI tool..."
	go build -o vpnless ./cmd/vpnless-cli

# Stripped binaries for release / smaller images (see DIST_GO_LDFLAGS).
build-dist: # Build vpnless-caddy + vpnless with -ldflags -s -w
	@echo "Building stripped vpnless-caddy..."
	go build -ldflags="$(DIST_GO_LDFLAGS)" -o vpnless-caddy ./cmd/vpnless-caddy
	@echo "Building stripped vpnless CLI..."
	go build -ldflags="$(DIST_GO_LDFLAGS)" -o vpnless ./cmd/vpnless-cli
	sudo setcap 'cap_net_bind_service=+ep' vpnless-caddy

# Run tests
test: # Run Go tests
	@# Force an empty build-tag set so opt-in xcaddye2e E2E tests don't run.
	go test -tags '' ./...

# Optional slow E2E test: builds and runs real Caddy via xcaddy.
test-xcaddy-e2e: # Run slow xcaddy E2E test
	go test -tags xcaddye2e -run TestE2E_XCaddyBinary_DeviceAuthAndCookieFlow ./...

# Clean build artifacts
clean: # Remove local build artifacts
	rm -f caddy vpnless-caddy vpnless
	rm -f vpnless.db vpnless.db-shm vpnless.db-wal authorized_devices.db authorized_devices.db-shm authorized_devices.db-wal authorized_devices.json

help: # List make targets (interactive with fzf when available)
	@if command -v fzf >/dev/null 2>&1; then \
		output=$$(awk 'BEGIN {FS=":.*# "}; /^[a-zA-Z0-9_.-]+:.*# / {printf "%s,| %s\n", $$1, $$2}' "$(lastword $(MAKEFILE_LIST))" | column -t -s ',' | fzf --tiebreak=index --height '80%'); \
		if [ $$? -eq 0 ] && [ -n "$$output" ]; then \
			target=$$(echo "$$output" | sed --regexp-extended 's/\s*\|.*//'); \
			exec $(MAKE) --no-print-directory "$$target"; \
		else \
			echo "Operation cancelled"; \
		fi; \
	else \
		awk 'BEGIN {FS=":.*# "}; /^[a-zA-Z0-9_.-]+:.*# / {printf "%s,| %s\n", $$1, $$2}' "$(lastword $(MAKEFILE_LIST))" | column -t -s ','; \
	fi
