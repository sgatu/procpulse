# ==============================================================================
# Ultra-Light Windows Process Telemetry & Load Diagnostics (procpulse) Makefile
# ==============================================================================

.PHONY: help build release test check clean run

help:
	@echo Available targets:
	@echo   make build    - Build procpulse in debug mode
	@echo   make release  - Build optimized release binary (LTO, stripped)
	@echo   make test     - Run all unit and integration tests
	@echo   make check    - Fast syntax and type checking without code generation
	@echo   make clean    - Remove build artifacts (target/)
	@echo   make run      - Run procpulse in debug mode

build:
	cargo build

release:
	cargo build --release --bin procpulse

test:
	cargo test

check:
	cargo check

clean:
	cargo clean

run:
	cargo run --bin procpulse
