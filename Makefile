.PHONY: check test lint format

all: format check lint

check:
	cargo check

test:
	cargo test

lint:
	cargo clippy -- -D warnings

format:
	cargo fmt

