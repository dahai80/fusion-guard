.PHONY: build release test clippy fmt lint check clean

build:
	cargo build

release:
	cargo build --release

test:
	cargo test

clippy:
	cargo clippy --all-targets -- -D warnings

fmt:
	cargo fmt --all -- --check

lint: clippy fmt

check: lint test

clean:
	cargo clean
