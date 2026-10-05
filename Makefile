.PHONY: check test lint format rootfs

ALPINE_VERSION := 3.24.2
ARCH := $(shell uname -m)
ALPINE_TARBALL := alpine-minirootfs-$(ALPINE_VERSION)-$(ARCH).tar.gz
ALPINE_URL := https://dl-cdn.alpinelinux.org/alpine/v$(basename $(ALPINE_VERSION))/releases/$(ARCH)/$(ALPINE_TARBALL)

all: format check lint

check:
	cargo check

test:
	cargo test

lint:
	cargo clippy -- -D warnings

format:
	cargo fmt

rootfs: rootfs/etc/alpine-release

rootfs/etc/alpine-release:
	mkdir -p target rootfs
	cd target && curl -fsSLO $(ALPINE_URL) && curl -fsSLO $(ALPINE_URL).sha256
	cd target && sha256sum -c $(ALPINE_TARBALL).sha256
	tar -xzf target/$(ALPINE_TARBALL) -C rootfs
