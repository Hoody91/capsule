.PHONY: check test lint format rootfs net-clean demo-image demo-rootfs demo-test

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

# Remove the host-side network state capsule leaves in place between runs.
net-clean:
	-sudo ip link del capsule0
	-sudo nft delete table ip capsule

DEMO := demo/nginx

demo-image:
	docker build -t capsule-nginx $(DEMO)

# Flatten the image into a plain directory capsule can use with --rootfs.
demo-rootfs: demo-image
	rm -rf $(DEMO)/rootfs
	mkdir -p $(DEMO)/rootfs
	id=$$(docker create capsule-nginx) && \
		docker export $$id | tar -x -C $(DEMO)/rootfs; \
		status=$$?; docker rm $$id >/dev/null; exit $$status

# Rootless smoke test: start nginx, fetch the page and stylesheet from inside
# the same container. When sh (PID 1) exits, the kernel kills nginx with it.
demo-test:
	cargo build --release
	./target/release/capsule run --rootfs $(DEMO)/rootfs sh -c '\
		nginx & sleep 0.5; \
		wget -qO- http://127.0.0.1:8080/ | grep -q "Served by nginx inside capsule" && echo "index.html: ok"; \
		wget -qS -O /dev/null http://127.0.0.1:8080/style.css 2>&1 | grep -i "content-type"'
