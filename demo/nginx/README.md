# nginx demo

A small nginx image serving a static page, used to test capsule with a real application before it can pull images itself.

## Build and flatten (needs Docker)

```sh
make demo-rootfs
```

This builds the `capsule-nginx` image and exports its filesystem into `demo/nginx/rootfs`.

## Run under capsule

Rootless, with loopback only. Start nginx and fetch from inside the same container:

```sh
make demo-test
```

With root and bridge networking, nginx is reachable from the host:

```sh
sudo ./target/release/capsule run --rootfs demo/nginx/rootfs nginx
curl http://10.200.0.2:8080/   # the container's address: ls /run/capsule/ips
```

capsule doesn't read the image's `CMD` yet, so `nginx` is given explicitly.

## Why the config looks like this

- `daemon off;` keeps nginx in the foreground, so it is the container's PID 1 and its exit status passes through.
- `master_process off;` and `user root root;` are both there because rootless capsule maps only your UID, to root:
  - With workers, nginx would switch user with `setgid`/`initgroups`/`setuid`. Those calls fail there, because the target user isn't mapped and `setgroups` is denied in that user namespace.
  - Even as a single process, nginx `chown`s its temp directories to the configured user, which defaults to `nginx` (uid 101). That uid isn't mapped, so the call fails with `EINVAL`. Running "as root" points the chown at the one user that is mapped.
- The PID file and temp directories live in `/tmp`, and logs go to `/dev/stdout` and `/dev/stderr`. capsule runs every container on a copy-on-write layer over the rootfs, so nothing nginx writes reaches `demo/nginx/rootfs`.
- It listens on IPv4 port 8080 only, because capsule containers have no IPv6.

## Sanity check in plain Docker

```sh
docker run --rm -p 8080:8080 capsule-nginx
curl http://localhost:8080/
```
