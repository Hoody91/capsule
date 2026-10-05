# capsule

A minimal container runtime in Rust, built to understand the Linux primitives underneath Docker, containerd and Kubernetes.

## Usage

```sh
make rootfs            # download and extract an Alpine minirootfs into ./rootfs
cargo build --release
sudo ./target/release/capsule run --rootfs ./rootfs --hostname box1 sh
```

Inside, you're in Alpine: `cat /etc/alpine-release` prints its version, `hostname` prints `box1`, `echo $$` prints `1`, and `ps` shows only the container's processes. The host's filesystem is not reachable.

Without root, `unshare -Urmn ./target/release/capsule run --rootfs ./rootfs sh` works too. The `-n` matters: mounting sysfs requires owning the network namespace.

## Roadmap

- [x] **1. Process isolation** — PID, UTS and mount namespaces via `clone(2)`; private mount propagation; fresh `/proc`.
- [x] **2. Filesystem isolation** — `pivot_root` into an extracted Alpine rootfs; mount `/proc`, `/sys`, `/dev`; unmount the old root.
- [ ] **3. Resource limits** — cgroups v2: `memory.max`, `pids.max`, `cpu.max`; clean up the cgroup on exit.
- [ ] **4. Networking** — network namespace, veth pair, bridge, NAT to the outside.
- [ ] **5. Hardening** — drop capabilities, seccomp filter, `no_new_privs`, user namespaces for rootless mode.
- [ ] **6. Images** — pull and unpack an OCI image from a registry.

## How it works

`capsule` calls `clone(2)` with `CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWNS`. The child becomes PID 1 in a new PID namespace, marks `/` as `MS_PRIVATE` so its mounts never leak to the host, sets its hostname, sets up the container's filesystem, then execs the requested command with a clean environment. The parent waits and passes the exit code through (`128 + signal` if killed).

The filesystem is set up before the root is switched, while the host's `/dev` is still reachable. The rootfs is bind-mounted onto itself, because `pivot_root(2)` needs the new root to be a mount point. Then the child mounts:

- a fresh procfs at `proc`
- a read-only sysfs at `sys`
- a tmpfs at `dev`, holding bind mounts of the host's `null`, `zero`, `full`, `random`, `urandom` and `tty` nodes, a private `devpts` instance, a `shm` tmpfs, and the usual `fd`/`stdin`/`stdout`/`stderr`/`ptmx` symlinks

Finally it calls `pivot_root(".", ".")` from inside the rootfs. That stacks the old root on top of the new one, and a lazy `umount2(".", MNT_DETACH)` then removes the old root, so no `put_old` directory is needed.
