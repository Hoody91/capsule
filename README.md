# capsule

A minimal container runtime in Rust, built to understand the Linux primitives underneath Docker, containerd and Kubernetes.

## Usage

```sh
cargo build --release
sudo ./target/release/capsule run --hostname box1 sh
```

Inside, `hostname` prints `box1`, `echo $$` prints `1`, and `ps` shows only the container's processes.

## Roadmap

- [x] **1. Process isolation** — PID, UTS and mount namespaces via `clone(2)`; private mount propagation; fresh `/proc`.
- [ ] **2. Filesystem isolation** — `pivot_root` into an extracted Alpine rootfs; mount `/proc`, `/sys`, `/dev`; unmount the old root.
- [ ] **3. Resource limits** — cgroups v2: `memory.max`, `pids.max`, `cpu.max`; clean up the cgroup on exit.
- [ ] **4. Networking** — network namespace, veth pair, bridge, NAT to the outside.
- [ ] **5. Hardening** — drop capabilities, seccomp filter, `no_new_privs`, user namespaces for rootless mode.
- [ ] **6. Images** — pull and unpack an OCI image from a registry.

## How it works

`capsule` calls `clone(2)` with `CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWNS`. The child becomes PID 1 in a new PID namespace, marks `/` as `MS_PRIVATE` so its mounts never leak to the host, sets its hostname, mounts a fresh procfs, then `execvp`s the requested command. The parent waits and passes the exit code through (`128 + signal` if killed).