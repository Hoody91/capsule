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

### Resource limits

```sh
sudo ./target/release/capsule run --rootfs ./rootfs --memory 64M --pids 32 --cpus 0.5 sh
```

`--memory` takes bytes with an optional `K`/`M`/`G` suffix, `--pids` caps the number of processes, and `--cpus` is a fraction of one CPU. Limits need root and cgroup v2. Without any limit flags, no cgroup is created and rootless mode still works.

On WSL, the default hybrid setup leaves cgroup v2 with no controllers. To switch to pure v2, add this to `%UserProfile%\.wslconfig`, then run `wsl --shutdown`:

```ini
[wsl2]
kernelCommandLine = cgroup_no_v1=all
```

## Roadmap

- [x] **1. Process isolation** — PID, UTS and mount namespaces via `clone(2)`; private mount propagation; fresh `/proc`.
- [x] **2. Filesystem isolation** — `pivot_root` into an extracted Alpine rootfs; mount `/proc`, `/sys`, `/dev`; unmount the old root.
- [x] **3. Resource limits** — cgroups v2: `memory.max`, `pids.max`, `cpu.max`; clean up the cgroup on exit.
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

When limits are given, the parent creates `/sys/fs/cgroup/capsule/<pid>` before cloning and writes `memory.max` (plus `memory.swap.max = 0`, so the limit leads to an OOM kill instead of swapping), `pids.max` and `cpu.max`. Each controller is first enabled in the parent's `cgroup.subtree_control`. The `capsule` level never holds processes itself, so cgroup v2's "no internal processes" rule holds.

The child must be inside the cgroup before it execs. The parent can only learn the child's PID once `clone` returns, so the child starts by blocking on a pipe. The parent writes the PID to `cgroup.procs` and then sends one byte to release it. If anything fails, the parent closes the pipe instead, and the child sees EOF and exits. When the container exits, the parent writes `cgroup.kill` to catch any stragglers and removes the cgroup directory. If the OOM killer ran, capsule says so on stderr.
