# capsule

A minimal container runtime in Rust, built to understand the Linux primitives underneath Docker, containerd and Kubernetes.

## Usage

```sh
sudo apt install nftables   # for the container's outbound NAT
make rootfs                 # download and extract an Alpine minirootfs into ./rootfs
cargo build --release
sudo ./target/release/capsule run --rootfs ./rootfs --hostname box1 sh
```

Inside, you're in Alpine: `cat /etc/alpine-release` prints its version, `hostname` prints `box1`, `echo $$` prints `1`, and `ps` shows only the container's processes. The host's filesystem is not reachable. `ip addr` shows an `eth0` on `10.200.0.0/24`, and the internet is reachable through NAT.

### Rootless

Without sudo, capsule runs rootless. It creates its own user namespace in which your user is root, and defaults to `--network none`:

```sh
./target/release/capsule run --rootfs ./rootfs sh
```

Inside, `id` says root, but on the host the processes belong to you. Only your one UID/GID is mapped, so switching to another user inside (`su nobody`, say) fails. Bridge networking and resource limits need host root, so they still need `sudo`.

### Networking

By default (`--network bridge`), each container gets its own network namespace connected to the host's `capsule0` bridge, with outbound NAT. `--network none` gives an isolated namespace with only loopback. It needs no host privileges, and it's the default when running rootless.

The bridge, the NAT table and `net.ipv4.ip_forward=1` stay in place between runs, like Docker's `docker0`. `make net-clean` removes the bridge and the NAT table.

### Resource limits

```sh
sudo ./target/release/capsule run --rootfs ./rootfs --memory 64M --pids 32 --cpus 0.5 sh
```

`--memory` takes bytes with an optional `K`/`M`/`G` suffix, `--pids` caps the number of processes, and `--cpus` is a fraction of one CPU. Limits need root and cgroup v2. Without any limit flags, no cgroup is created.

On WSL, the default hybrid setup leaves cgroup v2 with no controllers. To switch to pure v2, add this to `%UserProfile%\.wslconfig`, then run `wsl --shutdown`:

```ini
[wsl2]
kernelCommandLine = cgroup_no_v1=all
```

## Roadmap

- [x] **1. Process isolation** — PID, UTS and mount namespaces via `clone(2)`; private mount propagation; fresh `/proc`.
- [x] **2. Filesystem isolation** — `pivot_root` into an extracted Alpine rootfs; mount `/proc`, `/sys`, `/dev`; unmount the old root.
- [x] **3. Resource limits** — cgroups v2: `memory.max`, `pids.max`, `cpu.max`; clean up the cgroup on exit.
- [x] **4. Networking** — network namespace, veth pair, bridge, NAT to the outside.
- [x] **5. Hardening** — drop capabilities, seccomp filter, `no_new_privs`, user namespaces for rootless mode.
- [ ] **6. Images** — pull and unpack an OCI image from a registry.

## How it works

`capsule` calls `clone(2)` with `CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWNS | CLONE_NEWNET`, plus `CLONE_NEWUSER` when rootless. The child becomes PID 1 in a new PID namespace, marks `/` as `MS_PRIVATE` so its mounts never leak to the host, sets its hostname, sets up the container's filesystem, then execs the requested command with a clean environment. The parent waits and passes the exit code through (`128 + signal` if killed).

The filesystem is set up before the root is switched, while the host's `/dev` is still reachable. The rootfs is bind-mounted onto itself, because `pivot_root(2)` needs the new root to be a mount point. Then the child mounts:

- a fresh procfs at `proc`
- a read-only sysfs at `sys`
- a tmpfs at `dev`, holding bind mounts of the host's `null`, `zero`, `full`, `random`, `urandom` and `tty` nodes, a private `devpts` instance, a `shm` tmpfs, and the usual `fd`/`stdin`/`stdout`/`stderr`/`ptmx` symlinks

Finally it calls `pivot_root(".", ".")` from inside the rootfs. That stacks the old root on top of the new one, and a lazy `umount2(".", MNT_DETACH)` then removes the old root, so no `put_old` directory is needed.

When limits are given, the parent creates `/sys/fs/cgroup/capsule/<pid>` before cloning and writes `memory.max` (plus `memory.swap.max = 0`, so the limit leads to an OOM kill instead of swapping), `pids.max` and `cpu.max`. Each controller is first enabled in the parent's `cgroup.subtree_control`. The `capsule` level never holds processes itself, so cgroup v2's "no internal processes" rule holds.

The child must be inside the cgroup before it execs. The parent can only learn the child's PID once `clone` returns, so the child starts by blocking on a pipe. The parent writes the PID to `cgroup.procs` and then sends one byte to release it. If anything fails, the parent closes the pipe instead, and the child sees EOF and exits. When the container exits, the parent writes `cgroup.kill` to catch any stragglers and removes the cgroup directory. If the OOM killer ran, capsule says so on stderr.

Networking uses hand-built rtnetlink messages (`src/netlink.rs`), the same requests `ip link`/`ip addr`/`ip route` send. Before cloning, the parent:

- creates the `capsule0` bridge with address `10.200.0.1/24`
- turns on IP forwarding
- loads an idempotent nftables ruleset that masquerades `10.200.0.0/24` traffic leaving the host
- leases an address by atomically creating `/run/capsule/ips/<addr>` holding its PID; leases whose PID is gone are reclaimed
- writes a `resolv.conf` (the host's nameservers minus loopback ones) and a `hosts` file, which the child bind-mounts read-only over the rootfs's

After `clone`, while the child is still blocked on the pipe, the parent creates a veth pair. The `eth0` end is created directly inside the child's namespace (`IFLA_NET_NS_PID`), and the host end `vcap<pid>` is attached to the bridge. Once released, the child brings up `lo` and `eth0`, assigns its address, and adds a default route via the bridge. When the container exits, its namespace is destroyed, and the kernel deletes the veth pair with it.

Rootless mode relies on the kernel creating the user namespace first in `clone(2)`. The other namespaces are then owned by it, which is why an unprivileged user may create them. The child starts with no ID mapping, but it is already waiting on the pipe, so the parent writes `/proc/<pid>/setgroups` (`deny`, which the kernel requires before an unprivileged `gid_map` write), then `uid_map` and `gid_map` (`0 <your id> 1`), before releasing it.

The last step before exec is hardening (`src/security.rs`), in this order:

1. **`no_new_privs`:** setuid binaries and file capabilities can no longer raise privileges, and an unprivileged process may install a seccomp filter.
2. **Capabilities:** everything outside Docker's default set is dropped from the bounding set, the ambient set is cleared, and `capset(2)` sets effective, permitted and inheritable to the same set. `CapEff` reads `00000000a80425fb`, as in a Docker container.
3. **Seccomp:** a classic BPF filter kills the process for a non-x86_64 arch or an x32-ABI syscall. It returns `EPERM` for a deny-list of syscalls that change the kernel or system (modules, kexec, reboot, clock), rearrange the container's view (`mount`, `pivot_root`, `unshare`, `setns`, the new mount API) or expose a large attack surface (`bpf`, `perf_event_open`, `userfaultfd`, `keyctl`, `ptrace`, `io_uring`). It goes last, so the steps above aren't filtered.
