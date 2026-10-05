//! End-to-end tests that run real containers. As a normal user capsule runs
//! rootless, so these need no sudo, only the Alpine rootfs from `make rootfs`.

use std::path::PathBuf;
use std::process::{Command, Output};

/// The rootfs to run in, or `None` (and a note) if it hasn't been fetched.
fn rootfs() -> Option<PathBuf> {
    let rootfs = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rootfs");
    if rootfs.join("etc/alpine-release").exists() {
        Some(rootfs)
    } else {
        eprintln!("skipping: no rootfs, run `make rootfs`");
        None
    }
}

/// Run `sh -c script` in a container with only loopback networking.
fn run_sh(rootfs: &PathBuf, extra: &[&str], script: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_capsule"))
        .arg("run")
        .arg("--rootfs")
        .arg(rootfs)
        .args(["--network", "none"])
        .args(extra)
        .args(["sh", "-c", script])
        .output()
        .expect("failed to spawn capsule")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn runs_as_root_pid_1_with_hostname() {
    let Some(rootfs) = rootfs() else { return };
    let output = run_sh(
        &rootfs,
        &["--hostname", "box"],
        "echo $$ $(hostname) $(id -u)",
    );
    assert_eq!(
        stdout(&output).trim(),
        "1 box 0",
        "stderr: {}",
        stderr(&output)
    );
}

#[test]
fn passes_through_exit_code() {
    let Some(rootfs) = rootfs() else { return };
    let output = run_sh(&rootfs, &[], "exit 7");
    assert_eq!(output.status.code(), Some(7), "stderr: {}", stderr(&output));
}

#[test]
fn drops_capabilities_and_sets_seccomp() {
    let Some(rootfs) = rootfs() else { return };
    let output = run_sh(&rootfs, &[], "cat /proc/self/status");
    let status = stdout(&output);
    let field = |name: &str| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(name)?.strip_prefix(':'))
            .unwrap_or_else(|| panic!("no {name} in status; stderr: {}", stderr(&output)))
            .trim()
            .to_string()
    };
    // Docker's default capability set.
    assert_eq!(field("CapEff"), "00000000a80425fb");
    assert_eq!(field("CapBnd"), "00000000a80425fb");
    assert_eq!(field("CapAmb"), "0000000000000000");
    assert_eq!(field("NoNewPrivs"), "1");
    assert_eq!(field("Seccomp"), "2", "2 means a filter is installed");
}

#[test]
fn cannot_mount() {
    let Some(rootfs) = rootfs() else { return };
    let output = run_sh(&rootfs, &[], "mount -t tmpfs t /mnt");
    assert!(!output.status.success(), "mount succeeded");
}

#[test]
fn cannot_write_sysrq_trigger() {
    let Some(rootfs) = rootfs() else { return };
    let output = run_sh(&rootfs, &[], "echo h > /proc/sysrq-trigger");
    assert!(!output.status.success(), "wrote /proc/sysrq-trigger");
}

#[test]
fn network_none_has_only_loopback() {
    let Some(rootfs) = rootfs() else { return };
    let output = run_sh(&rootfs, &[], "ls /sys/class/net");
    assert_eq!(stdout(&output).trim(), "lo", "stderr: {}", stderr(&output));
}

#[test]
fn host_filesystem_is_not_visible() {
    let Some(rootfs) = rootfs() else { return };
    let output = run_sh(&rootfs, &[], "cat /etc/alpine-release && ! ls /home/*/dev");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
}

#[test]
fn writes_do_not_reach_the_rootfs() {
    let Some(rootfs) = rootfs() else { return };
    let marker = format!("capsule-test-{}", std::process::id());
    let output = run_sh(
        &rootfs,
        &[],
        &format!("echo x > /etc/{marker} && rm /etc/alpine-release && cat /etc/{marker}"),
    );
    assert_eq!(stdout(&output).trim(), "x", "stderr: {}", stderr(&output));
    assert!(
        !rootfs.join("etc").join(&marker).exists(),
        "write leaked into rootfs"
    );
    assert!(
        rootfs.join("etc/alpine-release").exists(),
        "delete leaked into rootfs"
    );
}
