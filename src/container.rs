use std::ffi::CString;

use anyhow::{Context, Result};
use nix::mount::{MsFlags, mount};
use nix::sched::{CloneFlags, clone};
use nix::sys::signal::Signal;
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::{execvp, sethostname};

use crate::cli::Config;

const STACK_SIZE: usize = 1024 * 1024;

/// Run the configured command in new namespaces and return its exit code.
pub fn run(config: &Config) -> Result<u8> {
    // Build the argv up front so the child does no fallible allocation work
    // beyond what it strictly needs.
    let argv: Vec<CString> = std::iter::once(&config.command)
        .chain(&config.args)
        .map(|s| CString::new(s.as_str()))
        .collect::<Result<_, _>>()
        .context("command contains a NUL byte")?;

    let flags = CloneFlags::CLONE_NEWPID | CloneFlags::CLONE_NEWUTS | CloneFlags::CLONE_NEWNS;

    let mut stack = vec![0u8; STACK_SIZE];
    let child = Box::new(|| match init(config, &argv) {
        Ok(never) => match never {},
        Err(e) => {
            eprintln!("capsule (child): {e:#}");
            126
        }
    });

    // SAFETY: the child only runs `init`, which execs or returns an exit code.
    // SIGCHLD lets the parent reap it with waitpid.
    let pid = unsafe { clone(child, &mut stack, flags, Some(Signal::SIGCHLD as i32)) }
        .context("clone failed (are you root?)")?;

    match waitpid(pid, None).context("waitpid failed")? {
        WaitStatus::Exited(_, code) => Ok(code as u8),
        WaitStatus::Signaled(_, sig, _) => Ok(128 + sig as u8),
        other => anyhow::bail!("unexpected wait status: {other:?}"),
    }
}

/// Runs inside the new namespaces as PID 1, then replaces itself with the command.
fn init(config: &Config, argv: &[CString]) -> Result<std::convert::Infallible> {
    // Stop our mount changes propagating back to the host's mount namespace.
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .context("making / private")?;

    sethostname(&config.hostname).context("sethostname")?;

    // A fresh procfs reflects our PID namespace, so `ps` only sees this container.
    mount(
        Some("proc"),
        "/proc",
        Some("proc"),
        MsFlags::empty(),
        None::<&str>,
    )
    .context("mounting /proc")?;

    execvp(&argv[0], argv).with_context(|| format!("exec {:?}", argv[0]))
}
