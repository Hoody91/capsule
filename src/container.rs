use std::convert::Infallible;
use std::ffi::{CString, NulError};
use std::fmt;

use nix::errno::Errno;
use nix::mount::{MsFlags, mount};
use nix::sched::{CloneFlags, clone};
use nix::sys::signal::Signal;
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::{execvp, sethostname};

use crate::cli::Config;

const STACK_SIZE: usize = 1024 * 1024;

#[derive(Debug)]
pub enum Error {
    NulInCommand(NulError),
    Clone(Errno),
    Wait(Errno),
    UnexpectedWaitStatus(WaitStatus),
    MakeRootPrivate(Errno),
    SetHostname(Errno),
    MountProc(Errno),
    Exec { command: CString, source: Errno },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NulInCommand(e) => write!(f, "command contains a NUL byte: {e}"),
            Error::Clone(e) => write!(f, "clone failed (are you root?): {e}"),
            Error::Wait(e) => write!(f, "waitpid failed: {e}"),
            Error::UnexpectedWaitStatus(status) => write!(f, "unexpected wait status: {status:?}"),
            Error::MakeRootPrivate(e) => write!(f, "making / private: {e}"),
            Error::SetHostname(e) => write!(f, "sethostname: {e}"),
            Error::MountProc(e) => write!(f, "mounting /proc: {e}"),
            Error::Exec { command, source } => write!(f, "exec {command:?}: {source}"),
        }
    }
}

// The cause is already part of the Display message, so `source()` is left as
// `None` to avoid it being printed twice by anything that walks the chain.
impl std::error::Error for Error {}

/// Run the configured command in new namespaces and return its exit code.
pub fn run(config: &Config) -> Result<u8, Error> {
    // Build the argv up front so the child does no fallible allocation work
    // beyond what it strictly needs.
    let argv: Vec<CString> = std::iter::once(&config.command)
        .chain(&config.args)
        .map(|s| CString::new(s.as_str()))
        .collect::<Result<_, _>>()
        .map_err(Error::NulInCommand)?;

    let flags = CloneFlags::CLONE_NEWPID | CloneFlags::CLONE_NEWUTS | CloneFlags::CLONE_NEWNS;

    let mut stack = vec![0u8; STACK_SIZE];
    let child = Box::new(|| match init(config, &argv) {
        Ok(never) => match never {},
        Err(e) => {
            eprintln!("capsule (child): {e}");
            126
        }
    });

    // SAFETY: the child only runs `init`, which execs or returns an exit code.
    // SIGCHLD lets the parent reap it with waitpid.
    let pid = unsafe { clone(child, &mut stack, flags, Some(Signal::SIGCHLD as i32)) }
        .map_err(Error::Clone)?;

    match waitpid(pid, None).map_err(Error::Wait)? {
        WaitStatus::Exited(_, code) => Ok(code as u8),
        WaitStatus::Signaled(_, sig, _) => Ok(128 + sig as u8),
        other => Err(Error::UnexpectedWaitStatus(other)),
    }
}

/// Runs inside the new namespaces as PID 1, then replaces itself with the command.
fn init(config: &Config, argv: &[CString]) -> Result<Infallible, Error> {
    // Stop our mount changes propagating back to the host's mount namespace.
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .map_err(Error::MakeRootPrivate)?;

    sethostname(&config.hostname).map_err(Error::SetHostname)?;

    // A fresh procfs reflects our PID namespace, so `ps` only sees this container.
    mount(
        Some("proc"),
        "/proc",
        Some("proc"),
        MsFlags::empty(),
        None::<&str>,
    )
    .map_err(Error::MountProc)?;

    execvp(&argv[0], argv).map_err(|source| Error::Exec {
        command: argv[0].clone(),
        source,
    })
}
