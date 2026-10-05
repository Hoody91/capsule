use std::convert::Infallible;
use std::ffi::{CString, NulError};
use std::path::{Path, PathBuf};
use std::{fmt, io};

use nix::errno::Errno;
use nix::mount::{MsFlags, mount};
use nix::sched::{CloneFlags, clone};
use nix::sys::signal::Signal;
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::{execvpe, sethostname};

use crate::cli::Config;
use crate::rootfs;

const STACK_SIZE: usize = 1024 * 1024;

/// The host's PATH means nothing inside the rootfs, so commands get this one.
const CONTAINER_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

#[derive(Debug)]
pub enum Error {
    NulInCommand(NulError),
    Rootfs { path: PathBuf, source: io::Error },
    RootfsNotDir(PathBuf),
    Clone(Errno),
    Wait(Errno),
    UnexpectedWaitStatus(WaitStatus),
    MakeRootPrivate(Errno),
    SetHostname(Errno),
    Mount { target: PathBuf, source: Errno },
    Prepare { path: PathBuf, source: io::Error },
    Chdir { path: PathBuf, source: Errno },
    PivotRoot(Errno),
    UnmountOldRoot(Errno),
    Exec { command: CString, source: Errno },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NulInCommand(e) => write!(f, "command contains a NUL byte: {e}"),
            Error::Rootfs { path, source } => write!(f, "rootfs {}: {source}", path.display()),
            Error::RootfsNotDir(path) => write!(f, "rootfs {} is not a directory", path.display()),
            Error::Clone(e) => write!(f, "clone failed (are you root?): {e}"),
            Error::Wait(e) => write!(f, "waitpid failed: {e}"),
            Error::UnexpectedWaitStatus(status) => write!(f, "unexpected wait status: {status:?}"),
            Error::MakeRootPrivate(e) => write!(f, "making / private: {e}"),
            Error::SetHostname(e) => write!(f, "sethostname: {e}"),
            Error::Mount { target, source } => {
                write!(f, "mounting {}: {source}", target.display())
            }
            Error::Prepare { path, source } => write!(f, "creating {}: {source}", path.display()),
            Error::Chdir { path, source } => write!(f, "chdir {}: {source}", path.display()),
            Error::PivotRoot(e) => write!(f, "pivot_root: {e}"),
            Error::UnmountOldRoot(e) => write!(f, "unmounting old root: {e}"),
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
    let env = container_env();

    let rootfs = std::fs::canonicalize(&config.rootfs).map_err(|source| Error::Rootfs {
        path: config.rootfs.clone(),
        source,
    })?;
    if !rootfs.is_dir() {
        return Err(Error::RootfsNotDir(rootfs));
    }

    let flags = CloneFlags::CLONE_NEWPID | CloneFlags::CLONE_NEWUTS | CloneFlags::CLONE_NEWNS;

    let mut stack = vec![0u8; STACK_SIZE];
    let child = Box::new(|| match init(config, &rootfs, &argv, &env) {
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
fn init(
    config: &Config,
    rootfs: &Path,
    argv: &[CString],
    env: &[CString],
) -> Result<Infallible, Error> {
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

    rootfs::enter(rootfs)?;

    // execvpe searches the caller's PATH, not the one in `env`, so set ours.
    // SAFETY: the cloned child is single-threaded, so nothing reads the
    // environment concurrently.
    unsafe { std::env::set_var("PATH", CONTAINER_PATH) };

    execvpe(&argv[0], argv, env).map_err(|source| Error::Exec {
        command: argv[0].clone(),
        source,
    })
}

/// The environment the command starts with: a clean one rather than the host's.
fn container_env() -> Vec<CString> {
    let mut env = vec![format!("PATH={CONTAINER_PATH}"), "HOME=/root".to_string()];
    if let Ok(term) = std::env::var("TERM") {
        env.push(format!("TERM={term}"));
    }
    // Neither the constants nor an existing env var can contain a NUL byte.
    env.into_iter()
        .map(|var| CString::new(var).expect("env var contains a NUL byte"))
        .collect()
}
