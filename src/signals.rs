//! Keep capsule alive through termination signals, so it always gets to clean
//! up after the container (its cgroup, layer directory and network lease).
//!
//! The signals are blocked and read from a signalfd instead of killing the
//! process. The first one is passed on to the container; a second one kills it.

use std::os::fd::OwnedFd;

use libc::{c_int, pid_t, sigset_t};

use crate::container::Error;
use crate::sys::{self, WaitStatus};

/// Signals that would otherwise end capsule while the container runs.
const TERMINATING: [c_int; 4] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT];

/// Blocks the terminating signals (and SIGCHLD, to learn when the container
/// exits) until dropped.
pub struct Signals {
    fd: OwnedFd,
    old_mask: sigset_t,
}

impl Signals {
    /// Start catching signals. Call this before creating anything that needs
    /// cleaning up, so a signal can't arrive between creating it and being
    /// ready to clean it up.
    pub fn block() -> Result<Signals, Error> {
        let mut signals = TERMINATING.to_vec();
        signals.push(libc::SIGCHLD);
        let set = sys::sigset(&signals);
        let old_mask = sys::sigmask(libc::SIG_BLOCK, &set).map_err(Error::Signals)?;
        let fd = sys::signalfd(&set).map_err(Error::Signals)?;
        Ok(Signals { fd, old_mask })
    }

    /// The mask from before `block`. The container's process must start with
    /// it, because a blocked signal mask survives exec.
    pub fn original_mask(&self) -> sigset_t {
        self.old_mask
    }

    /// Wait for the container's PID 1 to exit, passing signals on to it.
    pub fn supervise(&self, pid: pid_t) -> Result<WaitStatus, Error> {
        let mut forwarded = false;
        loop {
            // Checked before every read: an exit that happened before we got
            // here is already reapable, and its SIGCHLD may be long consumed.
            if let Some(status) = sys::try_waitpid(pid).map_err(Error::Wait)? {
                return Ok(status);
            }

            let info = sys::read_signal(&self.fd).map_err(Error::Signals)?;
            let signal = info.ssi_signo as c_int;
            if signal == libc::SIGCHLD {
                continue;
            }
            // Ctrl-C and Ctrl-\ at the terminal: the kernel already sent them
            // to the whole foreground process group, container included, so
            // they're the container's to handle (an interactive shell just
            // cancels the line).
            if info.ssi_code == libc::SI_KERNEL && matches!(signal, libc::SIGINT | libc::SIGQUIT) {
                continue;
            }

            let name = signal_name(signal);
            if forwarded {
                eprintln!("capsule: second signal ({name}), killing the container");
                // Unlike other signals, SIGKILL reaches a namespace's PID 1
                // from outside even when it has no handler.
                send(pid, libc::SIGKILL)?;
            } else {
                eprintln!("capsule: passing {name} to the container; send it again to kill it");
                send(pid, signal)?;
                forwarded = true;
            }
        }
    }
}

impl Drop for Signals {
    fn drop(&mut self) {
        // Any signal still pending is delivered as soon as this unblocks it.
        let _ = sys::sigmask(libc::SIG_SETMASK, &self.old_mask);
    }
}

/// Signal `pid`, tolerating it having already exited (it may be a zombie
/// waiting to be reaped, or gone).
fn send(pid: pid_t, signal: c_int) -> Result<(), Error> {
    match sys::kill(pid, signal) {
        Err(e) if e.raw_os_error() == Some(libc::ESRCH) => Ok(()),
        other => other.map_err(Error::Signals),
    }
}

fn signal_name(signal: c_int) -> &'static str {
    match signal {
        libc::SIGINT => "SIGINT",
        libc::SIGTERM => "SIGTERM",
        libc::SIGHUP => "SIGHUP",
        libc::SIGQUIT => "SIGQUIT",
        _ => "signal",
    }
}
