use std::convert::Infallible;
use std::ffi::{CString, NulError};
use std::fs::File;
use std::io::Write;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::{fmt, io};

use libc::{c_int, gid_t, pid_t, sigset_t, uid_t};

use crate::cgroup::Cgroup;
use crate::cli::{Config, NetworkMode};
use crate::network::{self, Network};
use crate::overlay::Overlay;
use crate::signals::Signals;
use crate::sys::{self, WaitStatus};
use crate::{rootfs, security, sweep, userns};

const STACK_SIZE: usize = 1024 * 1024;

/// The host's PATH means nothing inside the rootfs, so commands get this one.
const CONTAINER_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

#[derive(Debug)]
pub enum Error {
    NulInCommand(NulError),
    Rootfs { path: PathBuf, source: io::Error },
    RootfsNotDir(PathBuf),
    Overlay { path: PathBuf, source: io::Error },
    OverlayPath(PathBuf),
    CgroupUnavailable(String),
    Cgroup { path: PathBuf, source: io::Error },
    Pipe(io::Error),
    Signals(io::Error),
    ParentAborted,
    Netlink { op: &'static str, source: io::Error },
    Nft(String),
    NoFreeAddress,
    Network { path: PathBuf, source: io::Error },
    LimitsNeedRoot,
    UserNamespace { path: PathBuf, source: io::Error },
    Security { op: &'static str, source: io::Error },
    Clone(io::Error),
    Wait(io::Error),
    UnexpectedWaitStatus(c_int),
    MakeRootPrivate(io::Error),
    SetHostname(io::Error),
    Mount { target: PathBuf, source: io::Error },
    Prepare { path: PathBuf, source: io::Error },
    Chdir { path: PathBuf, source: io::Error },
    PivotRoot(io::Error),
    UnmountOldRoot(io::Error),
    Exec { command: CString, source: io::Error },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NulInCommand(e) => write!(f, "command contains a NUL byte: {e}"),
            Error::Rootfs { path, source } => write!(f, "rootfs {}: {source}", path.display()),
            Error::RootfsNotDir(path) => write!(f, "rootfs {} is not a directory", path.display()),
            Error::Overlay { path, source } => {
                write!(f, "container layer {}: {source}", path.display())
            }
            Error::OverlayPath(path) => write!(
                f,
                "{} contains ',', ':' or '\\', which overlayfs mount options can't carry",
                path.display()
            ),
            Error::CgroupUnavailable(reason) => write!(f, "cgroups unavailable: {reason}"),
            Error::Cgroup { path, source } => write!(f, "cgroup {}: {source}", path.display()),
            Error::Pipe(e) => write!(f, "sync pipe: {e}"),
            Error::Signals(e) => write!(f, "signal handling: {e}"),
            Error::ParentAborted => write!(f, "parent aborted container setup"),
            Error::Netlink { op, source } if source.raw_os_error() == Some(libc::EPERM) => {
                write!(
                    f,
                    "{op}: {source} (network setup needs root; use --network none)"
                )
            }
            Error::Netlink { op, source } => write!(f, "{op}: {source}"),
            Error::Nft(reason) => write!(f, "nft: {reason}"),
            Error::NoFreeAddress => write!(f, "no free container address in 10.200.0.0/24"),
            Error::Network { path, source } => {
                write!(f, "network setup {}: {source}", path.display())
            }
            Error::LimitsNeedRoot => write!(
                f,
                "--memory, --pids and --cpus need root (cgroups can't be created rootless)"
            ),
            Error::UserNamespace { path, source } => {
                write!(f, "user namespace {}: {source}", path.display())
            }
            Error::Security { op, source } => write!(f, "{op}: {source}"),
            Error::Clone(e) => write!(f, "clone failed (are you root?): {e}"),
            Error::Wait(e) => write!(f, "waitpid failed: {e}"),
            Error::UnexpectedWaitStatus(status) => write!(f, "unexpected wait status: {status:#x}"),
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

    // Without root, capsule makes its own user namespace and maps our ids to
    // root inside it, so the other namespaces can be created unprivileged.
    let rootless = sys::geteuid() != 0;

    // From here on, everything created is cleaned up when this function
    // returns, so termination signals must not kill us. Declared first so it's
    // dropped last, after that cleanup.
    let signals = Signals::block()?;

    // Clear up after earlier capsules that died without cleaning up.
    sweep::sweep(rootless);

    // The rootfs stays read-only: the container writes to its own layer, which
    // is deleted when this function returns.
    let overlay = Overlay::create(&rootfs, rootless)?;
    if rootless && !config.limits.is_empty() {
        return Err(Error::LimitsNeedRoot);
    }
    let id_map = rootless.then(|| (sys::geteuid(), sys::getegid()));

    // Created before the child exists, so a bad host setup fails cheaply.
    let cgroup = if config.limits.is_empty() {
        None
    } else {
        Some(Cgroup::create(
            &std::process::id().to_string(),
            &config.limits,
        )?)
    };

    // Bridging needs root on the host, so rootless defaults to loopback only.
    let default_network = if rootless {
        NetworkMode::None
    } else {
        NetworkMode::Bridge
    };
    let network = match config.network.as_ref().unwrap_or(&default_network) {
        NetworkMode::Bridge => Some(Network::setup_host(&config.hostname)?),
        NetworkMode::None => None,
    };
    let setup = ChildSetup {
        config,
        overlay: &overlay,
        signal_mask: signals.original_mask(),
        argv: &argv,
        env: &env,
        addr: network.as_ref().map(|n| n.addr),
        files: network
            .as_ref()
            .map(Network::bind_mounts)
            .unwrap_or_default(),
    };

    // The child blocks reading this until the parent has finished its side of
    // the setup (moved it into the cgroup, given it a veth), so the command never runs
    // unconfined. CLOEXEC keeps both ends out of the command.
    let (ready_rx, ready_tx) = sys::pipe2(libc::O_CLOEXEC).map_err(Error::Pipe)?;

    let flags = libc::CLONE_NEWPID | libc::CLONE_NEWUTS | libc::CLONE_NEWNS | libc::CLONE_NEWNET;
    // The kernel creates the user namespace first, then the others owned by it.
    let flags = if rootless {
        flags | libc::CLONE_NEWUSER
    } else {
        flags
    };

    let mut stack = vec![0u8; STACK_SIZE];
    let mut child = || match init(&setup, &ready_rx, &ready_tx) {
        Ok(never) => match never {},
        Err(e) => {
            eprintln!("capsule (child): {e}");
            126
        }
    };

    // The child only runs `init`, which execs or returns an exit code.
    let pid = sys::clone(&mut child, &mut stack, flags).map_err(Error::Clone)?;

    drop(ready_rx);

    if let Err(e) = release_child(id_map, cgroup.as_ref(), network.as_ref(), pid, ready_tx) {
        // The write end is gone, so the child sees EOF and exits.
        let _ = sys::waitpid(pid);
        return Err(e);
    }

    let code = match signals.supervise(pid)? {
        WaitStatus::Exited(code) => code as u8,
        WaitStatus::Signaled(sig) => 128 + sig as u8,
        WaitStatus::Other(status) => return Err(Error::UnexpectedWaitStatus(status)),
    };

    if let Some(limit) = cgroup.as_ref().and_then(Cgroup::oom_killed) {
        eprintln!("capsule: OOM killer ran in the container (memory limit {limit} bytes)");
    }
    Ok(code)
}

/// Everything the child needs, prepared by the parent before `clone`.
struct ChildSetup<'a> {
    config: &'a Config,
    overlay: &'a Overlay,
    /// The signal mask from before the parent blocked its signals.
    signal_mask: sigset_t,
    argv: &'a [CString],
    env: &'a [CString],
    /// The container's address when bridged.
    addr: Option<Ipv4Addr>,
    /// Host files to bind over the rootfs's, as (host, container).
    files: Vec<(PathBuf, &'static str)>,
}

/// Finish the parent's side of the setup, then let the child go on to exec.
///
/// Takes `ready` by value: on error it's dropped unwritten, which the child
/// reads as EOF and gives up.
fn release_child(
    id_map: Option<(uid_t, gid_t)>,
    cgroup: Option<&Cgroup>,
    network: Option<&Network>,
    pid: pid_t,
    ready: OwnedFd,
) -> Result<(), Error> {
    if let Some((uid, gid)) = id_map {
        userns::write_id_maps(pid, uid, gid)?;
    }
    if let Some(cgroup) = cgroup {
        cgroup.add(pid)?;
    }
    if let Some(network) = network {
        network.attach(pid)?;
    }
    File::from(ready).write_all(&[1]).map_err(Error::Pipe)
}

/// Block until the parent releases us with a byte on `ready_rx`.
fn wait_for_parent(ready_rx: &OwnedFd, ready_tx: &OwnedFd) -> Result<(), Error> {
    // Our copy of the write end would keep the pipe open forever if the parent
    // died, so close it: then EOF reliably means the parent gave up.
    sys::close(ready_tx.as_raw_fd()).map_err(Error::Pipe)?;

    let mut byte = [0u8];
    loop {
        match sys::read(ready_rx, &mut byte) {
            Ok(1) => return Ok(()),
            Ok(_) => return Err(Error::ParentAborted),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(Error::Pipe(e)),
        }
    }
}

/// Runs inside the new namespaces as PID 1, then replaces itself with the command.
fn init(setup: &ChildSetup, ready_rx: &OwnedFd, ready_tx: &OwnedFd) -> Result<Infallible, Error> {
    let ChildSetup {
        config,
        overlay,
        signal_mask,
        argv,
        env,
        addr,
        files,
    } = setup;

    // If capsule dies, even by SIGKILL, the kernel kills the container with it,
    // rather than leaving it running unsupervised on a layer the next sweep
    // would delete. Set before waiting: if capsule died even earlier, the read
    // below sees EOF.
    sys::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL as libc::c_ulong, 0)
        .map_err(Error::Signals)?;

    // The parent's blocked signals were inherited, and would survive exec.
    sys::sigmask(libc::SIG_SETMASK, signal_mask).map_err(Error::Signals)?;

    wait_for_parent(ready_rx, ready_tx)?;

    // Stop our mount changes propagating back to the host's mount namespace.
    sys::mount(
        None,
        Path::new("/"),
        None,
        libc::MS_REC | libc::MS_PRIVATE,
        None,
    )
    .map_err(Error::MakeRootPrivate)?;

    sys::sethostname(&config.hostname).map_err(Error::SetHostname)?;

    network::configure(*addr)?;

    let root = overlay.mount()?;
    rootfs::enter(&root, files)?;

    security::harden()?;

    // execvpe searches the caller's PATH, not the one in `env`, so set ours.
    // SAFETY: the cloned child is single-threaded, so nothing reads the
    // environment concurrently.
    unsafe { std::env::set_var("PATH", CONTAINER_PATH) };

    Err(Error::Exec {
        command: argv[0].clone(),
        source: sys::execvpe(&argv[0], argv, env),
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
