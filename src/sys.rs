//! Thin safe wrappers over the raw libc syscalls capsule makes. Each one only
//! converts arguments (paths to C strings, slices to pointers) and turns a
//! failure return into `io::Error::last_os_error()`; the semantics are the
//! syscall's own, as documented in its man page.

use std::ffi::{CStr, CString, c_void};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::ptr;

use libc::{c_char, c_int, c_long, c_ulong, gid_t, pid_t, sigset_t, uid_t};

/// How a waited-for child ended.
#[derive(Debug, PartialEq)]
pub enum WaitStatus {
    Exited(i32),
    Signaled(i32),
    /// Stopped or continued: only reported with flags capsule doesn't pass.
    Other(c_int),
}

/// Turn libc's "-1 and errno" convention into an `io::Result`.
pub fn cvt(ret: c_int) -> io::Result<c_int> {
    if ret == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

/// `cvt` for calls returning `long`, like `syscall(2)`.
pub fn cvt_long(ret: c_long) -> io::Result<c_long> {
    if ret == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

/// `cvt` for calls returning `ssize_t`, like `send(2)`.
fn cvt_size(ret: isize) -> io::Result<usize> {
    if ret == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret as usize)
    }
}

pub fn cstring(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
}

fn cstr(s: &str) -> io::Result<CString> {
    CString::new(s).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
}

/// A nullable C string pointer for an optional argument.
fn opt_ptr(s: &Option<CString>) -> *const c_char {
    s.as_ref().map_or(ptr::null(), |s| s.as_ptr())
}

/// `mount(2)`
pub fn mount(
    source: Option<&Path>,
    target: &Path,
    fstype: Option<&str>,
    flags: c_ulong,
    data: Option<&str>,
) -> io::Result<()> {
    let source = source.map(cstring).transpose()?;
    let target = cstring(target)?;
    let fstype = fstype.map(cstr).transpose()?;
    let data = data.map(cstr).transpose()?;
    // SAFETY: every pointer is either null or a NUL-terminated string that
    // outlives the call.
    cvt(unsafe {
        libc::mount(
            opt_ptr(&source),
            target.as_ptr(),
            opt_ptr(&fstype),
            flags,
            opt_ptr(&data).cast::<c_void>(),
        )
    })?;
    Ok(())
}

/// `umount2(2)`
pub fn umount2(target: &Path, flags: c_int) -> io::Result<()> {
    let target = cstring(target)?;
    // SAFETY: `target` is a NUL-terminated string that outlives the call.
    cvt(unsafe { libc::umount2(target.as_ptr(), flags) })?;
    Ok(())
}

/// `pivot_root(2)`. glibc has no wrapper, so this is the raw syscall.
pub fn pivot_root(new_root: &Path, put_old: &Path) -> io::Result<()> {
    let new_root = cstring(new_root)?;
    let put_old = cstring(put_old)?;
    // SAFETY: both pointers are NUL-terminated strings that outlive the call.
    cvt_long(unsafe { libc::syscall(libc::SYS_pivot_root, new_root.as_ptr(), put_old.as_ptr()) })?;
    Ok(())
}

/// `chdir(2)`
pub fn chdir(path: &Path) -> io::Result<()> {
    let path = cstring(path)?;
    // SAFETY: `path` is a NUL-terminated string that outlives the call.
    cvt(unsafe { libc::chdir(path.as_ptr()) })?;
    Ok(())
}

/// `sethostname(2)`. Takes a length, so no NUL terminator is needed.
pub fn sethostname(name: &str) -> io::Result<()> {
    // SAFETY: the pointer and length describe `name`'s bytes.
    cvt(unsafe { libc::sethostname(name.as_ptr().cast::<c_char>(), name.len()) })?;
    Ok(())
}

/// `geteuid(2)`, which cannot fail.
pub fn geteuid() -> uid_t {
    // SAFETY: no arguments, no failure mode.
    unsafe { libc::geteuid() }
}

/// `getegid(2)`, which cannot fail.
pub fn getegid() -> gid_t {
    // SAFETY: no arguments, no failure mode.
    unsafe { libc::getegid() }
}

/// `if_nametoindex(3)`: 0 means no such interface, with errno set.
pub fn if_nametoindex(name: &str) -> io::Result<u32> {
    let name = cstr(name)?;
    // SAFETY: `name` is a NUL-terminated string that outlives the call.
    match unsafe { libc::if_nametoindex(name.as_ptr()) } {
        0 => Err(io::Error::last_os_error()),
        index => Ok(index),
    }
}

/// `pipe2(2)`, as (read end, write end).
pub fn pipe2(flags: c_int) -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as c_int; 2];
    // SAFETY: `fds` has room for the two descriptors pipe2 writes.
    cvt(unsafe { libc::pipe2(fds.as_mut_ptr(), flags) })?;
    // SAFETY: both descriptors were just created and nothing else owns them.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// `read(2)`
pub fn read(fd: &OwnedFd, buf: &mut [u8]) -> io::Result<usize> {
    // SAFETY: the pointer and length describe `buf`, which is valid for writes.
    cvt_size(unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast::<c_void>(), buf.len()) })
}

/// `close(2)` on a descriptor this process doesn't hold as an `OwnedFd`
/// (e.g. a cloned child's copy of one of the parent's).
pub fn close(fd: RawFd) -> io::Result<()> {
    // SAFETY: closing an fd only affects this process's descriptor table.
    cvt(unsafe { libc::close(fd) })?;
    Ok(())
}

/// `execvpe(3)`. Only returns if the exec failed.
pub fn execvpe(file: &CStr, argv: &[CString], env: &[CString]) -> io::Error {
    let null_terminated = |strings: &[CString]| {
        strings
            .iter()
            .map(|s| s.as_ptr())
            .chain([ptr::null()])
            .collect::<Vec<*const c_char>>()
    };
    let argv = null_terminated(argv);
    let env = null_terminated(env);
    // SAFETY: `file` is NUL-terminated, and argv/env are NULL-terminated arrays
    // of NUL-terminated strings, all outliving the call.
    unsafe { libc::execvpe(file.as_ptr(), argv.as_ptr(), env.as_ptr()) };
    io::Error::last_os_error()
}

/// `waitpid(2)` for one child, retrying if a signal interrupts the wait.
pub fn waitpid(pid: pid_t) -> io::Result<WaitStatus> {
    loop {
        if let Some(status) = wait(pid, 0)? {
            return Ok(status);
        }
    }
}

/// `waitpid(2)` with `WNOHANG`: `None` while the child is still running.
pub fn try_waitpid(pid: pid_t) -> io::Result<Option<WaitStatus>> {
    wait(pid, libc::WNOHANG)
}

fn wait(pid: pid_t, flags: c_int) -> io::Result<Option<WaitStatus>> {
    let mut status: c_int = 0;
    let reaped = loop {
        // SAFETY: `status` is valid for the kernel to write.
        match cvt(unsafe { libc::waitpid(pid, &mut status, flags) }) {
            Ok(reaped) => break reaped,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    };
    if reaped == 0 {
        return Ok(None);
    }
    Ok(Some(if libc::WIFEXITED(status) {
        WaitStatus::Exited(libc::WEXITSTATUS(status))
    } else if libc::WIFSIGNALED(status) {
        WaitStatus::Signaled(libc::WTERMSIG(status))
    } else {
        WaitStatus::Other(status)
    }))
}

/// A signal set holding exactly `signals`.
pub fn sigset(signals: &[c_int]) -> sigset_t {
    // SAFETY: sigemptyset initialises the whole set before sigaddset uses it;
    // both only fail for invalid signal numbers, which callers don't pass.
    unsafe {
        let mut set: sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        for &signal in signals {
            libc::sigaddset(&mut set, signal);
        }
        set
    }
}

/// `pthread_sigmask(3)`, returning the previous mask. `how` is `SIG_BLOCK`,
/// `SIG_UNBLOCK` or `SIG_SETMASK`.
pub fn sigmask(how: c_int, set: &sigset_t) -> io::Result<sigset_t> {
    // SAFETY: zeroed is a valid sigset_t for the old mask to be written into.
    let mut old: sigset_t = unsafe { std::mem::zeroed() };
    // SAFETY: both pointers are valid for the call. pthread_sigmask returns
    // the error number itself rather than setting errno.
    match unsafe { libc::pthread_sigmask(how, set, &mut old) } {
        0 => Ok(old),
        errno => Err(io::Error::from_raw_os_error(errno)),
    }
}

/// `signalfd(2)`: a descriptor that reads, instead of delivers, the signals
/// in `set`. They must also be blocked, or they're delivered as usual.
pub fn signalfd(set: &sigset_t) -> io::Result<OwnedFd> {
    // SAFETY: `set` is valid for the call; -1 asks for a new descriptor.
    let fd = cvt(unsafe { libc::signalfd(-1, set, libc::SFD_CLOEXEC) })?;
    // SAFETY: `fd` was just created and nothing else owns it.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Read the next signal from a `signalfd`, blocking until one is pending.
pub fn read_signal(fd: &OwnedFd) -> io::Result<libc::signalfd_siginfo> {
    // SAFETY: signalfd_siginfo is plain integers, for which all-zero is valid.
    let mut info: libc::signalfd_siginfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::signalfd_siginfo>();
    loop {
        // SAFETY: `info` is valid for writes of `size` bytes.
        let ret = unsafe {
            libc::read(
                fd.as_raw_fd(),
                (&mut info as *mut libc::signalfd_siginfo).cast::<c_void>(),
                size,
            )
        };
        match cvt_size(ret) {
            // signalfd only ever returns whole records.
            Ok(n) if n == size => return Ok(info),
            Ok(_) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
}

/// `kill(2)`
pub fn kill(pid: pid_t, signal: c_int) -> io::Result<()> {
    // SAFETY: plain kill(2) call, no pointers.
    cvt(unsafe { libc::kill(pid, signal) })?;
    Ok(())
}

/// `clone(2)` running `cb` in the child on `stack`. The child exits with
/// `cb`'s return value; the parent gets the child's pid. SIGCHLD is always
/// added to `flags` so the parent can reap the child with `waitpid`.
///
/// Without CLONE_VM the child gets a copy of the parent's memory, so `cb` and
/// everything it borrows are valid in the child too.
pub fn clone(cb: &mut dyn FnMut() -> c_int, stack: &mut [u8], flags: c_int) -> io::Result<pid_t> {
    extern "C" fn trampoline(arg: *mut c_void) -> c_int {
        // SAFETY: `arg` is the `&mut &mut dyn FnMut` passed below, valid in the
        // child's copy of the parent's memory.
        let cb = unsafe { &mut *arg.cast::<&mut dyn FnMut() -> c_int>() };
        cb()
    }

    // The stack grows down, so the child starts at the top, which the ABI
    // wants 16-byte aligned.
    let top = stack.as_mut_ptr_range().end as usize & !0xf;
    let mut cb = cb;
    // SAFETY: `top` is inside `stack`, which outlives the child's use of it
    // (the child has its own copy of the memory); `arg` points at `cb`, which
    // lives until clone returns.
    cvt(unsafe {
        libc::clone(
            trampoline,
            top as *mut c_void,
            flags | libc::SIGCHLD,
            (&mut cb as *mut &mut dyn FnMut() -> c_int).cast::<c_void>(),
        )
    })
}

/// `socket(2)`
pub fn socket(domain: c_int, ty: c_int, protocol: c_int) -> io::Result<OwnedFd> {
    // SAFETY: plain socket(2) call; the result is checked before use.
    let fd = cvt(unsafe { libc::socket(domain, ty, protocol) })?;
    // SAFETY: `fd` was just created and nothing else owns it.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// `send(2)`
pub fn send(fd: &OwnedFd, buf: &[u8]) -> io::Result<usize> {
    // SAFETY: the pointer and length describe `buf`.
    cvt_size(unsafe { libc::send(fd.as_raw_fd(), buf.as_ptr().cast::<c_void>(), buf.len(), 0) })
}

/// `recv(2)`
pub fn recv(fd: &OwnedFd, buf: &mut [u8]) -> io::Result<usize> {
    // SAFETY: the pointer and length describe `buf`, which is valid for writes.
    cvt_size(unsafe {
        libc::recv(
            fd.as_raw_fd(),
            buf.as_mut_ptr().cast::<c_void>(),
            buf.len(),
            0,
        )
    })
}

/// `prctl(2)` for options whose arguments are all integers.
pub fn prctl(option: c_int, arg2: c_ulong, arg3: c_ulong) -> io::Result<()> {
    // SAFETY: the options passed here take no pointers.
    cvt(unsafe { libc::prctl(option, arg2, arg3, 0 as c_ulong, 0 as c_ulong) })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::{Read, Write};
    use std::process::Command;

    #[test]
    fn signalfd_reads_blocked_signals() {
        // Test threads share the process, so use a thread-directed signal
        // (raise uses tgkill) on this thread only.
        let set = sigset(&[libc::SIGUSR1]);
        let old = sigmask(libc::SIG_BLOCK, &set).unwrap();
        let fd = signalfd(&set).unwrap();
        // SAFETY: raising a signal this thread has blocked just leaves it pending.
        assert_eq!(unsafe { libc::raise(libc::SIGUSR1) }, 0);
        let info = read_signal(&fd).unwrap();
        sigmask(libc::SIG_SETMASK, &old).unwrap();
        assert_eq!(info.ssi_signo as c_int, libc::SIGUSR1);
        assert_eq!(info.ssi_code, libc::SI_TKILL);
    }

    #[test]
    fn try_waitpid_sees_running_then_exited() {
        let mut child = Command::new("sleep").arg("10").spawn().unwrap();
        let pid = child.id() as pid_t;
        assert_eq!(try_waitpid(pid).unwrap(), None);
        kill(pid, libc::SIGTERM).unwrap();
        assert_eq!(waitpid(pid).unwrap(), WaitStatus::Signaled(libc::SIGTERM));
        // Already reaped by us; std's own wait would now fail, so check that.
        assert!(child.try_wait().is_err());
    }

    #[test]
    fn cstring_rejects_interior_nul() {
        let err = cstring(Path::new("a\0b")).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn pipe2_ends_are_connected_and_cloexec() {
        let (rx, tx) = pipe2(libc::O_CLOEXEC).unwrap();
        for fd in [&rx, &tx] {
            // SAFETY: F_GETFD on a descriptor we own.
            let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
            assert_ne!(flags & libc::FD_CLOEXEC, 0);
        }
        File::from(tx).write_all(b"x").unwrap();
        let mut byte = [0u8];
        File::from(rx).read_exact(&mut byte).unwrap();
        assert_eq!(&byte, b"x");
    }

    #[test]
    fn if_nametoindex_finds_loopback() {
        assert!(if_nametoindex("lo").unwrap() > 0);
        assert!(if_nametoindex("no-such-if0").is_err());
    }

    #[test]
    // The children are reaped by the waitpid under test, not Child::wait.
    #[allow(clippy::zombie_processes)]
    fn waitpid_decodes_exit_and_signal() {
        let exited = Command::new("sh").args(["-c", "exit 3"]).spawn().unwrap();
        assert_eq!(
            waitpid(exited.id() as pid_t).unwrap(),
            WaitStatus::Exited(3)
        );

        let killed = Command::new("sh")
            .args(["-c", "kill -KILL $$"])
            .spawn()
            .unwrap();
        assert_eq!(
            waitpid(killed.id() as pid_t).unwrap(),
            WaitStatus::Signaled(libc::SIGKILL)
        );
    }
}
