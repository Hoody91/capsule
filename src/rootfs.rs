use std::fs::{self, File};
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use libc::c_ulong;

use crate::container::Error;
use crate::sys;

/// Host device nodes bind-mounted into the container's `/dev`.
const DEVICES: &[&str] = &["null", "zero", "full", "random", "urandom", "tty"];

/// Symlinks created in the container's `/dev`, as (name, target).
const DEV_SYMLINKS: &[(&str, &str)] = &[
    ("ptmx", "pts/ptmx"),
    ("fd", "/proc/self/fd"),
    ("stdin", "/proc/self/fd/0"),
    ("stdout", "/proc/self/fd/1"),
    ("stderr", "/proc/self/fd/2"),
];

/// Mount the container's filesystems under `rootfs`, then make it `/`.
///
/// Must run inside a private mount namespace. Everything is mounted before the
/// pivot, while the host's `/dev` is still reachable for the device binds.
pub fn enter(rootfs: &Path, files: &[(PathBuf, &str)]) -> Result<(), Error> {
    // pivot_root needs the new root to be a mount point.
    mount_at(
        Some(rootfs),
        rootfs,
        None,
        libc::MS_BIND | libc::MS_REC,
        None,
    )?;

    // A fresh procfs reflects our PID namespace, so `ps` only sees this container.
    mount_at(
        Some(Path::new("proc")),
        &rootfs.join("proc"),
        Some("proc"),
        0,
        None,
    )?;

    mount_at(
        Some(Path::new("sysfs")),
        &rootfs.join("sys"),
        Some("sysfs"),
        libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        None,
    )?;

    setup_dev(&rootfs.join("dev"))?;
    bind_files(rootfs, files)?;

    pivot(rootfs)
}

/// Build a minimal `/dev` on a tmpfs instead of exposing the host's.
fn setup_dev(dev: &Path) -> Result<(), Error> {
    // No MS_NODEV: the bind-mounted device nodes below must stay usable.
    mount_at(
        Some(Path::new("tmpfs")),
        dev,
        Some("tmpfs"),
        libc::MS_NOSUID | libc::MS_STRICTATIME,
        Some("mode=755,size=65536k"),
    )?;

    // Bind the host's nodes rather than mknod them, which also works rootless.
    for name in DEVICES {
        let target = dev.join(name);
        File::create(&target).map_err(|source| Error::Prepare {
            path: target.clone(),
            source,
        })?;
        mount_at(
            Some(Path::new("/dev").join(name).as_path()),
            &target,
            None,
            libc::MS_BIND,
            None,
        )?;
    }

    let pts = dev.join("pts");
    create_dir(&pts)?;
    mount_at(
        Some(Path::new("devpts")),
        &pts,
        Some("devpts"),
        libc::MS_NOSUID | libc::MS_NOEXEC,
        Some("newinstance,ptmxmode=0666,mode=0620"),
    )?;

    let shm = dev.join("shm");
    create_dir(&shm)?;
    mount_at(
        Some(Path::new("shm")),
        &shm,
        Some("tmpfs"),
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        Some("mode=1777,size=65536k"),
    )?;

    for (name, target) in DEV_SYMLINKS {
        let path = dev.join(name);
        symlink(target, &path).map_err(|source| Error::Prepare { path, source })?;
    }

    Ok(())
}

/// Bind each host file read-only over its path in the rootfs, e.g. a generated
/// resolv.conf over `/etc/resolv.conf`.
fn bind_files(rootfs: &Path, files: &[(PathBuf, &str)]) -> Result<(), Error> {
    for (source, dest) in files {
        let target = rootfs.join(dest.trim_start_matches('/'));
        // A bind mount needs something to mount over.
        if !target.exists() {
            File::create(&target).map_err(|source| Error::Prepare {
                path: target.clone(),
                source,
            })?;
        }
        mount_at(Some(source.as_path()), &target, None, libc::MS_BIND, None)?;
        // MS_RDONLY is ignored on the initial bind; it takes a remount.
        mount_at(
            None,
            &target,
            None,
            libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY,
            None,
        )?;
    }
    Ok(())
}

/// Swap `/` for `rootfs` and detach the old root so the host is unreachable.
fn pivot(rootfs: &Path) -> Result<(), Error> {
    sys::chdir(rootfs).map_err(|source| Error::Chdir {
        path: rootfs.to_path_buf(),
        source,
    })?;

    // pivot_root(".", ".") stacks the old root on top of the new one at `/`,
    // so no put_old directory is needed; unmounting `.` then removes it.
    let here = Path::new(".");
    sys::pivot_root(here, here).map_err(Error::PivotRoot)?;
    sys::umount2(here, libc::MNT_DETACH).map_err(Error::UnmountOldRoot)?;

    sys::chdir(Path::new("/")).map_err(|source| Error::Chdir {
        path: "/".into(),
        source,
    })
}

fn create_dir(path: &Path) -> Result<(), Error> {
    fs::create_dir_all(path).map_err(|source| Error::Prepare {
        path: path.to_path_buf(),
        source,
    })
}

fn mount_at(
    source: Option<&Path>,
    target: &Path,
    fstype: Option<&str>,
    flags: c_ulong,
    data: Option<&str>,
) -> Result<(), Error> {
    sys::mount(source, target, fstype, flags, data).map_err(|source| Error::Mount {
        target: target.to_path_buf(),
        source,
    })
}
