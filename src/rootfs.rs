use std::fs::{self, File};
use std::os::unix::fs::symlink;
use std::path::Path;

use nix::NixPath;
use nix::mount::{MntFlags, MsFlags, mount, umount2};
use nix::unistd::{chdir, pivot_root};

use crate::container::Error;

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
pub fn enter(rootfs: &Path) -> Result<(), Error> {
    // pivot_root needs the new root to be a mount point.
    mount_at(
        Some(rootfs),
        rootfs,
        None,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None,
    )?;

    // A fresh procfs reflects our PID namespace, so `ps` only sees this container.
    mount_at(
        Some("proc"),
        &rootfs.join("proc"),
        Some("proc"),
        MsFlags::empty(),
        None,
    )?;

    mount_at(
        Some("sysfs"),
        &rootfs.join("sys"),
        Some("sysfs"),
        MsFlags::MS_RDONLY | MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        None,
    )?;

    setup_dev(&rootfs.join("dev"))?;

    pivot(rootfs)
}

/// Build a minimal `/dev` on a tmpfs instead of exposing the host's.
fn setup_dev(dev: &Path) -> Result<(), Error> {
    // No MS_NODEV: the bind-mounted device nodes below must stay usable.
    mount_at(
        Some("tmpfs"),
        dev,
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_STRICTATIME,
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
            Some(&Path::new("/dev").join(name)),
            &target,
            None,
            MsFlags::MS_BIND,
            None,
        )?;
    }

    let pts = dev.join("pts");
    create_dir(&pts)?;
    mount_at(
        Some("devpts"),
        &pts,
        Some("devpts"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        Some("newinstance,ptmxmode=0666,mode=0620"),
    )?;

    let shm = dev.join("shm");
    create_dir(&shm)?;
    mount_at(
        Some("shm"),
        &shm,
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        Some("mode=1777,size=65536k"),
    )?;

    for (name, target) in DEV_SYMLINKS {
        let path = dev.join(name);
        symlink(target, &path).map_err(|source| Error::Prepare { path, source })?;
    }

    Ok(())
}

/// Swap `/` for `rootfs` and detach the old root so the host is unreachable.
fn pivot(rootfs: &Path) -> Result<(), Error> {
    chdir(rootfs).map_err(|source| Error::Chdir {
        path: rootfs.to_path_buf(),
        source,
    })?;

    // pivot_root(".", ".") stacks the old root on top of the new one at `/`,
    // so no put_old directory is needed; unmounting `.` then removes it.
    pivot_root(".", ".").map_err(Error::PivotRoot)?;
    umount2(".", MntFlags::MNT_DETACH).map_err(Error::UnmountOldRoot)?;

    chdir("/").map_err(|source| Error::Chdir {
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

fn mount_at<S: ?Sized + NixPath>(
    source: Option<&S>,
    target: &Path,
    fstype: Option<&str>,
    flags: MsFlags,
    data: Option<&str>,
) -> Result<(), Error> {
    mount(source, target, fstype, flags, data).map_err(|source| Error::Mount {
        target: target.to_path_buf(),
        source,
    })
}
