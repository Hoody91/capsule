//! A copy-on-write layer over the rootfs, so containers never modify it.
//!
//! The rootfs is overlayfs's read-only lower layer. Everything a container
//! writes lands in its own upper layer, and deletions are recorded there as
//! whiteouts. The whole upper layer is thrown away when the container exits.

use std::ffi::OsString;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use crate::container::Error;
use crate::sys;

/// Where root keeps container layers.
const ROOT_CONTAINERS_DIR: &str = "/var/lib/capsule/containers";

/// One container's layers: `upper` (its writes), `work` (overlayfs scratch
/// space, on the same filesystem as `upper`) and `merged` (the mount point).
///
/// They live on disk rather than on a tmpfs: on kernels before 6.6, tmpfs
/// can't hold the `user.*` xattrs a rootless overlay records whiteouts and
/// opaque directories in.
pub struct Overlay {
    lower: PathBuf,
    dir: PathBuf,
}

impl Overlay {
    /// Create this container's empty layer directories. Runs in the parent;
    /// dropping the `Overlay` deletes them again.
    pub fn create(lower: &Path, rootless: bool) -> Result<Overlay, Error> {
        let containers = containers_dir(
            rootless,
            std::env::var_os("XDG_DATA_HOME"),
            std::env::var_os("HOME"),
        )?;
        let dir = containers.join(std::process::id().to_string());
        check_option_safe(lower)?;
        check_option_safe(&dir)?;

        // A crashed run that had our pid would have left its writes here.
        if dir.exists() {
            remove_tree(&dir).map_err(overlay_error(&dir))?;
        }
        let overlay = Overlay {
            lower: lower.to_path_buf(),
            dir,
        };
        for layer in ["upper", "work", "merged"] {
            let path = overlay.dir.join(layer);
            fs::create_dir_all(&path).map_err(overlay_error(&path))?;
        }
        Ok(overlay)
    }

    /// Mount the overlay and return the merged view, to use as the rootfs.
    /// Runs in the child, in its private mount namespace, so the host only
    /// ever sees an empty `merged` directory.
    pub fn mount(&self) -> Result<PathBuf, Error> {
        let merged = self.dir.join("merged");
        // userxattr: keep overlay metadata in user.* xattrs, which a user
        // namespace may set, rather than trusted.*, which it may not.
        let options = format!(
            "lowerdir={},upperdir={},workdir={},userxattr",
            self.lower.display(),
            self.dir.join("upper").display(),
            self.dir.join("work").display(),
        );
        sys::mount(
            Some(Path::new("overlay")),
            &merged,
            Some("overlay"),
            0,
            Some(&options),
        )
        .map_err(|source| Error::Mount {
            target: merged.clone(),
            source,
        })?;
        Ok(merged)
    }
}

impl Drop for Overlay {
    fn drop(&mut self) {
        if let Err(e) = remove_tree(&self.dir) {
            eprintln!(
                "capsule: removing container layer {}: {e}",
                self.dir.display()
            );
        }
    }
}

/// Root uses /var/lib; a rootless user their XDG data directory, which must
/// be somewhere they can write.
fn containers_dir(
    rootless: bool,
    xdg_data_home: Option<OsString>,
    home: Option<OsString>,
) -> Result<PathBuf, Error> {
    if !rootless {
        return Ok(PathBuf::from(ROOT_CONTAINERS_DIR));
    }
    // The XDG spec says to ignore a relative XDG_DATA_HOME.
    if let Some(xdg) = xdg_data_home.map(PathBuf::from).filter(|p| p.is_absolute()) {
        return Ok(xdg.join("capsule/containers"));
    }
    match home.map(PathBuf::from).filter(|p| p.is_absolute()) {
        Some(home) => Ok(home.join(".local/share/capsule/containers")),
        None => Err(Error::Overlay {
            path: PathBuf::from("$HOME"),
            source: io::Error::new(io::ErrorKind::NotFound, "HOME is not set"),
        }),
    }
}

/// Overlay's mount options are comma-separated, and `lowerdir` splits on
/// colons, so paths containing either (or the backslash that would escape
/// them) can't be passed safely.
fn check_option_safe(path: &Path) -> Result<(), Error> {
    let bytes = path.as_os_str().as_encoded_bytes();
    if bytes.iter().any(|b| matches!(b, b',' | b':' | b'\\')) {
        return Err(Error::OverlayPath(path.to_path_buf()));
    }
    Ok(())
}

/// Delete a layer directory. overlayfs leaves `work/work` with mode 000, and a
/// container may have chmod'ed its own directories, so make every directory
/// accessible first. Symlinks are never followed.
fn remove_tree(dir: &Path) -> io::Result<()> {
    fn make_accessible(path: &Path) -> io::Result<()> {
        if !fs::symlink_metadata(path)?.is_dir() {
            return Ok(());
        }
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        for entry in fs::read_dir(path)? {
            make_accessible(&entry?.path())?;
        }
        Ok(())
    }

    match make_accessible(dir) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        other => other?,
    }
    fs::remove_dir_all(dir)
}

fn overlay_error(path: &Path) -> impl Fn(io::Error) -> Error {
    let path = path.to_path_buf();
    move |source| Error::Overlay {
        path: path.clone(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_uses_var_lib() {
        let dir = containers_dir(false, Some("/xdg".into()), Some("/home/u".into())).unwrap();
        assert_eq!(dir, Path::new("/var/lib/capsule/containers"));
    }

    #[test]
    fn rootless_prefers_xdg_data_home() {
        let dir = containers_dir(true, Some("/xdg".into()), Some("/home/u".into())).unwrap();
        assert_eq!(dir, Path::new("/xdg/capsule/containers"));
    }

    #[test]
    fn rootless_falls_back_to_home() {
        for xdg in [None, Some("".into()), Some("relative".into())] {
            let dir = containers_dir(true, xdg, Some("/home/u".into())).unwrap();
            assert_eq!(dir, Path::new("/home/u/.local/share/capsule/containers"));
        }
        assert!(containers_dir(true, None, None).is_err());
    }

    #[test]
    fn option_breaking_paths_are_rejected() {
        assert!(check_option_safe(Path::new("/srv/images/alpine")).is_ok());
        for bad in ["/a,b", "/a:b", "/a\\b"] {
            assert!(check_option_safe(Path::new(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn remove_tree_handles_inaccessible_dirs() {
        let dir = std::env::temp_dir().join(format!("capsule-test-tree-{}", std::process::id()));
        let locked = dir.join("work/work");
        fs::create_dir_all(locked.join("inner")).unwrap();
        fs::write(locked.join("inner/file"), "x").unwrap();
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();

        remove_tree(&dir).unwrap();
        assert!(!dir.exists());
        // Removing what's already gone is fine.
        remove_tree(&dir).unwrap();
    }
}
