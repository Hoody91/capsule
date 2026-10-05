use std::fs;
use std::path::PathBuf;

use libc::{gid_t, pid_t, uid_t};

use crate::container::Error;

/// Map the child's user namespace so its root is `uid`/`gid` outside. Written
/// by the parent while the child waits: an unprivileged process may write
/// exactly one mapping, of its own ids, into a namespace it created.
pub fn write_id_maps(pid: pid_t, uid: uid_t, gid: gid_t) -> Result<(), Error> {
    // Required before an unprivileged gid_map write, so a mapped process can't
    // drop supplementary groups the host used to deny it access.
    write(pid, "setgroups", "deny")?;
    write(pid, "uid_map", &format!("0 {uid} 1"))?;
    write(pid, "gid_map", &format!("0 {gid} 1"))
}

fn write(pid: pid_t, file: &str, contents: &str) -> Result<(), Error> {
    let path = PathBuf::from(format!("/proc/{pid}/{file}"));
    fs::write(&path, contents).map_err(|source| Error::UserNamespace { path, source })
}
