//! Clean up after capsules that died without doing it themselves: killed by
//! SIGKILL, crashed, or run by a version from before signal handling.
//!
//! Every capsule's state is named after its pid: the layer directory, and as
//! root also its cgroup, its network files and its address lease. Pids get
//! reused, so "is that pid running?" can't tell whether the state is still in
//! use. The layer directory's lock can: a capsule holds it for as long as it
//! runs, and the kernel releases it however the process ends. The layer is
//! created before any other state and removed after it, so any other state
//! whose pid has no locked layer is a leftover too.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use crate::cgroup::{self, Cgroup};
use crate::network;
use crate::overlay;

/// Remove whatever earlier capsules left behind. Problems are reported, not
/// returned: a failed sweep shouldn't stop a container from starting.
pub fn sweep(rootless: bool) {
    let Ok(layers) = overlay::containers_root(rootless) else {
        return;
    };
    let mut report = Report::default();
    let live = sweep_layers(&layers, &mut report);
    // Only root creates cgroups and network state.
    if !rootless {
        for (pid, path) in stale_pid_dirs(&cgroup::capsule_dir(), &live) {
            drop(Cgroup::adopt(path.clone()));
            if !path.exists() {
                report.add(pid, "cgroup");
            }
        }
        sweep_network(Path::new(network::RUN_DIR), &live, &mut report);
    }
    report.print();
}

/// Remove unlocked layer directories, returning the pids still running.
fn sweep_layers(dir: &Path, report: &mut Report) -> BTreeSet<u32> {
    let mut live = BTreeSet::new();
    for (name, path) in entries(dir) {
        let (pid, staging) = match name.strip_suffix(overlay::STAGING_SUFFIX) {
            Some(pid) => (pid, true),
            None => (name.as_str(), false),
        };
        let Ok(pid) = pid.parse::<u32>() else {
            continue;
        };
        // A layer still being staged is briefly unlocked between its mkdir
        // and its lock, so it counts as live while its pid exists.
        if overlay::in_use(&path) || (staging && process_exists(pid)) {
            live.insert(pid);
            continue;
        }
        match overlay::remove_tree(&path) {
            Ok(()) => report.add(pid, "layer"),
            Err(e) => eprintln!("capsule: removing leftover {}: {e}", path.display()),
        }
    }
    live
}

fn sweep_network(run_dir: &Path, live: &BTreeSet<u32>, report: &mut Report) {
    for (pid, path) in stale_pid_dirs(run_dir, live) {
        match fs::remove_dir_all(&path) {
            Ok(()) => report.add(pid, "network files"),
            Err(e) => eprintln!("capsule: removing leftover {}: {e}", path.display()),
        }
    }
    for (_, path) in entries(&run_dir.join("ips")) {
        // An unreadable lease is still being written by its new owner.
        let Some(pid) = network::lease_owner(&path) else {
            continue;
        };
        if live.contains(&pid) {
            continue;
        }
        match fs::remove_file(&path) {
            Ok(()) => report.add(pid, "address lease"),
            Err(e) => eprintln!("capsule: removing leftover {}: {e}", path.display()),
        }
    }
}

/// Entries of `dir` named by a pid that isn't in `live`.
fn stale_pid_dirs(dir: &Path, live: &BTreeSet<u32>) -> Vec<(u32, PathBuf)> {
    entries(dir)
        .into_iter()
        .filter_map(|(name, path)| Some((name.parse::<u32>().ok()?, path)))
        .filter(|(pid, path)| !live.contains(pid) && path.is_dir())
        .collect()
}

/// (name, path) of each entry in `dir`; nothing if it doesn't exist yet.
fn entries(dir: &Path) -> Vec<(String, PathBuf)> {
    let Ok(read) = fs::read_dir(dir) else {
        return Vec::new();
    };
    read.filter_map(|entry| {
        let entry = entry.ok()?;
        Some((entry.file_name().into_string().ok()?, entry.path()))
    })
    .collect()
}

fn process_exists(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

/// What was removed, by the pid of the capsule that left it.
#[derive(Default)]
struct Report(BTreeMap<u32, Vec<&'static str>>);

impl Report {
    fn add(&mut self, pid: u32, what: &'static str) {
        self.0.entry(pid).or_default().push(what);
    }

    fn print(&self) {
        for (pid, removed) in &self.0 {
            eprintln!(
                "capsule: cleaned up after capsule process {pid}, which exited without doing so ({})",
                removed.join(", ")
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;

    /// A pid no process can have (above the kernel's pid_max limit).
    const DEAD: u32 = 4_194_305;

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("capsule-test-sweep-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn layers_are_kept_while_locked_and_removed_once_free() {
        let dir = scratch("layers");
        let me = std::process::id();
        for name in [
            "101",
            "202",
            &format!("{DEAD}.new"),
            &format!("{me}.new"),
            "notes",
        ] {
            fs::create_dir_all(dir.join(name).join("upper")).unwrap();
        }
        let lock = File::open(dir.join("101")).unwrap();
        lock.try_lock().unwrap();

        let mut report = Report::default();
        let live = sweep_layers(&dir, &mut report);

        assert_eq!(live, BTreeSet::from([101, me]));
        assert!(dir.join("101").exists(), "locked layer kept");
        assert!(!dir.join("202").exists(), "unlocked layer removed");
        assert!(
            !dir.join(format!("{DEAD}.new")).exists(),
            "dead staging removed"
        );
        assert!(dir.join(format!("{me}.new")).exists(), "live staging kept");
        assert!(dir.join("notes").exists(), "non-pid entries ignored");
        assert_eq!(report.0.keys().copied().collect::<Vec<_>>(), [202, DEAD]);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn network_state_follows_live_layers() {
        let run = scratch("network");
        fs::create_dir_all(run.join("ips")).unwrap();
        for pid in [101, 202] {
            fs::create_dir(run.join(pid.to_string())).unwrap();
        }
        fs::write(run.join("ips/10.200.0.2"), "101").unwrap();
        fs::write(run.join("ips/10.200.0.3"), "202").unwrap();
        fs::write(run.join("ips/10.200.0.4"), "").unwrap();

        let mut report = Report::default();
        sweep_network(&run, &BTreeSet::from([101]), &mut report);

        assert!(run.join("101").exists());
        assert!(!run.join("202").exists());
        assert!(run.join("ips/10.200.0.2").exists());
        assert!(!run.join("ips/10.200.0.3").exists());
        assert!(
            run.join("ips/10.200.0.4").exists(),
            "lease still being written"
        );
        assert_eq!(report.0[&202], ["network files", "address lease"]);
        fs::remove_dir_all(&run).unwrap();
    }

    #[test]
    fn missing_directories_are_fine() {
        let gone = Path::new("/nonexistent/capsule");
        assert!(stale_pid_dirs(gone, &BTreeSet::new()).is_empty());
        let mut report = Report::default();
        assert!(sweep_layers(gone, &mut report).is_empty());
        assert!(report.0.is_empty());
    }
}
