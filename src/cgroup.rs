use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::thread::sleep;
use std::time::Duration;

use libc::pid_t;

use crate::cli::Limits;
use crate::container::Error;

const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// Parent of every container's cgroup. It never holds processes itself, which
/// satisfies cgroup v2's rule that only leaves may have both.
const CAPSULE_DIR: &str = "capsule";

/// cpu.max period in microseconds; the quota is a share of this.
const CPU_PERIOD_US: u64 = 100_000;

const CLEANUP_ATTEMPTS: u32 = 50;
const CLEANUP_INTERVAL: Duration = Duration::from_millis(10);

/// A container's cgroup. Dropping it kills anything left inside and removes it.
pub struct Cgroup {
    path: PathBuf,
    memory: Option<u64>,
}

/// The directory holding every container's cgroup.
pub fn capsule_dir() -> PathBuf {
    Path::new(CGROUP_ROOT).join(CAPSULE_DIR)
}

impl Cgroup {
    /// Take charge of an existing cgroup, e.g. one a dead capsule left behind,
    /// so dropping it cleans it up.
    pub fn adopt(path: PathBuf) -> Cgroup {
        Cgroup { path, memory: None }
    }

    /// Create `/sys/fs/cgroup/capsule/<name>` and apply `limits` to it.
    pub fn create(name: &str, limits: &Limits) -> Result<Cgroup, Error> {
        let controllers = needed_controllers(limits);
        let root = Path::new(CGROUP_ROOT);
        check_available(root, &controllers)?;

        // Each level must enable a controller for its children before they can use it.
        let parent = root.join(CAPSULE_DIR);
        enable_controllers(root, &controllers)?;
        create_dir(&parent)?;
        enable_controllers(&parent, &controllers)?;

        let path = parent.join(name);
        fs::create_dir(&path).map_err(|source| cgroup_error(&path, source))?;
        // From here on, Drop removes the directory if a limit fails to apply.
        let cgroup = Cgroup {
            path,
            memory: limits.memory,
        };

        if let Some(bytes) = limits.memory {
            cgroup.write("memory.max", &bytes.to_string())?;
            // Without this the container swaps instead of hitting its limit.
            if cgroup.path.join("memory.swap.max").exists() {
                cgroup.write("memory.swap.max", "0")?;
            }
        }
        if let Some(pids) = limits.pids {
            cgroup.write("pids.max", &pids.to_string())?;
        }
        if let Some(cpus) = limits.cpus {
            let quota = (cpus * CPU_PERIOD_US as f64) as u64;
            cgroup.write("cpu.max", &format!("{quota} {CPU_PERIOD_US}"))?;
        }

        Ok(cgroup)
    }

    /// Move `pid` into this cgroup. Its future children are born inside it.
    pub fn add(&self, pid: pid_t) -> Result<(), Error> {
        self.write("cgroup.procs", &pid.to_string())
    }

    /// The memory limit in bytes and whether the kernel OOM-killed anything for
    /// exceeding it.
    pub fn oom_killed(&self) -> Option<u64> {
        let limit = self.memory?;
        let events = fs::read_to_string(self.path.join("memory.events")).ok()?;
        let kills = events
            .lines()
            .find_map(|line| line.strip_prefix("oom_kill "))?
            .parse::<u64>()
            .ok()?;
        (kills > 0).then_some(limit)
    }

    fn write(&self, file: &str, value: &str) -> Result<(), Error> {
        let path = self.path.join(file);
        fs::write(&path, value).map_err(|source| cgroup_error(&path, source))
    }
}

impl Drop for Cgroup {
    fn drop(&mut self) {
        // Anything still inside (a process that escaped PID 1's death, or a
        // child we never got to exec) would keep the directory busy.
        let _ = fs::write(self.path.join("cgroup.kill"), "1");

        // Killed processes linger briefly until reaped, so rmdir can see EBUSY.
        let mut result = fs::remove_dir(&self.path);
        for _ in 1..CLEANUP_ATTEMPTS {
            match &result {
                Err(e) if e.raw_os_error() == Some(libc::EBUSY) => {
                    sleep(CLEANUP_INTERVAL);
                    result = fs::remove_dir(&self.path);
                }
                _ => break,
            }
        }
        if let Err(e) = result {
            eprintln!("capsule: removing cgroup {}: {e}", self.path.display());
        }
    }
}

fn needed_controllers(limits: &Limits) -> Vec<&'static str> {
    let mut controllers = Vec::new();
    if limits.cpus.is_some() {
        controllers.push("cpu");
    }
    if limits.memory.is_some() {
        controllers.push("memory");
    }
    if limits.pids.is_some() {
        controllers.push("pids");
    }
    controllers
}

/// Fail early, with a pointer to the fix, on hosts without usable cgroup v2.
fn check_available(root: &Path, controllers: &[&str]) -> Result<(), Error> {
    let hint = "capsule needs cgroup v2 with the cpu, memory and pids controllers. \
                On WSL, add `kernelCommandLine = cgroup_no_v1=all` under [wsl2] in \
                %UserProfile%\\.wslconfig, then run `wsl --shutdown`";

    let Ok(available) = fs::read_to_string(root.join("cgroup.controllers")) else {
        return Err(Error::CgroupUnavailable(format!(
            "{CGROUP_ROOT} is not a cgroup v2 mount. {hint}"
        )));
    };
    let available: Vec<&str> = available.split_whitespace().collect();
    let missing: Vec<&str> = controllers
        .iter()
        .copied()
        .filter(|c| !available.contains(c))
        .collect();
    if !missing.is_empty() {
        return Err(Error::CgroupUnavailable(format!(
            "controllers not available: {}. {hint}",
            missing.join(", ")
        )));
    }
    Ok(())
}

/// Let `dir`'s children use `controllers`, skipping any already enabled.
fn enable_controllers(dir: &Path, controllers: &[&str]) -> Result<(), Error> {
    let path = dir.join("cgroup.subtree_control");
    let enabled = fs::read_to_string(&path).map_err(|source| cgroup_error(&path, source))?;
    let enabled: Vec<&str> = enabled.split_whitespace().collect();

    let to_enable: Vec<String> = controllers
        .iter()
        .filter(|c| !enabled.contains(c))
        .map(|c| format!("+{c}"))
        .collect();
    if to_enable.is_empty() {
        return Ok(());
    }
    fs::write(&path, to_enable.join(" ")).map_err(|source| cgroup_error(&path, source))
}

fn create_dir(path: &Path) -> Result<(), Error> {
    match fs::create_dir(path) {
        Err(e) if e.kind() != io::ErrorKind::AlreadyExists => Err(cgroup_error(path, e)),
        _ => Ok(()),
    }
}

fn cgroup_error(path: &Path, source: io::Error) -> Error {
    Error::Cgroup {
        path: path.to_path_buf(),
        source,
    }
}
