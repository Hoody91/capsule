use std::fmt;
use std::path::PathBuf;

pub const USAGE: &str = "usage: capsule run --rootfs DIR [--hostname NAME] [--memory SIZE] [--pids N] [--cpus N] [--network bridge|none] <command> [args...]";

const PROC_HOSTNAME: &str = "capsule";

/// The kernel rejects a cpu.max quota under 1ms of each 100ms period.
const MIN_CPUS: f64 = 0.01;

#[derive(Debug, PartialEq)]
pub enum CliError {
    MissingSubcommand,
    UnknownSubcommand(String),
    MissingValue(&'static str),
    InvalidValue { flag: &'static str, value: String },
    MissingRootfs,
    MissingCommand,
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CliError::MissingSubcommand => write!(f, "missing subcommand"),
            CliError::UnknownSubcommand(name) => write!(f, "unknown subcommand '{name}'"),
            CliError::MissingValue(flag) => write!(f, "{flag} needs a value"),
            CliError::InvalidValue { flag, value } => {
                write!(f, "invalid value '{value}' for {flag}")
            }
            CliError::MissingRootfs => write!(f, "missing --rootfs"),
            CliError::MissingCommand => write!(f, "missing command to run"),
        }
    }
}

impl std::error::Error for CliError {}

/// Resource limits applied through a cgroup. `None` means unlimited.
#[derive(Debug, Default, PartialEq)]
pub struct Limits {
    /// Bytes.
    pub memory: Option<u64>,
    pub pids: Option<u64>,
    /// Fraction of one CPU, e.g. 0.5.
    pub cpus: Option<f64>,
}

impl Limits {
    pub fn is_empty(&self) -> bool {
        *self == Limits::default()
    }
}

/// How the container's network namespace is connected.
#[derive(Debug, PartialEq)]
pub enum NetworkMode {
    /// A veth pair onto the host's capsule0 bridge, with outbound NAT.
    Bridge,
    /// Loopback only. Needs no host privileges.
    None,
}

#[derive(Debug)]
pub struct Config {
    pub hostname: String,
    pub rootfs: PathBuf,
    pub limits: Limits,
    /// `None` when not given: the default depends on whether we run as root.
    pub network: Option<NetworkMode>,
    pub command: String,
    pub args: Vec<String>,
}

impl Config {
    pub fn new(mut args: impl Iterator<Item = String>) -> Result<Config, CliError> {
        match args.next().as_deref() {
            Some("run") => {}
            Some(other) => return Err(CliError::UnknownSubcommand(other.to_string())),
            None => return Err(CliError::MissingSubcommand),
        }

        let mut hostname = String::from(PROC_HOSTNAME);
        let mut rootfs = None;
        let mut limits = Limits::default();
        let mut network = None;
        let mut rest = Vec::new();

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--hostname" if rest.is_empty() => hostname = value(&mut args, "--hostname")?,
                "--rootfs" if rest.is_empty() => {
                    rootfs = Some(PathBuf::from(value(&mut args, "--rootfs")?))
                }
                "--memory" if rest.is_empty() => {
                    limits.memory = Some(parse_flag(&mut args, "--memory", parse_size)?)
                }
                "--pids" if rest.is_empty() => {
                    limits.pids = Some(parse_flag(&mut args, "--pids", parse_count)?)
                }
                "--cpus" if rest.is_empty() => {
                    limits.cpus = Some(parse_flag(&mut args, "--cpus", parse_cpus)?)
                }
                "--network" if rest.is_empty() => {
                    network = Some(parse_flag(&mut args, "--network", parse_network)?)
                }
                _ => {
                    rest.push(arg);
                    rest.extend(args.by_ref());
                }
            }
        }

        let mut rest = rest.into_iter();
        let Some(command) = rest.next() else {
            return Err(CliError::MissingCommand);
        };
        let Some(rootfs) = rootfs else {
            return Err(CliError::MissingRootfs);
        };

        Ok(Config {
            hostname,
            rootfs,
            limits,
            network,
            command,
            args: rest.collect(),
        })
    }
}

/// Take the value following `flag`.
fn value(args: &mut impl Iterator<Item = String>, flag: &'static str) -> Result<String, CliError> {
    args.next().ok_or(CliError::MissingValue(flag))
}

/// Take the value following `flag` and parse it, or report it as invalid.
fn parse_flag<T>(
    args: &mut impl Iterator<Item = String>,
    flag: &'static str,
    parse: fn(&str) -> Option<T>,
) -> Result<T, CliError> {
    let value = value(args, flag)?;
    parse(&value).ok_or(CliError::InvalidValue { flag, value })
}

/// Parse a positive byte count with an optional K, M or G suffix (base 1024).
fn parse_size(s: &str) -> Option<u64> {
    let (digits, multiplier) = match s.char_indices().last()? {
        (i, 'k' | 'K') => (&s[..i], 1 << 10),
        (i, 'm' | 'M') => (&s[..i], 1 << 20),
        (i, 'g' | 'G') => (&s[..i], 1 << 30),
        _ => (s, 1),
    };
    let bytes = parse_count(digits)?.checked_mul(multiplier)?;
    Some(bytes)
}

/// Parse a positive integer.
fn parse_count(s: &str) -> Option<u64> {
    // u64's parser accepts a leading '+'; plain digits only.
    if !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok().filter(|&n| n > 0)
}

/// Parse a CPU fraction no smaller than the kernel's minimum quota.
fn parse_cpus(s: &str) -> Option<f64> {
    s.parse()
        .ok()
        .filter(|&n: &f64| n.is_finite() && n >= MIN_CPUS)
}

fn parse_network(s: &str) -> Option<NetworkMode> {
    match s {
        "bridge" => Some(NetworkMode::Bridge),
        "none" => Some(NetworkMode::None),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Config, CliError> {
        Config::new(args.iter().map(|s| s.to_string()))
    }

    fn parse_err(args: &[&str]) -> CliError {
        parse(args).unwrap_err()
    }

    #[test]
    fn run_with_command_only() {
        let config = parse(&["run", "--rootfs", "r", "sh"]).unwrap();
        assert_eq!(config.hostname, PROC_HOSTNAME);
        assert_eq!(config.command, "sh");
        assert!(config.args.is_empty());
    }

    #[test]
    fn run_with_command_and_args() {
        let config = parse(&["run", "--rootfs", "r", "echo", "hello", "world"]).unwrap();
        assert_eq!(config.command, "echo");
        assert_eq!(config.args, ["hello", "world"]);
    }

    #[test]
    fn hostname_flag_sets_hostname() {
        let config = parse(&["run", "--rootfs", "r", "--hostname", "box", "sh"]).unwrap();
        assert_eq!(config.hostname, "box");
        assert_eq!(config.command, "sh");
    }

    #[test]
    fn last_hostname_flag_wins() {
        let config = parse(&[
            "run",
            "--rootfs",
            "r",
            "--hostname",
            "a",
            "--hostname",
            "b",
            "sh",
        ])
        .unwrap();
        assert_eq!(config.hostname, "b");
    }

    #[test]
    fn flags_after_command_belong_to_command() {
        let config = parse(&["run", "--rootfs", "r", "sh", "--hostname", "box"]).unwrap();
        assert_eq!(config.hostname, PROC_HOSTNAME);
        assert_eq!(config.command, "sh");
        assert_eq!(config.args, ["--hostname", "box"]);
    }

    #[test]
    fn unknown_flag_is_treated_as_command() {
        let config = parse(&["run", "--rootfs", "r", "--verbose", "sh"]).unwrap();
        assert_eq!(config.command, "--verbose");
        assert_eq!(config.args, ["sh"]);
    }

    #[test]
    fn rootfs_flag_sets_rootfs() {
        let config = parse(&["run", "--hostname", "box", "--rootfs", "./alpine", "sh"]).unwrap();
        assert_eq!(config.rootfs, PathBuf::from("./alpine"));
        assert_eq!(config.hostname, "box");
        assert_eq!(config.command, "sh");
    }

    #[test]
    fn rootfs_after_command_belongs_to_command() {
        assert_eq!(
            parse_err(&["run", "sh", "--rootfs", "r"]),
            CliError::MissingRootfs
        );
    }

    #[test]
    fn missing_rootfs() {
        assert_eq!(parse_err(&["run", "sh"]), CliError::MissingRootfs);
    }

    #[test]
    fn rootfs_without_value() {
        assert_eq!(
            parse_err(&["run", "--rootfs"]),
            CliError::MissingValue("--rootfs")
        );
    }

    #[test]
    fn missing_command_reported_before_missing_rootfs() {
        assert_eq!(parse_err(&["run"]), CliError::MissingCommand);
    }

    #[test]
    fn missing_subcommand() {
        assert_eq!(parse_err(&[]), CliError::MissingSubcommand);
    }

    #[test]
    fn unknown_subcommand() {
        assert_eq!(
            parse_err(&["exec", "sh"]),
            CliError::UnknownSubcommand("exec".to_string())
        );
    }

    #[test]
    fn missing_command() {
        assert_eq!(parse_err(&["run"]), CliError::MissingCommand);
    }

    #[test]
    fn missing_command_after_hostname() {
        assert_eq!(
            parse_err(&["run", "--hostname", "box"]),
            CliError::MissingCommand
        );
    }

    #[test]
    fn hostname_without_value() {
        assert_eq!(
            parse_err(&["run", "--hostname"]),
            CliError::MissingValue("--hostname")
        );
    }

    #[test]
    fn parse_size_accepts_suffixes() {
        assert_eq!(parse_size("4096"), Some(4096));
        assert_eq!(parse_size("2K"), Some(2048));
        assert_eq!(parse_size("2k"), Some(2048));
        assert_eq!(parse_size("64M"), Some(64 << 20));
        assert_eq!(parse_size("64m"), Some(64 << 20));
        assert_eq!(parse_size("1G"), Some(1 << 30));
    }

    #[test]
    fn parse_size_rejects_bad_input() {
        for bad in [
            "", "M", "abc", "12X", "1.5G", "-1M", "+1M", "0", "0M", " 1M",
        ] {
            assert_eq!(parse_size(bad), None, "{bad:?}");
        }
        assert_eq!(parse_size("99999999999999999G"), None, "overflow");
    }

    #[test]
    fn limit_flags_set_limits() {
        let config = parse(&[
            "run", "--rootfs", "r", "--memory", "64M", "--pids", "32", "--cpus", "0.5", "sh",
        ])
        .unwrap();
        assert_eq!(
            config.limits,
            Limits {
                memory: Some(64 << 20),
                pids: Some(32),
                cpus: Some(0.5),
            }
        );
        assert!(!config.limits.is_empty());
    }

    #[test]
    fn no_limit_flags_means_no_limits() {
        let config = parse(&["run", "--rootfs", "r", "sh"]).unwrap();
        assert!(config.limits.is_empty());
    }

    #[test]
    fn invalid_limit_values() {
        for (flag, value) in [
            ("--memory", "lots"),
            ("--pids", "0"),
            ("--pids", "ten"),
            ("--cpus", "0"),
            ("--cpus", "-1"),
            ("--cpus", "0.001"),
            ("--cpus", "NaN"),
            ("--cpus", "inf"),
        ] {
            assert_eq!(
                parse_err(&["run", "--rootfs", "r", flag, value, "sh"]),
                CliError::InvalidValue {
                    flag,
                    value: value.to_string()
                },
                "{flag} {value}"
            );
        }
    }

    #[test]
    fn network_defaults_to_unset() {
        let config = parse(&["run", "--rootfs", "r", "sh"]).unwrap();
        assert_eq!(config.network, None);
    }

    #[test]
    fn network_flag_sets_mode() {
        for (value, mode) in [("bridge", NetworkMode::Bridge), ("none", NetworkMode::None)] {
            let config = parse(&["run", "--rootfs", "r", "--network", value, "sh"]).unwrap();
            assert_eq!(config.network, Some(mode));
        }
    }

    #[test]
    fn invalid_network() {
        assert_eq!(
            parse_err(&["run", "--rootfs", "r", "--network", "host", "sh"]),
            CliError::InvalidValue {
                flag: "--network",
                value: "host".to_string()
            }
        );
    }

    #[test]
    fn network_without_value() {
        assert_eq!(
            parse_err(&["run", "--network"]),
            CliError::MissingValue("--network")
        );
    }

    #[test]
    fn limit_flags_without_value() {
        for flag in ["--memory", "--pids", "--cpus"] {
            assert_eq!(parse_err(&["run", flag]), CliError::MissingValue(flag));
        }
    }

    #[test]
    fn display_messages() {
        assert_eq!(
            CliError::MissingSubcommand.to_string(),
            "missing subcommand"
        );
        assert_eq!(
            CliError::UnknownSubcommand("exec".to_string()).to_string(),
            "unknown subcommand 'exec'"
        );
        assert_eq!(
            CliError::MissingValue("--hostname").to_string(),
            "--hostname needs a value"
        );
        assert_eq!(
            CliError::InvalidValue {
                flag: "--memory",
                value: "lots".to_string()
            }
            .to_string(),
            "invalid value 'lots' for --memory"
        );
        assert_eq!(CliError::MissingRootfs.to_string(), "missing --rootfs");
        assert_eq!(
            CliError::MissingCommand.to_string(),
            "missing command to run"
        );
    }
}
