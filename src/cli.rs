use std::fmt;

pub const USAGE: &str = "usage: capsule run [--hostname NAME] <command> [args...]";

const PROC_HOSTNAME: &str = "capsule";

#[derive(Debug, PartialEq)]
pub enum CliError {
    MissingSubcommand,
    UnknownSubcommand(String),
    MissingHostnameValue,
    MissingCommand,
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CliError::MissingSubcommand => write!(f, "missing subcommand"),
            CliError::UnknownSubcommand(name) => write!(f, "unknown subcommand '{name}'"),
            CliError::MissingHostnameValue => write!(f, "--hostname needs a value"),
            CliError::MissingCommand => write!(f, "missing command to run"),
        }
    }
}

impl std::error::Error for CliError {}

#[derive(Debug)]
pub struct Config {
    pub hostname: String,
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
        let mut rest = Vec::new();

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--hostname" if rest.is_empty() => match args.next() {
                    Some(h) => hostname = h,
                    None => return Err(CliError::MissingHostnameValue),
                },
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

        Ok(Config {
            hostname,
            command,
            args: rest.collect(),
        })
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
        let config = parse(&["run", "sh"]).unwrap();
        assert_eq!(config.hostname, PROC_HOSTNAME);
        assert_eq!(config.command, "sh");
        assert!(config.args.is_empty());
    }

    #[test]
    fn run_with_command_and_args() {
        let config = parse(&["run", "echo", "hello", "world"]).unwrap();
        assert_eq!(config.command, "echo");
        assert_eq!(config.args, ["hello", "world"]);
    }

    #[test]
    fn hostname_flag_sets_hostname() {
        let config = parse(&["run", "--hostname", "box", "sh"]).unwrap();
        assert_eq!(config.hostname, "box");
        assert_eq!(config.command, "sh");
    }

    #[test]
    fn last_hostname_flag_wins() {
        let config = parse(&["run", "--hostname", "a", "--hostname", "b", "sh"]).unwrap();
        assert_eq!(config.hostname, "b");
    }

    #[test]
    fn flags_after_command_belong_to_command() {
        let config = parse(&["run", "sh", "--hostname", "box"]).unwrap();
        assert_eq!(config.hostname, PROC_HOSTNAME);
        assert_eq!(config.command, "sh");
        assert_eq!(config.args, ["--hostname", "box"]);
    }

    #[test]
    fn unknown_flag_is_treated_as_command() {
        let config = parse(&["run", "--verbose", "sh"]).unwrap();
        assert_eq!(config.command, "--verbose");
        assert_eq!(config.args, ["sh"]);
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
            CliError::MissingHostnameValue
        );
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
            CliError::MissingHostnameValue.to_string(),
            "--hostname needs a value"
        );
        assert_eq!(
            CliError::MissingCommand.to_string(),
            "missing command to run"
        );
    }
}
