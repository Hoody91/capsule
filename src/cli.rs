use anyhow::{Result, bail};

pub const USAGE: &str = "usage: capsule run [--hostname NAME] <command> [args...]";

const PROC_HOSTNAME: &str = "capsule";

#[derive(Debug)]
pub struct Config {
    pub hostname: String,
    pub command: String,
    pub args: Vec<String>,
}

impl Config {
    pub fn new(mut args: impl Iterator<Item = String>) -> Result<Config> {
        match args.next().as_deref() {
            Some("run") => {}
            Some(other) => bail!("unknown subcommand '{other}'"),
            None => bail!("missing subcommand"),
        }

        let mut hostname = String::from(PROC_HOSTNAME);
        let mut rest = Vec::new();

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--hostname" if rest.is_empty() => match args.next() {
                    Some(h) => hostname = h,
                    None => bail!("--hostname needs a value"),
                },
                _ => {
                    rest.push(arg);
                    rest.extend(args.by_ref());
                }
            }
        }

        let mut rest = rest.into_iter();
        let Some(command) = rest.next() else {
            bail!("missing command to run");
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

    fn parse(args: &[&str]) -> Result<Config> {
        Config::new(args.iter().map(|s| s.to_string()))
    }

    fn parse_err(args: &[&str]) -> String {
        parse(args).unwrap_err().to_string()
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
        assert_eq!(parse_err(&[]), "missing subcommand");
    }

    #[test]
    fn unknown_subcommand() {
        assert_eq!(parse_err(&["exec", "sh"]), "unknown subcommand 'exec'");
    }

    #[test]
    fn missing_command() {
        assert_eq!(parse_err(&["run"]), "missing command to run");
    }

    #[test]
    fn missing_command_after_hostname() {
        assert_eq!(
            parse_err(&["run", "--hostname", "box"]),
            "missing command to run"
        );
    }

    #[test]
    fn hostname_without_value() {
        assert_eq!(
            parse_err(&["run", "--hostname"]),
            "--hostname needs a value"
        );
    }
}
