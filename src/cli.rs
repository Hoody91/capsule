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
