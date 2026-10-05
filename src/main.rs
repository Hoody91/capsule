use std::process::ExitCode;

use crate::cli::Config;

mod cgroup;
mod cli;
mod container;
mod rootfs;

fn main() -> ExitCode {
    match Config::new(std::env::args().skip(1)) {
        Ok(config) => match container::run(&config) {
            Ok(code) => ExitCode::from(code),
            Err(e) => {
                eprintln!("capsule: {e}");
                ExitCode::from(125)
            }
        },
        Err(e) => {
            eprintln!("capsule {e}\n\n{}", cli::USAGE);
            ExitCode::from(2)
        }
    }
}
