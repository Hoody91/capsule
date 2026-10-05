use std::process::ExitCode;

use crate::cli::Config;

mod cli;

fn main() -> ExitCode {
    match Config::new(std::env::args().skip(1)) {
        Ok(_config) => {
            unimplemented!()
        }
        Err(e) => {
            eprintln!("capsule {e}\n\n{}", cli::USAGE);
            ExitCode::from(2)
        }
    }
}
