use std::process::{Command, Output};

fn capsule(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_capsule"))
        .args(args)
        .output()
        .expect("failed to spawn capsule")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn no_args_prints_usage_and_exits_2() {
    let output = capsule(&[]);
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("missing subcommand"));
    assert!(stderr(&output).contains("usage: capsule run"));
}

#[test]
fn unknown_subcommand_exits_2() {
    let output = capsule(&["frobnicate"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("unknown subcommand 'frobnicate'"));
}

#[test]
fn run_without_command_exits_2() {
    let output = capsule(&["run"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("missing command to run"));
}
