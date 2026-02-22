use std::env;
use std::path::Path;
use std::process::{exit, Command};

const BRIDGE_VERSION: &str = "0.1.0";

fn print_help() {
    println!(
        "foxclaw-rs-cli (bridge scaffold)\n\
         Usage:\n\
           foxclaw-rs-cli <foxclaw-subcommand> [args...]\n\
           foxclaw-rs-cli --help\n\
           foxclaw-rs-cli --version\n\n\
         Environment:\n\
           FOXCLAW_PYTHON_BIN  Python interpreter used for bridge execution.\n\n\
         Notes:\n\
           This WS-31 bridge forwards commands to `python -m foxclaw` while the\n\
           native Rust scanner implementation lands in later workslices."
    );
}

fn resolve_python_bin() -> String {
    if let Ok(explicit) = env::var("FOXCLAW_PYTHON_BIN") {
        if !explicit.trim().is_empty() {
            return explicit;
        }
    }
    if Path::new(".venv/bin/python").exists() {
        ".venv/bin/python".to_string()
    } else {
        "python3".to_string()
    }
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("error: missing subcommand.");
        print_help();
        exit(2);
    }
    if args.len() == 1 && (args[0] == "--help" || args[0] == "-h") {
        print_help();
        exit(0);
    }
    if args.len() == 1 && args[0] == "--version" {
        println!("foxclaw-rs-cli {} (bridge)", BRIDGE_VERSION);
        exit(0);
    }

    let python_bin = resolve_python_bin();
    let status = Command::new(&python_bin)
        .arg("-m")
        .arg("foxclaw")
        .args(&args)
        .status();
    match status {
        Ok(child_status) => {
            let code = child_status.code().unwrap_or(1);
            exit(code);
        }
        Err(exc) => {
            eprintln!(
                "error: failed to execute bridge command with '{}': {}",
                python_bin, exc
            );
            exit(1);
        }
    }
}
