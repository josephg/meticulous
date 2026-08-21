mod cli;
mod commands;
mod config;
mod mtp;
mod db;
mod hash;
mod marks;
mod parity;
mod util;
mod worker;
mod zfs;

use clap::Parser;

fn main() {
    // Behave like a normal Unix tool when piped into `head` etc.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
    let cli = cli::Cli::parse();
    match commands::run(cli) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("error: {e:#}");
            std::process::exit(1);
        }
    }
}
