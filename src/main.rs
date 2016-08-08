#[macro_use]
extern crate log;
extern crate getopts;
#[macro_use]
extern crate shoop;

use std::str;
use std::env;
use getopts::Options;
use shoop::{ShoopLogger, ShoopMode, TransferMode, Target, Server, Client};
use shoop::connection::PortRange;

const VERSION: &'static str = env!("CARGO_PKG_VERSION");
const DEFAULT_PORT_RANGE: &'static str = "55000-55050";

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Shoop is a ultrafast, (hopefully) secure file transfer tool, that is
(hopefully) ideal for transferring large files.

Usage: {0} [options] SOURCE DEST
...where HOST is an SSH host
...where PATH is the path on the *remote* machine of the file you want
...where DEST is either an existing folder or a location for the new
                 file (\".\" by default)

Example: {0} seedbox.facebook.com:/home/zuck/internalized_sadness.zip .",
                        program);
    print!("{}", opts.usage(&brief));
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();
    let mut opts = Options::new();
    // TODO
    // opts.optopt("o", "output", "set output file name", "NAME");
    // opts.optopt("a", "ssh-args", "arguments to pass to ssh directly (at your own risk)", ARGS);
    opts.optopt("p",
                "port-range",
                "server listening port range",
                DEFAULT_PORT_RANGE);
    opts.optflag("r", "receive", "receive mode (server mode only)");
    opts.optflag("s", "server", "server mode (advanced usage only)");
    opts.optflag("h", "help", "print this help menu");
    opts.optflag("v", "version", "print the version");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => panic!(f.to_string()),
    };

    if matches.opt_present("h") {
        print_usage(&program, opts);
        return;
    }

    if matches.opt_present("v") {
        println!("shoop {}", VERSION);
        return;
    }

    let raw_source = if !matches.free.is_empty() {
        matches.free[0].clone()
    } else {
        print_usage(&program, opts);
        return;
    };

    let mode = if matches.opt_present("s") {
        ShoopMode::Server
    } else {
        ShoopMode::Client
    };

    let port_range = {
        let range_opt = &matches.opt_str("p").unwrap_or_else(|| String::from(DEFAULT_PORT_RANGE));
        PortRange::from(range_opt).unwrap()
    };

    ShoopLogger::init(mode).expect("Error starting shoop logger.");

    match mode {
        ShoopMode::Server => {
            let transfer_mode = if matches.opt_present("r") {
                TransferMode::Receive
            } else {
                TransferMode::Send
            };

            if let Ok(server) = Server::new(port_range, &raw_source) {
                server.start(transfer_mode);
                info!("exiting.");
            }
        }
        ShoopMode::Client => {
            let raw_dest = if matches.free.len() > 1 {
                matches.free[1].clone()
            } else {
                String::from(".")
            };

            let source = Target::from(raw_source.clone());
            let dest = Target::from(raw_dest.clone());

            match Client::new(source, dest, port_range) {
                Ok(client) => client.start(),
                Err(e) => error!("{}", e),
            }
        }
    }
}
