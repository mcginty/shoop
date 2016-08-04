#[macro_use]
extern crate log;
extern crate getopts;
#[macro_use]
extern crate shoop;

use std::str;
use std::env;
use std::path::Path;
use getopts::Options;
use shoop::{ShoopLogger, Server, download};
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

enum Target {
    Local(String),
    Remote(String, String),
}

impl Target {
    fn from(s: String) -> Target {
        match s.find(':') {
            None => Target::Local(s),
            Some(i) => {
                let owned = s.to_owned();
                let (first, second) = owned.split_at(i);
                if first.contains('/') {
                    Target::Local(s)
                } else {
                    Target::Remote(String::from(first), String::from(second))
                }
            }
        }
    }
}

fn main() {
    enum Mode {
        Server,
        Client,
    }
    ShoopLogger::init().expect("Error starting shoop logger.");

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

    let source = if !matches.free.is_empty() {
        matches.free[0].clone()
    } else {
        print_usage(&program, opts);
        return;
    };

    let mode: Mode = if matches.opt_present("s") {
        Mode::Server
    } else {
        Mode::Client
    };


    let port_range = {
        let range_opt = &matches.opt_str("p").unwrap_or_else(|| String::from(DEFAULT_PORT_RANGE));
        PortRange::from(range_opt).unwrap()
    };

    match mode {
        Mode::Server => {
            Server::new(port_range, &source).start();
        }
        Mode::Client => {
            let dest = if matches.free.len() > 1 {
                matches.free[1].clone()
            } else {
                String::from(".")
            };

            match Target::from(source) {
                Target::Local(_) => error!("Sorry, you can only copy *from* a remote host currently."),
                Target::Remote(source_addr, source_path_str) => {
                    match Target::from(dest) {
                        Target::Remote(_,_) => error!("Sorry, you can only copy to a local path currently."),
                        Target::Local(dest_path_str) => {
                            let source_path = Path::new(&source_path_str);
                            let source_file_name = match source_path.file_name() {
                                Some(s) => s,
                                None => {
                                    error!("The remote path specified doesn't look like a path to a file.");
                                    std::process::exit(1);
                                }
                            };
                            let dest_path = Path::new(&dest_path_str);
                            let final_dest_path = if dest_path.is_dir() {
                                dest_path.join(source_file_name)
                            } else {
                                dest_path.to_path_buf()
                            };

                            download(&source_addr, port_range, &dest_path_str, final_dest_path);
                        }
                    }
                }
            }

        }
    }
}
