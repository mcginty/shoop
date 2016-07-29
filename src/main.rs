#[macro_use]
extern crate log;
extern crate env_logger;
extern crate getopts;
extern crate shoop;

use std::str;
use std::env;
use getopts::Options;
use shoop::{Server, Client, PortRange};

const DEFAULT_PORT_RANGE: &'static str = "55000-55050";

fn print_usage(program: &str, opts: Options) {
    let brief = format!(
"Shoop is a ultrafast, (hopefully) secure file transfer tool, that is
(hopefully) ideal for transferring large files.

Usage: {0} [options] HOST:PATH
...where HOST is an SSH host
...where PATH is the path on the *remote* machine of the file you want

Example: {0} seedbox.facebook.com:/home/zuck/internalized_sadness.zip", program);
    print!("{}", opts.usage(&brief));
}

fn main() {
    enum Mode {Server, Client}
    env_logger::init().expect("Error starting logger");

    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();
    let mut opts = Options::new();
    // TODO
    // opts.optopt("o", "output", "set output file name", "NAME");
    // opts.optopt("a", "ssh-args", "arguments to pass to ssh directly (at your own risk)", ARGS);
    opts.optopt("p", "port-range", "server listening port range", DEFAULT_PORT_RANGE);
    opts.optflag("s", "server", "server mode (advanced usage only)");
    opts.optflag("h", "help", "print this help menu");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => { m }
        Err(f) => { panic!(f.to_string()) }
    };

    if matches.opt_present("h") {
        print_usage(&program, opts);
        return;
    }

    let input = if !matches.free.is_empty() {
        matches.free[0].clone()
    } else {
        print_usage(&program, opts);
        return;
    };

    let mode: Mode = match matches.opt_present("s") {
        true => Mode::Server,
        false => Mode::Client
    };

    let port_range = {
        let range_opt = &matches.opt_str("p").unwrap_or(String::from(DEFAULT_PORT_RANGE));
        PortRange::from(range_opt).unwrap()
    };

    match mode {
        Mode::Server => {
            Server::new(port_range, &input).start();
        }
        Mode::Client => {
            let sections: Vec<&str> = input.split(":").collect();
            let addr: String = sections[0].to_owned();
            let path: String = sections[1].to_owned();
            Client::new(&addr, port_range, &path).start();
        }
    }
}

