#[macro_use]
extern crate log;
extern crate env_logger;
extern crate getopts;
extern crate daemonize;
extern crate udt;
extern crate byteorder;
extern crate time;
extern crate sodiumoxide;
extern crate rustc_serialize;
extern crate shoop;

use std::str;
use std::env;
use getopts::Options;
use shoop::{Server, Client};

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options] REMOTE-LOCATION", program);
    print!("{}", opts.usage(&brief));
}

fn main() {
    enum Mode {Server, Client}
    env_logger::init().expect("Error starting logger");

    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();
    let mut opts = Options::new();
    // opts.optopt("o", "output", "set output file name", "NAME");
    opts.optflag("s", "server", "server mode");
    opts.optflag("p", "port-range", "server listening port range");
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

    match mode {
        Mode::Server => {
            Server::new(&input).start();
        }
        Mode::Client => {
            let sections: Vec<&str> = input.split(":").collect();
            let addr: String = sections[0].to_owned();
            let path: String = sections[1].to_owned();
            Client::new(&addr, &path).start();
        }
    }
}

