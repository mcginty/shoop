//! Implementation of a simple uTP client and server.
#[macro_use]
extern crate log;
extern crate env_logger;
extern crate utp;
extern crate getopts;
extern crate url;

use url::{Url, ParseError};
use std::process;
use std::process::Command;
use std::thread;
use std::net::{SocketAddr, SocketAddrV4, Ipv4Addr};
use std::net;
use std::str;
use std::env;
use std::fs::File;
use getopts::Options;

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options] REMOTE-LOCATION", program);
    print!("{}", opts.usage(&brief));
}

fn main() {
    use utp::UtpStream;
    use std::io::{stdin, stdout, stderr, Read, Write};

    // This example may run in either server or client mode.
    // Using an enum tends to make the code cleaner and easier to read.
    enum Mode {Server, Client}

    // Start logging
    env_logger::init().expect("Error starting logger");

    // Fetch arguments
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();
    let mut opts = Options::new();
    opts.optopt("o", "", "set output file name", "NAME");
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

    // Parse the mode argument
    let mode: Mode = match matches.opt_present("s") {
        true => Mode::Server,
        false => Mode::Client
    };

    match mode {
        Mode::Server => {
            // Create a listening stream
            let mut stream = UtpStream::bind("127.0.0.1:8080").expect("Error binding stream");
            let mut writer = stdout();
            let _ = writeln!(&mut stderr(), "Serving on 127.0.0.1:8080");

            let mut f = File::open(input).unwrap();

            // Create a reasonably sized buffer
            let mut payload = vec![0; 1024 * 1024];

            // Wait for a new connection and print the received data to stdout.
            // Reading and printing chunks like this feels more interactive than trying to read
            // everything with `read_to_end` and avoids resizing the buffer multiple times.
            loop {
                match stream.read(&mut payload) {
                    Ok(0) => break,
                    Ok(read) => writer.write(&payload[..read]).expect("Error writing to stdout"),
                    Err(e) => panic!("{}", e)
                };
            }
        }
        Mode::Client => {
            let sections: Vec<&str> = input.split(":").collect();
            let addr = sections[0];
            let path = sections[1];
            let output = Command::new("ssh")
                                 .arg(addr)
                                 .arg("shoop -s path")
                                 .output()
                                 .unwrap_or_else(|e| {
                                     panic!("failed to execute process: {}", e);
                                 });
            let result = output.stdout;


            // Create a stream and try to connect to the remote address
            let mut stream = UtpStream::connect(addr).expect("Error connecting to remote peer");
            let mut reader = stdin();

            // Create a reasonably sized buffer
            let mut payload = vec![0; 1024 * 1024];

            // Read from stdin and send it to the remote server.
            // Once again, reading and sending small chunks like this avoids having to read the
            // entire input (which may be endless!) before starting to send, unlike what would
            // happen if we were to use `read_to_end` on `reader`.
            loop {
                match reader.read(&mut payload) {
                    Ok(0) => break,
                    Ok(read) => stream.write(&payload[..read]).expect("Error writing to stream"),
                    Err(e) => {
                        stream.close().expect("Error closing stream");
                        panic!("{:?}", e);
                    }
                };
            }

            // Explicitly close the stream.
            stream.close().expect("Error closing stream");
        }
    }
}

