//! Implementation of a simple uTP client and server.
#[macro_use]
extern crate log;
extern crate env_logger;
extern crate getopts;
extern crate daemonize;
extern crate udt;
extern crate crypto;
extern crate byteorder;

use daemonize::{Daemonize};
use std::process;
use std::process::Command;
use std::thread;
use std::net::{SocketAddr, SocketAddrV4, Ipv4Addr};
use std::net;
use std::str;
use std::env;
use std::fs::File;
use std::str::FromStr;
use std::path::Path;
use std::io;
use std::io::{Cursor, Error, Seek, SeekFrom, ErrorKind, stdin, stdout, stderr, Read, Write};
use getopts::Options;
use crypto::{blake2b};
use udt::*;
use byteorder::{ReadBytesExt, WriteBytesExt, LittleEndian};

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options] REMOTE-LOCATION", program);
    print!("{}", opts.usage(&brief));
}

fn send_file(stream: UdtSocket, filename: &str) -> Result<(), Error> {
    let mut f = File::open(filename).unwrap();

    let mut filesize = 0u64;
    let mut buf = vec![0; 1024 * 1024];
    loop {
        match try!(f.read(&mut buf)) {
            0    => { break },
            read => { filesize += read as u64 },
        }
    }

    let mut wtr = vec![];
    wtr.write_u64::<LittleEndian>(filesize).unwrap();
    match stream.sendmsg(&wtr[..]) {
        Ok(0) => {
            return Err(Error::new(ErrorKind::WriteZero, "failed to write filesize header before timeout"))
        },
        Err(e) => {
            return Err(Error::new(ErrorKind::Other, format!("{:?}", e)))
        }
        _ => {
            println!("wrote filesize of {:.2}kb.", filesize as f64 / 1024f64);
        }
    }
    let mut total = 0;
    let mut payload = vec![0; 1300];
    f.seek(SeekFrom::Start(0));
    loop {
        match f.read(&mut payload) {
            Ok(0) => {
                println!("\nEOF.");
                stream.sendmsg(&vec![0;0]);
                break;
            }
            Ok(read) => {
                match stream.sendmsg(&payload[0..read]) {
                    Ok(written) => {
                        total += written;
                        print!("\rwritten {}kb / {}kb ({:.1}%)", total/1024, filesize/1024, (total as f64/1024f64) / (filesize as f64/1024f64) * 100f64);
                    },
                    Err(e) => {
                        stream.close().expect("Error closing stream");
                        panic!("{:?}", e);
                    }
                }
            },
            Err(e) => {
                stream.close().expect("Error closing stream");
                panic!("{}", e);
            }
        }
    }

    stream.close().expect("Error closing stream.");
    println!("all done!");
    Ok(())
}

fn recv_file(sock: UdtSocket, filesize: u64, filename: &str) -> Result<(), Error> {
    let mut f = File::create(filename).unwrap();
    let mut total = 0u64;
    loop {
        let buf = try!(sock.recvmsg(1300).map_err(|e| Error::new(ErrorKind::Other, format!("{:?}", e))));
        total += buf.len() as u64;
        f.write_all(&buf[..]);
        print!("\rreceived {}kb / {}kb ({:.1}%)", total/1024, filesize/1024, (total as f64/1024f64) / (filesize as f64/1024f64) * 100f64);
        if total >= filesize {
            println!("\nEOF");
            break;
        }
    }
    sock.close();
    Ok(())
}

fn main() {

    // This example may run in either server or client mode.
    // Using an enum tends to make the code cleaner and easier to read.
    enum Mode {Server, Client}

    // Start logging
    env_logger::init().expect("Error starting logger");

    // Fetch arguments
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();
    let mut opts = Options::new();
    opts.optopt("o", "output", "set output file name", "NAME");
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
            udt::init();
            let sock = UdtSocket::new(SocketFamily::AFInet, SocketType::Datagram).unwrap();
            sock.setsockopt(UdtOpts::UDP_RCVBUF, 5590000i32);
            sock.setsockopt(UdtOpts::UDP_SNDBUF, 5590000i32);
            // sock.setsockopt(UdtOpts::UDT_SNDSYN, true);
            sock.bind(SocketAddr::V4(SocketAddrV4::from_str("0.0.0.0:55000").unwrap())).unwrap();
            let my_addr = sock.getsockname().unwrap();
            println!("Server bound to {:?}", my_addr);

            sock.listen(1).unwrap();

            let (mut stream, peer) = sock.accept().unwrap();
            println!("Received new connection from peer {:?}", peer);

            let daemonize = Daemonize::new();

            let mut clientversion = vec![0; 1];
            if let Ok(version) = stream.recvmsg(1) {
                println!("frand using protocol version {}.", version[0]);
                if version[0] == 0x00 {
                    send_file(stream, &input);
                } else {
                    panic!("Unrecognized version.");
                }
            } else {
                panic!("Failed to receive version byte from client.");
            }

            // match daemonize.start() {
            //     Ok(_) => { let _ = writeln!(&mut stderr(), "daemonized"); }
            //     Err(e) => { let _ = writeln!(&mut stderr(), "RWRWARWARARRR"); }
            // }

        }
        Mode::Client => {
            let sections: Vec<&str> = input.split(":").collect();
            let addr: String = sections[0].to_owned();
            let path: String = sections[1].to_owned();
            let cmd = format!("~/bin/shoop -s {}", path);
            println!("addr: {}, path: {}, cmd: {}", addr, path, cmd);

            // let output = Command::new("ssh")
            //                      .arg(addr.to_owned())
            //                      .arg(cmd)
            //                      .output()
            //                      .unwrap_or_else(|e| {
            //                          panic!("failed to execute process: {}", e);
            //                      });
            // let udp_addr = String::from_utf8_lossy(&output.stdout).trim().to_owned();
            //
            // // Create a stream and try to connect to the remote address
            // println!("shoop server told us to connect to {}", udp_addr);
            udt::init();
            let sock = UdtSocket::new(SocketFamily::AFInet, SocketType::Datagram).unwrap();
            sock.setsockopt(UdtOpts::UDP_RCVBUF, 5590000i32);
            sock.setsockopt(UdtOpts::UDP_SNDBUF, 5590000i32);
            let addr: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from_str(&addr).unwrap(), 55000));
            sock.bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from_str("0.0.0.0").unwrap(), 0)));
            match sock.connect(addr) {
                Ok(()) => {
                    println!("connected!");
                },
                Err(e) => {
                    panic!("errrrrrrr {:?}", e);
                }
            }

            sock.sendmsg(&[0u8; 1]);
            println!("checking if server is frand");

            match sock.recvmsg(8) {
                Ok(msg) => {
                    if msg.len() == 0 {
                        panic!("failed to get filesize from server, probable timeout.");
                    }
                    let mut rdr = Cursor::new(msg);
                    let filesize = rdr.read_u64::<LittleEndian>().unwrap();
                    println!("got reported filesize of {}", filesize);
                    recv_file(sock, filesize, "outfile");
                }
                Err(e) => {
                    panic!("{:?}", e);
                }
            }
        }
    }
}

