//! Implementation of a simple uTP client and server.
#[macro_use]
extern crate log;
extern crate env_logger;
extern crate getopts;
extern crate daemonize;
extern crate udt;
extern crate crypto;
extern crate byteorder;
extern crate rand;
extern crate sodiumoxide;
extern crate rustc_serialize;

use daemonize::{Daemonize};
use std::process::Command;
use std::net::{UdpSocket, SocketAddr, SocketAddrV4, Ipv4Addr};
use std::str;
use std::env;
use std::fs::File;
use std::str::FromStr;
use std::path::Path;
use std::ffi::OsStr;
use std::io::{Cursor, Error, Seek, SeekFrom, ErrorKind, stderr, Read, Write};
use getopts::Options;
use udt::*;
use byteorder::{ReadBytesExt, WriteBytesExt, LittleEndian};
use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::secretbox::xsalsa20poly1305::Key;
use rustc_serialize::hex::{FromHex, ToHex};


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
            // println!("wrote filesize of {:.2}kb.", filesize as f64 / 1024f64);
        }
    }
    // let mut total = 0;
    let mut payload = vec![0; 1300];
    f.seek(SeekFrom::Start(0)).unwrap();
    loop {
        match f.read(&mut payload) {
            Ok(0) => {
                // println!("\nEOF.");
                stream.sendmsg(&vec![0;0]).unwrap();
                break;
            }
            Ok(read) => {
                match stream.sendmsg(&payload[0..read]) {
                    Ok(_) =>  { }
                    Err(e) => {
                        stream.close().expect("Error closing stream");
                        panic!("{:?}", e);
                    }
                }
            },
            Err(e) => {
                stream.close().expect("Error closing stream");
                panic!("{:?}", e);
            }
        }
    }

    stream.close().expect("Error closing stream.");
    // println!("all done!");
    Ok(())
}

fn get_open_port(start: u16, end: u16) -> Result<u16, ()> {
    assert!(end >= start);
    let mut p = start;
    loop {
        match UdpSocket::bind(&format!("0.0.0.0:{}", p)[..]) {
            Ok(_) => {
                return Ok(p);
            }
            Err(_) => {
                p += 1;
                if p > end {
                    return Err(());
                }
            }
        }
    }
}

fn recv_file(sock: UdtSocket, filesize: u64, filename: &str) -> Result<(), Error> {
    let mut f = File::create(filename).unwrap();
    let mut total = 0u64;
    loop {
        let buf = try!(sock.recvmsg(1300).map_err(|e| Error::new(ErrorKind::Other, format!("{:?}", e))));
        total += buf.len() as u64;
        f.write_all(&buf[..]).unwrap();
        print!("\rreceived {}kb / {}kb ({:.1}%)", total/1024, filesize/1024, (total as f64/1024f64) / (filesize as f64/1024f64) * 100f64);
        if total >= filesize {
            println!("\nEOF");
            break;
        }
    }
    let _ = sock.close();
    Ok(())
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

    // Parse the mode argument
    let mode: Mode = match matches.opt_present("s") {
        true => Mode::Server,
        false => Mode::Client
    };

    match mode {
        Mode::Server => {
            let sshconnstr = env::var("SSH_CONNECTION").unwrap_or(String::from("0.0.0.0 0 0.0.0.0 22")).trim().to_owned();
            let sshconn: Vec<&str> = sshconnstr.split(" ").collect();
            let ip = sshconn[2];
            let port = get_open_port(55000, 55100).unwrap();
            let key = secretbox::gen_key();
            match key {
                Key(keybytes) => { println!("shoop 0 {} {} {}", ip, port, keybytes.to_hex()) }
            }

            let daemonize = Daemonize::new();
            match daemonize.start() {
                Ok(_) => { let _ = writeln!(&mut stderr(), "daemonized"); }
                Err(_) => { let _ = writeln!(&mut stderr(), "RWRWARWARARRR"); }
            }

            udt::init();
            let sock = UdtSocket::new(SocketFamily::AFInet, SocketType::Datagram).unwrap();
            sock.setsockopt(UdtOpts::UDP_RCVBUF, 5590000i32).unwrap();
            sock.setsockopt(UdtOpts::UDP_SNDBUF, 5590000i32).unwrap();
            sock.bind(SocketAddr::V4(SocketAddrV4::from_str(&format!("{}:{}", ip, port)[..]).unwrap())).unwrap();

            sock.listen(1).unwrap();

            let (stream, _) = sock.accept().unwrap();
            // dbg(format!("Received new connection from peer {:?}", peer));

            if let Ok(version) = stream.recvmsg(1) {
                // dbg(format!("frand using protocol version {}.", version[0]));
                if version[0] == 0x00 {
                    send_file(stream, &input).unwrap();
                } else {
                    panic!("Unrecognized version.");
                }
            } else {
                panic!("Failed to receive version byte from client.");
            }
        }
        Mode::Client => {
            let sections: Vec<&str> = input.split(":").collect();
            let addr: String = sections[0].to_owned();
            let path: String = sections[1].to_owned();
            let cmd = format!("~/bin/shoop -s {}", path);
            println!("addr: {}, path: {}, cmd: {}", addr, path, cmd);

            let output = Command::new("ssh")
                                 .arg(addr.to_owned())
                                 .arg(cmd)
                                 .output()
                                 .unwrap_or_else(|e| {
                                     panic!("failed to execute process: {}", e);
                                 });
            let infostring = String::from_utf8_lossy(&output.stdout).to_owned().trim().to_owned();
            let info: Vec<&str> = infostring.split(" ").collect();
            if info.len() != 5 {
                panic!("unexpected response format from server");
            }

            let (magic, version, ip, port, keyhex) = (info[0], info[1], info[2], info[3], info[4]);
            if magic != "shoop" || version != "0" {
                panic!("response from server.. i don't know what it means. what does it mean? help me i am so confused.");
            }

            let mut keybytes = [0u8; 32];
            keybytes.copy_from_slice(&keyhex.from_hex().unwrap()[..]);
            let key = Key(keybytes);
            println!("got key {}", keyhex);

            udt::init();
            let sock = UdtSocket::new(SocketFamily::AFInet, SocketType::Datagram).unwrap();
            sock.setsockopt(UdtOpts::UDP_RCVBUF, 5590000i32).unwrap();
            sock.setsockopt(UdtOpts::UDP_SNDBUF, 5590000i32).unwrap();
            let addr: SocketAddr = SocketAddr::V4(SocketAddrV4::from_str(&format!("{}:{}", ip, port)[..]).unwrap());
            // let addr: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from_str(&addr).unwrap(), 55000));
            match sock.connect(addr) {
               Ok(()) => {
                   println!("connected!");
               },
               Err(e) => {
                   panic!("errrrrrrr {:?}", e);
               }
            }

            sock.sendmsg(&[0u8; 1]).unwrap();
            println!("checking if server is frand");

            match sock.recvmsg(8) {
               Ok(msg) => {
                   if msg.len() == 0 {
                       panic!("failed to get filesize from server, probable timeout.");
                   }
                   let mut rdr = Cursor::new(msg);
                   let filesize = rdr.read_u64::<LittleEndian>().unwrap();
                   println!("got reported filesize of {}", filesize);
                   let filename = Path::new(&path).file_name().unwrap_or(OsStr::new("outfile")).to_str().unwrap_or("outfile");
                   println!("writing to {}", filename);
                   recv_file(sock, filesize, filename).unwrap();
               }
               Err(e) => {
                   panic!("{:?}", e);
               }
            }
        }
    }
}

