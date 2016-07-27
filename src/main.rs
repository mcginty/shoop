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

use daemonize::{Daemonize};
use std::process::Command;
use std::net::{UdpSocket, SocketAddr, SocketAddrV4};
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
use sodiumoxide::crypto::secretbox::xsalsa20poly1305::{NONCEBYTES, Key, Nonce};
use rustc_serialize::hex::{FromHex, ToHex};

fn command_exists(command: &str) -> bool {
    match Command::new("which").arg(command).output() {
        Ok(output) => output.status.success(),
        Err(_)     => false
    }
}

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options] REMOTE-LOCATION", program);
    print!("{}", opts.usage(&brief));
}

fn send_file(stream: UdtSocket, filename: &str, key: Key) -> Result<(), Error> {
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
        _ => {}
    }
    let mut payload = vec![0; 1300];
    f.seek(SeekFrom::Start(0)).unwrap();
    loop {
        match f.read(&mut payload) {
            Ok(0) => {
                break;
            }
            Ok(read) => {
                let nonce = secretbox::gen_nonce();
                let Nonce(noncebytes) = nonce;
                let mut hdr = vec![0u8; 1 + NONCEBYTES];
                hdr[0] = NONCEBYTES as u8;
                hdr[1..].clone_from_slice(&noncebytes);

                let mut sealed = secretbox::seal(&payload[0..read], &nonce, &key);
                let mut msg = Vec::with_capacity(hdr.len() + sealed.len());
                msg.extend_from_slice(&hdr);
                msg.append(&mut sealed);
                match stream.sendmsg(&msg[..]) {
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

fn recv_file(sock: UdtSocket, filesize: u64, filename: &str, key: Key) -> Result<(), Error> {
    let mut f = File::create(filename).unwrap();
    let mut ts = time::precise_time_ns();
    let mut total = 0u64;
    loop {
        let buf = try!(sock.recvmsg(8192).map_err(|e| Error::new(ErrorKind::Other, format!("{:?}", e))));
        if buf.len() < 1 {
            return Err(Error::new(ErrorKind::InvalidInput, "empty message"));
        }
        let noncelen = buf[0] as usize;
        if noncelen != NONCEBYTES {
            return Err(Error::new(ErrorKind::InvalidInput, "nonce bytes unexpected len"));
        }
        if buf.len() < (1 + noncelen) {
            return Err(Error::new(ErrorKind::InvalidInput, "nonce != nonce_len"));
        }
        let mut noncebytes = [0u8; NONCEBYTES];
        noncebytes.copy_from_slice(&buf[1..1+noncelen]);
        let nonce = Nonce(noncebytes);

        let unsealed = try!(secretbox::open(&buf[1+noncelen..], &nonce, &key).map_err(|_| Error::new(ErrorKind::InvalidInput, "failed to decrypt")));

        total += unsealed.len() as u64;
        f.write_all(&unsealed[..]).unwrap();
        if time::precise_time_ns() > ts + 10000000 {
            print!("\rreceived {:.1}M / {:.1}M ({:.1}%)                      ", (total as f64)/(1024f64*1024f64), (filesize as f64)/(1024f64*1024f64), (total as f64) / (filesize as f64) * 100f64);
            ts = time::precise_time_ns();
        }
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
            sock.setsockopt(UdtOpts::UDP_RCVBUF, 1024000i32).unwrap();
            sock.setsockopt(UdtOpts::UDP_SNDBUF, 1024000i32).unwrap();
            sock.bind(SocketAddr::V4(SocketAddrV4::from_str(&format!("{}:{}", ip, port)[..]).unwrap())).unwrap();

            sock.listen(1).unwrap();

            let (stream, _) = sock.accept().unwrap();

            if let Ok(version) = stream.recvmsg(1) {
                if version[0] == 0x00 {
                    send_file(stream, &input, key).unwrap();
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
            let cmd = format!("shoop -s '{}'", path);
            println!("addr: {}, path: {}, cmd: {}", addr, path, cmd);

            assert!(command_exists("ssh"), "`ssh` is required!");
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
                panic!("Unexpected response from server. Are you suuuuure shoop is setup on the server?");
            }

            let (magic, version, ip, port, keyhex) = (info[0], info[1], info[2], info[3], info[4]);
            println!("connecting to {}:{}", ip, port);
            if magic != "shoop" || version != "0" {
                panic!("Unexpected response from server. Are you suuuuure shoop is setup on the server?");
            }

            let mut keybytes = [0u8; 32];
            keybytes.copy_from_slice(&keyhex.from_hex().unwrap()[..]);
            let key = Key(keybytes);

            udt::init();
            let sock = UdtSocket::new(SocketFamily::AFInet, SocketType::Datagram).unwrap();
            sock.setsockopt(UdtOpts::UDP_RCVBUF, 1024000i32).unwrap();
            sock.setsockopt(UdtOpts::UDP_SNDBUF, 1024000i32).unwrap();
            let addr: SocketAddr = SocketAddr::V4(SocketAddrV4::from_str(&format!("{}:{}", ip, port)[..]).unwrap());
            match sock.connect(addr) {
               Ok(()) => {
                   println!("connected!");
               },
               Err(e) => {
                   panic!("errrrrrrr {:?}", e);
               }
            }

            sock.sendmsg(&[0u8; 1]).unwrap();
            // println!("checking if server is frand");

            match sock.recvmsg(8) {
               Ok(msg) => {
                   if msg.len() == 0 {
                       panic!("failed to get filesize from server, probable timeout.");
                   }
                   let mut rdr = Cursor::new(msg);
                   let filesize = rdr.read_u64::<LittleEndian>().unwrap();
                   let filename = Path::new(&path).file_name().unwrap_or(OsStr::new("outfile")).to_str().unwrap_or("outfile");
                   println!("{}, {:.1}MB", filename, (filesize as f64)/(1024f64*1024f64));
                   recv_file(sock, filesize, filename, key).unwrap();
               }
               Err(e) => {
                   panic!("{:?}", e);
               }
            }
        }
    }
}

