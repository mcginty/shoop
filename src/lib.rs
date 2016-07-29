#[macro_use]
extern crate log;
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
use std::fmt;
use std::str::FromStr;
use std::fs::{OpenOptions, File};
use std::path::Path;
use std::ffi::OsStr;
use std::io::{Cursor, Error, Seek, SeekFrom, stderr, Read, Write};
use udt::{UdtSocket, UdtOpts, SocketType, SocketFamily};
use log::{LogRecord, LogLevel, LogMetadata};
use byteorder::{ReadBytesExt, WriteBytesExt, LittleEndian};
use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::secretbox::xsalsa20poly1305::{NONCEBYTES, Key, Nonce};
use rustc_serialize::hex::{FromHex, ToHex};

macro_rules! overprint {
    ($fmt: expr) => {
        print!(concat!("\x1b[2K\r", $fmt));
        std::io::stdout().flush().unwrap();
    };
    ($fmt:expr, $($arg:tt)*) => {
        print!(concat!("\x1b[2K\r", $fmt) , $($arg)*);
        std::io::stdout().flush().unwrap();
    };
}

pub struct Server<'a> {
    filename: &'a str,
    sock: UdtSocket,
    key: Key,
}

pub struct Client<'a> {
    remote_host: &'a str,
    port_range: PortRange,
    remote_path: &'a str,
}

pub struct PortRange {
    start: u16,
    end: u16
}

enum ShoopErrKind {
    Severed,
    Fatal,
}
struct ShoopErr {
    kind: ShoopErrKind,
    msg: Option<String>,
    finished: u64,
}

pub struct ShoopLogger;

impl log::Log for ShoopLogger {
    fn enabled(&self, metadata: &LogMetadata) -> bool {
        metadata.level() <= LogLevel::Info
    }

    fn log(&self, record: &LogRecord) {
        if self.enabled(record.metadata()) {
            let mut f = OpenOptions::new().append(true).create(true).open("/home/kaonashi/shoop/shoop.log").expect("failed to open logfile");
            let line = format!("{} - {}\n", record.level(), record.args());
            print!("{}", line);
            let _ = f.write_all(&line.into_bytes()[..]);
            let _ = std::io::stdout().flush();
        }
    }
}

impl ShoopLogger {
    pub fn init() -> Result<(), log::SetLoggerError> {
        log::set_logger(|max_log_level| {
            max_log_level.set(log::LogLevelFilter::Info);
            Box::new(ShoopLogger)
        })
    }
}

impl ShoopErr {
    pub fn new(kind: ShoopErrKind, msg: &str, finished: u64) -> ShoopErr {
        ShoopErr { kind: kind, msg: Some(String::from(msg)), finished: finished }
    }

    pub fn from(err: Error, finished: u64) -> ShoopErr {
        ShoopErr { kind: ShoopErrKind::Severed, msg: Some(format!("{:?}", err)), finished: finished }
    }
}

impl PortRange {
    fn new(start: u16, end: u16) -> PortRange {
        PortRange{ start: start, end: end }
    }

    pub fn from(s: &str) -> Result<PortRange, &str> {
        let sections: Vec<&str> = s.split("-").collect();
        if sections.len() != 2 {
            return Err("Range must be specified in the form of \"<start>-<end>\"")
        }
        let (start, end) = (sections[0].parse::<u16>(),
                            sections[1].parse::<u16>());
        if start.is_err() || end.is_err() {
            return Err("invalid port range");
        }
        Ok(PortRange::new(start.unwrap(), end.unwrap()))
    }
}

impl fmt::Display for PortRange {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}-{}", self.start, self.end)
    }
}

impl<'a> Server<'a> {
    pub fn new(port_range : PortRange,
               filename   : &str)
        -> Server
    {
        let sshconnstr = env::var("SSH_CONNECTION").unwrap_or(String::from("0.0.0.0 0 0.0.0.0 22")).trim().to_owned();
        let sshconn: Vec<&str> = sshconnstr.split(" ").collect();
        let ip = sshconn[2];
        let port = Server::get_open_port(port_range).unwrap();
        let key = secretbox::gen_key();
        let Key(keybytes) = key;
        println!("shoop 0 {} {} {}", ip, port, keybytes.to_hex());
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
        Server { sock: sock, key: key, filename: filename }
    }

    pub fn start(&self) {
        self.sock.listen(1).unwrap();

        info!("listening...");
        loop {
            info!("waiting for connection...");
            let stream = match self.sock.accept() {
                Ok((stream, _)) => stream,
                Err(e) => { error!("error on sock accept() {:?}", e); panic!("{:?}", e); }
            };
            info!("accepted connection!");
            if let Ok(starthdr) = stream.recvmsg(9) {
                let version = starthdr[0];
                let mut rdr = Cursor::new(starthdr);
                rdr.set_position(1);
                let offset = rdr.read_u64::<LittleEndian>().unwrap();
                if version == 0x00 {
                    match self.send_file(stream, offset) {
                        Ok(_) => {
                            info!("done sending file");
                            let _ = stream.close();
                            break;
                        }
                        Err(ShoopErr{ kind: ShoopErrKind::Severed, msg, finished}) => {
                            info!("connection severed, msg: {:?}, finished: {}", msg, finished);
                            let _ = stream.close();
                            continue;
                        }
                        Err(ShoopErr{ kind: ShoopErrKind::Fatal, msg, finished}) => {
                            info!("connection fatal, msg: {:?}, finished: {}", msg, finished);
                            panic!("{:?}", msg);
                        }
                    }
                } else {
                    error!("unrecognized version");
                    panic!("Unrecognized version.");
                }
            } else {
                error!("Failed to receive version byte from client.");
                panic!("Failed to receive version byte from client.");
            }
        }
        info!("exiting listen loop.");
    }

    fn send_file(&self, stream: UdtSocket, offset: u64) -> Result<(), ShoopErr> {
        let mut f = File::open(self.filename).unwrap();
        f.seek(SeekFrom::Start(offset)).unwrap();

        let mut remaining = 0u64;
        let mut buf = vec![0; 1024 * 1024];
        loop {
            match try!(f.read(&mut buf).map_err(|e| ShoopErr::from(e, 0u64))) {
                0    => { break },
                read => { remaining += read as u64 },
            }
        }
        info!("total {} bytes", remaining);

        let mut wtr = vec![];
        wtr.write_u64::<LittleEndian>(remaining).unwrap();
        match stream.sendmsg(&wtr[..]) {
            Ok(0) => {
                return Err(ShoopErr::new(ShoopErrKind::Severed, "failed to write filesize header before timeout", remaining))
            },
            Err(e) => {
                return Err(ShoopErr::new(ShoopErrKind::Severed, &format!("{:?}", e), remaining))
            }
            _ => {}
        }
        let mut payload = vec![0; 1300];
        f.seek(SeekFrom::Start(offset)).unwrap();
        info!("sending file...", remaining);
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

                    let mut sealed = secretbox::seal(&payload[0..read], &nonce, &self.key);
                    let mut msg = Vec::with_capacity(hdr.len() + sealed.len());
                    msg.extend_from_slice(&hdr);
                    msg.append(&mut sealed);
                    match stream.sendmsg(&msg[..]) {
                        Ok(0) => {
                            return Err(ShoopErr::new(ShoopErrKind::Severed, "failed to write filesize header before timeout", remaining))
                        },
                        Err(e) => {
                            return Err(ShoopErr::new(ShoopErrKind::Severed, &format!("{:?}", e), remaining))
                        }
                        _ => {}
                    }
                },
                Err(e) => {
                    stream.close().expect("Error closing stream");
                    error!("failed to read from file.");
                    panic!("{:?}", e);
                }
            }
        }

        stream.close().expect("Error closing stream.");
        Ok(())
    }

    fn get_open_port(range: PortRange) -> Result<u16, ()> {
        for p in range.start..range.end {
            if let Ok(_) = UdpSocket::bind(&format!("0.0.0.0:{}", p)[..]) {
                return Ok(p);
            }
        }
        Err(())
    }
}

impl<'a> Client<'a> {
    pub fn new(remote_ssh_host : &'a str,
               port_range      : PortRange,
               remote_path     : &'a str)
        -> Client<'a>
    {
        Client{ remote_host: remote_ssh_host, port_range: port_range, remote_path: remote_path }
    }

    pub fn start(&self) {
        let cmd = format!("shoop -s '{}' -p {}", self.remote_path, self.port_range);
        // println!("addr: {}, path: {}, cmd: {}", addr, path, cmd);

        overprint!(" - establishing SSH session...");
        assert!(Client::command_exists("ssh"), "`ssh` is required!");
        let output = Command::new("ssh")
                             .arg(self.remote_host.to_owned())
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
        overprint!(" - opening UDT connection...");
        if magic != "shoop" || version != "0" {
            panic!("Unexpected response from server. Are you suuuuure shoop is setup on the server?");
        }

        let mut keybytes = [0u8; 32];
        keybytes.copy_from_slice(&keyhex.from_hex().unwrap()[..]);
        let key = Key(keybytes);

        udt::init();
        let addr: SocketAddr = SocketAddr::V4(SocketAddrV4::from_str(&format!("{}:{}", ip, port)[..]).unwrap());

        let mut offset = 0u64;
        loop {
            let sock = UdtSocket::new(SocketFamily::AFInet, SocketType::Datagram).unwrap();
            sock.setsockopt(UdtOpts::UDP_RCVBUF, 1024000i32).unwrap();
            sock.setsockopt(UdtOpts::UDP_SNDBUF, 1024000i32).unwrap();
            match sock.connect(addr) {
               Ok(()) => {
                   overprint!(" - connection opened, shakin' hands, makin' frands");
               },
               Err(e) => {
                   panic!("errrrrrrr connecting to {}:{} - {:?}", ip, port, e);
               }
            }
            let mut wtr = vec![];
            wtr.push(0);
            wtr.write_u64::<LittleEndian>(offset).unwrap();
            match sock.sendmsg(&wtr[..]) {
                Err(_) => { sock.close().unwrap(); continue; }
                _      => {}
            }

            match sock.recvmsg(8) {
               Ok(msg) => {
                   if msg.len() == 0 {
                       panic!("failed to get filesize from server, probable timeout.");
                   }
                   let mut rdr = Cursor::new(msg);
                   let filesize = rdr.read_u64::<LittleEndian>().unwrap();
                   let filename = Path::new(&self.remote_path).file_name().unwrap_or(OsStr::new("outfile")).to_str().unwrap_or("outfile");
                   overprint!(" + downloading {} ({:.1}MB)\n", filename, (filesize as f64)/(1024f64*1024f64));
                   match self.recv_file(sock, filesize, filename, &key, offset) {
                        Ok(_) => {
                            break;
                        }
                        Err(ShoopErr{ kind: ShoopErrKind::Severed, msg: _, finished}) => {
                            println!(" * [[SEVERED]]");
                            offset = finished;
                        }
                        Err(ShoopErr{ kind: ShoopErrKind::Fatal, msg, finished: _}) => {
                            panic!("{:?}", msg);
                        }
                   }
               }
               Err(_) => {}
            }
            let _ = sock.close();
        }
    }

    fn command_exists(command: &str) -> bool {
        match Command::new("which").arg(command).output() {
            Ok(output) => output.status.success(),
            Err(_)     => false
        }
    }

    fn recv_file(&self, sock: UdtSocket, filesize: u64, filename: &str, key: &Key, offset: u64) -> Result<(), ShoopErr> {
        let mut f = OpenOptions::new().write(true).create(true).truncate(false).open(filename).unwrap();
        f.seek(SeekFrom::Start(offset)).unwrap();
        let mut ts = time::precise_time_ns();
        let mut total = 0u64;
        loop {
            let buf = try!(sock.recvmsg(8192)
                               .map_err(|e| ShoopErr::new(ShoopErrKind::Severed, &format!("{:?}", e), total)));
            if buf.len() < 1 {
                return Err(ShoopErr::new(ShoopErrKind::Severed, "empty msg", total));
            }
            let noncelen = buf[0] as usize;
            if noncelen != NONCEBYTES {
                return Err(ShoopErr::new(ShoopErrKind::Fatal, "nonce length not recognized", total));
            }
            if buf.len() < (1 + noncelen) {
                return Err(ShoopErr::new(ShoopErrKind::Severed, "msg not long enough to contain nonce", total));
            }
            let mut noncebytes = [0u8; NONCEBYTES];
            noncebytes.copy_from_slice(&buf[1..1+noncelen]);
            let nonce = Nonce(noncebytes);

            let unsealed = try!(secretbox::open(&buf[1+noncelen..], &nonce, &key).map_err(|_| ShoopErr::new(ShoopErrKind::Fatal, "failed to decrypt", total)));

            total += unsealed.len() as u64;
            f.write_all(&unsealed[..]).unwrap();
            if time::precise_time_ns() > ts + 100_000_000 {
                overprint!("   {:.1}M / {:.1}M ({:.1}%)", (total as f64)/(1024f64*1024f64), (filesize as f64)/(1024f64*1024f64), (total as f64) / (filesize as f64) * 100f64);
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
}
