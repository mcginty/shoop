#![cfg_attr(all(feature = "nightly", test), feature(test))]
#[macro_use]
extern crate log;
extern crate libc;
extern crate getopts;
extern crate unix_daemonize;
extern crate byteorder;
extern crate udt;
extern crate time;
extern crate sodiumoxide;
extern crate rustc_serialize;
extern crate colored;

// crates needed for unit tests
#[cfg(test)]
extern crate rand;

pub mod connection;

use unix_daemonize::{daemonize_redirect, ChdirMode};
use std::process::Command;
use std::net::{SocketAddr, IpAddr};
use std::{str, env, thread, fmt};
use std::str::FromStr;
use std::fs::{OpenOptions, File};
use std::path::{Path, PathBuf};
use std::time::{Instant, Duration};
use std::io::{Cursor, Error, Seek, SeekFrom, stderr, Read, Write};
use std::sync::mpsc;
use log::{LogRecord, LogLevel, LogMetadata};
use colored::*;
use byteorder::{ReadBytesExt, WriteBytesExt, LittleEndian};
use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::secretbox::xsalsa20poly1305::Key;
use rustc_serialize::hex::{FromHex, ToHex};

// TODO config
const INITIAL_ACCEPT_TIMEOUT_SECONDS: u64 = 60;

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

#[macro_export]
macro_rules! die {
    ($fmt: expr) => {
        error!($fmt);
        panic!($fmt)
    };
    ($fmt:expr, $($arg:tt)*) => {
        error!($fmt, $($arg)*);
        panic!($fmt, $($arg)*)
    };
}

pub struct Server<'a> {
    pub ip: String,
    filename: &'a str,
    conn: connection::Server,
}

#[derive(Clone, Copy)]
pub enum ShoopMode {
    Server,
    Client,
}

#[derive(Clone, Copy)]
pub enum ServerErr {
    SshEnvMissing = 0,
    FileMissing,
}

impl fmt::Display for ServerErr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let pretty = match self {
            &ServerErr::SshEnvMissing => {
                "SSH_CONNECTION env variable unset but required."
            }
            &ServerErr::FileMissing => {
                "File doesn't exist, ya dingus."
            }
        };
        write!(f, "{} {}", *self as i32, pretty)
    }
}

#[allow(dead_code)]
enum ShoopErrKind {
    Severed,
    Fatal,
}

struct ShoopErr {
    kind: ShoopErrKind,
    msg: Option<String>,
    finished: u64,
}

pub struct ShoopLogger {
    pid: i32,
    mode: ShoopMode,
}

impl log::Log for ShoopLogger {
    fn enabled(&self, metadata: &LogMetadata) -> bool {
        metadata.level() <= LogLevel::Info
    }

    fn log(&self, record: &LogRecord) {
        if self.enabled(record.metadata()) {
            let prefix_symbol = match record.level() {
                LogLevel::Error => "E".red().bold(),
                LogLevel::Warn => "W".yellow().bold(),
                LogLevel::Info => "I".normal(),
                LogLevel::Debug => "D".dimmed(),
                LogLevel::Trace => "T".dimmed(),
            };

            let pidinfo = match self.mode {
                ShoopMode::Server => format!("({}) ", self.pid),
                ShoopMode::Client => String::new(),
            };

            println!("{}[{}] {}", pidinfo, prefix_symbol, record.args());
        }
    }
}

impl ShoopLogger {
    pub fn init(mode: ShoopMode) -> Result<(), log::SetLoggerError> {
        log::set_logger(|max_log_level| {
            max_log_level.set(log::LogLevelFilter::Info);
            Box::new(ShoopLogger{ pid: unsafe { libc::getpid() }, mode: mode })
        })
    }
}

impl ShoopErr {
    pub fn new(kind: ShoopErrKind, msg: &str, finished: u64) -> ShoopErr {
        ShoopErr {
            kind: kind,
            msg: Some(String::from(msg)),
            finished: finished,
        }
    }

    #[allow(dead_code)]
    pub fn from(err: Error, finished: u64) -> ShoopErr {
        ShoopErr {
            kind: ShoopErrKind::Severed,
            msg: Some(format!("{:?}", err)),
            finished: finished,
        }
    }
}

impl<'a> Server<'a> {
    fn daemonize() {
        let stdout = Some(Path::new(&env::var("HOME").unwrap()).join(".shoop.log"));
        let stderr = stdout.clone();
        daemonize_redirect(stdout, stderr, ChdirMode::ChdirRoot).unwrap();
    }

    pub fn new(port_range: connection::PortRange, filename: &str) -> Result<Server, ServerErr> {
        let mut err: Option<ServerErr> = None;
        let sshconnstr = match env::var("SSH_CONNECTION") {
            Ok(s) => s.trim().to_owned(),
            Err(_) => {
                err = Some(ServerErr::SshEnvMissing);
                String::new()
            }
        };

        if !Path::new(filename).is_file() {
            err = Some(ServerErr::FileMissing);
        }

        match err {
            None => {
                let sshconn: Vec<&str> = sshconnstr.split(' ').collect();
                let ip = sshconn[2].to_owned();
                let key = secretbox::gen_key();
                let Key(keybytes) = key;
                let port = connection::Server::get_open_port(&port_range).unwrap();
                println!("shoop 0 {} {} {}", ip, port, keybytes.to_hex());
                Server::daemonize();
                info!("got request: serve \"{}\" on range {}", filename, port_range);
                info!("sent response: shoop 0 {} {} <key redacted>", ip, port);
                let conn = connection::Server::new(IpAddr::from_str(&ip).unwrap(), port, key);
                Ok(Server {
                    ip: ip,
                    conn: conn,
                    filename: filename,
                })
            }
            Some(e) => {
                println!("shooperr {}", e);
                Server::daemonize();
                info!("got request: serve \"{}\" on range {}", filename, port_range);
                error!("init error: {}", e);
                Err(e)
            }
        }
    }

    pub fn start(&self) {
        self.conn.listen().unwrap();

        let mut connection_count: usize = 0;
        info!("listening...");
        loop {
            info!("waiting for connection...");
            let (tx, rx) = mpsc::channel();
            if connection_count == 0 {
                thread::spawn(move || {
                    thread::sleep(Duration::from_secs(INITIAL_ACCEPT_TIMEOUT_SECONDS));
                    if let Err(_) = rx.try_recv() {
                        error!("timed out waiting for initial connection. exiting.");
                        std::process::exit(1);
                    }
                });
            }
            let client = match self.conn.accept() {
                Ok(client) => client,
                Err(e) => {
                    die!("unexpected error on sock accept() {:?}", e);
                }
            };
            connection_count += 1;
            tx.send(()).unwrap();
            info!("accepted connection with {:?}!", client.getpeer());
            match self.send_file(&client) {
                Ok(_) => {
                    info!("done sending file");
                    let _ = client.close();
                    break;
                }
                Err(ShoopErr { kind: ShoopErrKind::Severed, msg, finished }) => {
                    info!("connection severed, msg: {:?}, finished: {}", msg, finished);
                    let _ = client.close();
                    continue;
                }
                Err(ShoopErr { kind: ShoopErrKind::Fatal, msg, finished }) => {
                    die!("connection fatal, msg: {:?}, finished: {}", msg, finished);
                }
            }
        }
        info!("stopped listening.");
    }

    fn send_file(&self, client: &connection::ServerConnection) -> Result<(), ShoopErr> {
        let starthdr = match client.recv() {
            Ok(hdr) => hdr,
            Err(e) => return Err(ShoopErr::new(ShoopErrKind::Severed, &format!("{:?}", e), 0)),
        };
        let mut rdr = Cursor::new(starthdr);
        let offset = rdr.read_u64::<LittleEndian>().unwrap();
        let mut f = File::open(self.filename).unwrap();
        f.seek(SeekFrom::Start(offset)).unwrap();
        let metadata = f.metadata().unwrap();

        let remaining = metadata.len() - offset;
        info!("total {} bytes", remaining);

        let mut wtr = vec![];
        wtr.write_u64::<LittleEndian>(remaining).unwrap();
        match client.send(&wtr[..]) {
            Ok(()) => info!("wrote filesize header."),
            Err(e) => {
                return Err(ShoopErr::new(ShoopErrKind::Severed, &format!("{:?}", e), remaining))
            }
        }
        let mut payload = vec![0; 1300];
        f.seek(SeekFrom::Start(offset)).unwrap();
        info!("sending file...");
        loop {
            match f.read(&mut payload) {
                Ok(0) => {
                    break;
                }
                Ok(read) => {
                    if let Err(e) = client.send(&payload[0..read]) {
                        return Err(ShoopErr::new(ShoopErrKind::Severed,
                                                 &format!("{:?}", e),
                                                 remaining));
                    }
                }
                Err(e) => {
                    client.close().expect("Error closing stream");
                    die!("failed to read from file: {:?}", e);
                }
            }
        }

        client.close().expect("Error closing stream.");
        Ok(())
    }
}

pub fn download(remote_ssh_host: &str,
                port_range: connection::PortRange,
                remote_path: &str,
                local_path: PathBuf) {
    let cmd = format!("shoop -s '{}' -p {}", remote_path, port_range);

    overprint!(" - establishing SSH session...");
    assert!(command_exists("ssh"), "`ssh` is required!");
    let output = Command::new("ssh")
        .arg(remote_ssh_host.to_owned())
        .arg(cmd)
        .output()
        .unwrap_or_else(|e| {
            die!("failed to execute process: {}", e);
        });
    let response = String::from_utf8_lossy(&output.stdout).to_owned().trim().to_owned();
    if response.starts_with("shooperr ") {
        let errblock = &response["shooperr ".len()..];
        let (code, msg) = errblock.split_at(errblock.find(' ').unwrap());
        overprint!("");
        error!("Server error #{}:{}", code, msg);
        std::process::exit(1);
    }

    let info: Vec<&str> = response.split(' ').collect();
    if info.len() != 5 {
        die!("Unexpected response from server. Are you suuuuure shoop is setup on the server?");
    }

    let (magic, version, ip, port, keyhex) = (info[0], info[1], info[2], info[3], info[4]);
    overprint!(" - opening UDT connection...");
    if magic != "shoop" || version != "0" {
        die!("Unexpected response from server. Are you suuuuure shoop is setup on the server?");
    }

    let mut keybytes = [0u8; 32];
    keybytes.copy_from_slice(&keyhex.from_hex().unwrap()[..]);
    let key = Key(keybytes);
    let addr: SocketAddr = SocketAddr::from_str(&format!("{}:{}", ip, port)[..]).unwrap();
    let conn = connection::Client::new(addr, key);

    let mut offset = 0u64;
    let mut filesize = None;
    let start_ts = Instant::now();
    loop {
        match conn.connect() {
            Ok(()) => {
                overprint!(" - connection opened, shakin' hands, makin' frands");
            }
            Err(e) => {
                die!("errrrrrrr connecting to {}:{} - {:?}", ip, port, e);
            }
        }
        let mut wtr = vec![];
        wtr.write_u64::<LittleEndian>(offset).unwrap();
        if let Err(_) = conn.send(&wtr[..]) {
            conn.close().unwrap();
            continue;
        }


        if let Ok(msg) = conn.recv() {
            if msg.is_empty() {
                die!("failed to get filesize from server, probable timeout.");
            }
            let mut rdr = Cursor::new(msg);
            filesize = filesize.or_else(|| Some(rdr.read_u64::<LittleEndian>().unwrap()));
            overprint!("downloading {} ({:.1}MB)\n",
                       local_path.to_string_lossy(),
                       (filesize.unwrap() as f64) / (1024f64 * 1024f64));
            match recv_file(&conn, filesize.unwrap(), &local_path, offset) {
                Ok(_) => {
                    break;
                }
                Err(ShoopErr { kind: ShoopErrKind::Severed, finished, .. }) => {
                    println!("{}", " * [[SEVERED]]".yellow().bold());
                    offset = finished;
                }
                Err(ShoopErr { kind: ShoopErrKind::Fatal, msg, .. }) => {
                    die!("{:?}", msg);
                }
            }
        }
        let _ = conn.close();
    }

    let elapsed = start_ts.elapsed().as_secs();
    let fmt_time = if elapsed < 60 {
        format!("{}s", elapsed)
    } else if elapsed < 60 * 60 {
        format!("{}m{}s", elapsed / 60, elapsed % 60)
    } else {
        format!("{}h{}m{}s", elapsed / (60 * 60), elapsed / 60, elapsed % 60)
    };
    println!("shooped it all up in {}", fmt_time.green().bold());
}

fn command_exists(command: &str) -> bool {
    match Command::new("which").arg(command).output() {
        Ok(output) => output.status.success(),
        Err(_) => false,
    }
}

fn recv_file(conn: &connection::Client,
             filesize: u64,
             filename: &PathBuf,
             offset: u64)
             -> Result<(), ShoopErr> {
    let mut f = OpenOptions::new().write(true).create(true).truncate(false).open(filename).unwrap();
    f.seek(SeekFrom::Start(offset)).unwrap();
    let start = Instant::now();
    let mut ts = Instant::now();
    let mut total = offset;
    let mut speed_ts = Instant::now();
    let mut speed_total = total;
    let mut speed = 0u64;
    loop {
        let buf = try!(conn.recv()
            .map_err(|e| ShoopErr::new(ShoopErrKind::Severed, &format!("{:?}", e), total)));
        if buf.len() < 1 {
            return Err(ShoopErr::new(ShoopErrKind::Severed, "empty msg", total));
        }

        f.write_all(&buf[..]).unwrap();
        total += buf.len() as u64;
        let speed_elapsed = speed_ts.elapsed();
        if speed_elapsed > Duration::new(1, 0) {
            speed = ((total - speed_total) as f64 /
                     ((speed_elapsed.as_secs() as f64) +
                      (speed_elapsed.subsec_nanos() as f64) /
                      1_000_000_000f64)) as u64;
            speed_ts = Instant::now();
            speed_total = total;
        }
        let speedfmt = if speed < 1024 {
            format!("{} b/s", speed)
        } else if speed < 1024 * 1024 {
            format!("{} kb/s", speed / 1024)
        } else {
            format!("{:.1} MB/s", ((speed / 1024) as f64) / 1024f64)
        };

        if ts.elapsed() > Duration::new(0, 100_000_000) {
            overprint!("   {:.1}M / {:.1}M ({:.1}%) [ {} ]",
                       (total as f64) / (1024f64 * 1024f64),
                       (filesize as f64) / (1024f64 * 1024f64),
                       (total as f64) / (filesize as f64) * 100f64,
                       speedfmt);
            ts = Instant::now();
        }
        if total >= filesize {
            overprint!("   {0:.1}M / {0:.1}M (100%) [ avg {1:.1} MB/s ]\n",
                       (filesize as f64) / (1024f64 * 1024f64),
                       ((total - offset) / start.elapsed().as_secs() / 1024) as f64 / 1024f64);
            break;
        }
    }
    let _ = conn.close();
    Ok(())
}
