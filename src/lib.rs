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

use connection::{PortRange, Transceiver};
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
const RECONNECT_ACCEPT_TIMEOUT_SECONDS: u64 = 21600;

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

pub type LocalTarget = PathBuf;
pub type RemoteTarget = (String, PathBuf);
#[derive(Clone)]
pub enum Target {
    Local(LocalTarget),
    Remote(RemoteTarget),
}

#[derive(Clone)]
enum TransferState {
    Send(LocalTarget, RemoteTarget),
    Receive(RemoteTarget, LocalTarget),
}

pub struct Client {
    port_range: PortRange,
    transfer_state: TransferState,
}

#[derive(Clone, Copy)]
pub enum ShoopMode {
    Server,
    Client,
}

#[derive(Clone, Copy)]
pub enum TransferMode {
    Send,
    Receive,
}

#[derive(Clone, Copy)]
pub enum ServerErr {
    SshEnv = 0,
    File,
}

impl fmt::Display for ServerErr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
         let pretty = match *self {
            ServerErr::SshEnv => {
                "SSH_CONNECTION env variable unset but required."
            }
            ServerErr::File => {
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

impl Target {
    pub fn from(s: String) -> Target {
        match s.find(':') {
            None => Target::Local(s.into()),
            Some(i) => {
                let owned = s.to_owned();
                let (first, second) = owned.split_at(i);
                if first.contains('/') {
                    Target::Local(s.into())
                } else {
                    Target::Remote((first.into(), (&second[1..]).into()))
                }
            }
        }
    }

    pub fn is_local(&self) -> bool {
        match *self {
            Target::Local(_) => true,
            _ => false,
        }
    }

    pub fn is_remote(&self) -> bool {
        !self.is_local()
    }

    fn looks_like_file_path(&self) -> bool {
        let target = self.clone();
        let path = match target {
            Target::Local(s) => s,
            Target::Remote((_, s)) => s,
        };
        Path::new(&path).file_name().is_some()
    }

    fn get_path(&self) -> PathBuf {
        let target = self.clone();
        let path = match target {
            Target::Local(s) => s,
            Target::Remote((_, s)) => s,
        };
        PathBuf::from(&path)
    }
}


impl<'a> Server<'a> {
    fn daemonize() {
        let stdout = Some(Path::new(&env::var("HOME").unwrap()).join(".shoop.log"));
        let stderr = stdout.clone();
        daemonize_redirect(stdout, stderr, ChdirMode::ChdirRoot).unwrap();
    }

    pub fn new(port_range: PortRange, filename: &str) -> Result<Server, ServerErr> {
        let mut err: Option<ServerErr> = None;
        let sshconnstr = match env::var("SSH_CONNECTION") {
            Ok(s) => s.trim().to_owned(),
            Err(_) => {
                err = Some(ServerErr::SshEnv);
                String::new()
            }
        };

        if !Path::new(filename).is_file() {
            err = Some(ServerErr::File);
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

    pub fn start(&self, mode: TransferMode) {
        self.conn.listen().unwrap();

        let mut connection_count: usize = 0;
        info!("listening...");
        loop {
            info!("waiting for connection...");
            let (tx, rx) = mpsc::channel();
            thread::spawn(move || {
                let (timeout, err) = if connection_count == 0 {
                    (INITIAL_ACCEPT_TIMEOUT_SECONDS,
                     "initial connection")
                } else {
                    (RECONNECT_ACCEPT_TIMEOUT_SECONDS,
                     "reconnect")
                };
                thread::sleep(Duration::from_secs(timeout));
                if let Err(_) = rx.try_recv() {
                    error!("timed out waiting for {}. exiting.",
                           err);
                    std::process::exit(1);
                }
            });
            let client = match self.conn.accept() {
                Ok(client) => client,
                Err(e) => {
                    die!("unexpected error on sock accept() {:?}", e);
                }
            };
            connection_count += 1;
            tx.send(()).unwrap();
            info!("accepted connection with {:?}!", client.getpeer());
            match mode {
                TransferMode::Send => {
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
                TransferMode::Receive => {
                    die!("receive not supported yet");
                    // match recv_file(&self.conn, filesize.unwrap(), &local_path, offset) {
                    //     Ok(_) => {
                    //         info!("done sending file");
                    //         let _ = client.close();
                    //         break;
                    //     }
                    //     Err(ShoopErr { kind: ShoopErrKind::Severed, msg, finished }) => {
                    //         info!("connection severed, msg: {:?}, finished: {}", msg, finished);
                    //         let _ = client.close();
                    //         continue;
                    //     }
                    //     Err(ShoopErr { kind: ShoopErrKind::Fatal, msg, finished }) => {
                    //         die!("connection fatal, msg: {:?}, finished: {}", msg, finished);
                    //     }
                    // }
                }
            }
        }
        info!("stopped listening.");
    }

    fn send_file<T: Transceiver>(&self, client: &T) -> Result<(), ShoopErr> {
        let buf = &mut [0u8; connection::MAX_MESSAGE_SIZE];
        let starthdr = match client.recv(buf) {
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

        if let Err(e) = client.recv(buf) {
            warn!("finished sending, but failed getting client confirmation");
            return Err(ShoopErr::new(ShoopErrKind::Severed,
                                     &format!("{:?}", e),
                                     remaining))
        }

        info!("got client finish confirmation.");

        client.close().expect("Error closing stream.");
        Ok(())
    }
}

impl Client {

    pub fn new(source: Target, dest: Target, port_range: PortRange)
            -> Result<Client, String> {
        if source.is_local() && dest.is_local() ||
            source.is_remote() && dest.is_remote() {
            return Err("source and dest can't both be local or remote".into());
        }

        if let Target::Local(path) = source.clone() {
            if Path::new(&path).is_file() {
                return Err("local source file doesn't exist or is a directory".into());
            }
        }

        if source.is_remote() && !source.looks_like_file_path() ||
            dest.is_remote() && !dest.looks_like_file_path() {
            return Err("remote target doesn't look like a normal \
                       file path (folders not supported)".into());
        }

        let final_dest = match dest.clone() {
            Target::Local(path) => {
                let source_path = source.get_path();
                let dest_path = Path::new(&path);
                let final_dest_path = if dest_path.is_dir() {
                    dest_path.join(source_path.file_name().unwrap())
                } else {
                    dest_path.to_path_buf()
                };
                Target::Local(final_dest_path)
            }
            Target::Remote(_) => dest
        };

        let state = if let Target::Local(s) = source {
            if let Target::Remote(d) = final_dest {
                TransferState::Send(s, d)
            } else {
                return Err("source and dest can't both be local".into());
            }
        } else if let Target::Remote(s) = source {
            if let Target::Local(d) = final_dest {
                TransferState::Receive(s, d)
            } else {
                return Err("source and dest can't both be remote".into());
            }
        } else {
            panic!("something in the assertions are wrong.");
        };

        Ok(Client {
            port_range: port_range,
            transfer_state: state
        })
    }

    pub fn start(&self) {
        let (host, cmd) = match self.transfer_state.clone() {
            TransferState::Send(..) => {
                panic!("sending unsupported");
            }
            TransferState::Receive((host, path), _) => {
                (host,
                 format!("shoop -s '{}' -p {}",
                         path.to_string_lossy(),
                         self.port_range))
            }
        };

        overprint!(" - establishing SSH session...");
        assert!(command_exists("ssh"), "`ssh` is required!");
        let output = Command::new("ssh")
            .arg(host)
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

        let start_ts = Instant::now();
        match self.transfer_state.clone() {
            TransferState::Send(..) => {
                die!("send not supported");
            }
            TransferState::Receive(_, dest_path) => {
                let mut offset = 0u64;
                let mut filesize = None;
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

                    let buf = &mut [0u8; connection::MAX_MESSAGE_SIZE];
                    if let Ok(msg) = conn.recv(buf) {
                        if msg.is_empty() {
                            die!("failed to get filesize from server, probable timeout.");
                        }
                        let mut rdr = Cursor::new(msg);
                        filesize = filesize.or_else(|| Some(rdr.read_u64::<LittleEndian>().unwrap()));
                        overprint!("downloading {} ({:.1}MB)\n",
                                   dest_path.to_string_lossy(),
                                   (filesize.unwrap() as f64) / (1024f64 * 1024f64));
                        match recv_file(&conn, filesize.unwrap(), Path::new(&dest_path), offset) {
                            Ok(_) => {
                                if let Err(_) = conn.send(&[0u8; 1]) {
                                    warn!("failed to send close signal to server");
                                }
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
            }
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
}

fn command_exists(command: &str) -> bool {
    match Command::new("which").arg(command).output() {
        Ok(output) => output.status.success(),
        Err(_) => false,
    }
}

fn recv_file<T: Transceiver>(conn: &T,
                             filesize: u64,
                             filename: &Path,
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
    let buf = &mut [0u8; connection::MAX_MESSAGE_SIZE];
    loop {
        let buf = try!(conn.recv(buf)
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
