#![cfg_attr(all(feature = "nightly", test), feature(test))]
#[macro_use]
extern crate log;
#[macro_use]
extern crate lazy_static;
extern crate chrono;
extern crate core;
extern crate libc;
extern crate pbr;
extern crate unix_daemonize;
extern crate byteorder;
extern crate udt;
extern crate ring;
extern crate colored;
extern crate hex;

// crates needed for unit tests
#[cfg(test)]
extern crate rand;

pub mod connection;
pub mod ssh;
pub mod file;
pub mod progress;

use byteorder::{ReadBytesExt, WriteBytesExt, LittleEndian};
use colored::*;
use connection::{PortRange, Transceiver};
use log::{Record, Level, Metadata};
use std::net::{SocketAddr, IpAddr};
use std::fs::File;
use std::io;
use std::io::{Cursor, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::{str, env, thread, fmt};
use std::str::FromStr;
use std::sync::mpsc;
use chrono::Utc;
use std::time::{Instant, Duration};
use progress::Progress;
use unix_daemonize::{daemonize_redirect, ChdirMode};
use file::ReadMsg;

// TODO config
const INITIAL_ACCEPT_TIMEOUT_SECONDS: u64 = 60;
const RECONNECT_ACCEPT_TIMEOUT_SECONDS: u64 = 21600;

macro_rules! overprint {
    ($fmt: expr) => {
        if log_enabled!(Level::Debug) {
            // println!($fmt);
        } else {
            print!(concat!("\x1b[2K\r", $fmt));
            std::io::stdout().flush().unwrap();
        }
    };
    ($fmt:expr, $($arg:tt)*) => {
        if log_enabled!(Level::Debug) {
            // println!($fmt, $($arg)*);
        } else {
            print!(concat!("\x1b[2K\r", $fmt), $($arg)*);
            std::io::stdout().flush().unwrap();
        }
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

pub struct Server {
    pub ip: String,
    filename: String,
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
pub enum LogVerbosity {
    Normal,
    Debug,
}

impl LogVerbosity {
    fn to_log_level(self, mode: ShoopMode) -> Level {
        match self {
            LogVerbosity::Debug => Level::Debug,
            LogVerbosity::Normal => {
                match mode {
                    ShoopMode::Server => Level::Info,
                    ShoopMode::Client => Level::Error,
                }
            }
        }
    }
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
enum ErrorKind {
    Severed,
    Fatal,
}

struct Error {
    kind: ErrorKind,
    msg: Option<String>,
    finished: u64,
}

pub struct ShoopLogger {
    pid: u32,
    mode: ShoopMode,
    log_level: Level,
}

impl log::Log for ShoopLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.log_level
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let prefix_symbol = match record.level() {
                Level::Error => "E".red().bold(),
                Level::Warn => "W".yellow().bold(),
                Level::Info => "I".normal(),
                Level::Debug => "D".dimmed(),
                Level::Trace => "T".dimmed(),
            };

            let pidinfo = match self.mode {
                ShoopMode::Server => format!("{} ({}) ",
                                             Utc::now().to_rfc2822(),
                                             self.pid),
                ShoopMode::Client => String::new(),
            };

            println!("{}[{}] {}", pidinfo, prefix_symbol, record.args());
        }
    }

    fn flush(&self) {}
}

impl ShoopLogger {
    pub fn init(mode: ShoopMode, verbosity: LogVerbosity) -> Result<(), log::SetLoggerError> {
        log::set_boxed_logger(Box::new(ShoopLogger {
            pid: std::process::id(),
            mode,
            log_level: verbosity.to_log_level(mode),
        }))
    }
}

impl Error {
    pub fn new(kind: ErrorKind, msg: &str, finished: u64) -> Error {
        Error {
            kind: kind,
            msg: Some(String::from(msg)),
            finished: finished,
        }
    }

    #[allow(dead_code)]
    pub fn from(err: io::Error, finished: u64) -> Error {
        Error {
            kind: ErrorKind::Severed,
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
            Target::Local(s) | Target::Remote((_, s)) => s,
        };
        Path::new(&path).file_name().is_some()
    }

    fn get_path(&self) -> PathBuf {
        let target = self.clone();
        let path = match target {
            Target::Local(s) | Target::Remote((_, s)) => s,
        };
        PathBuf::from(&path)
    }
}

impl fmt::Display for TransferState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let target = self.clone();
        let pretty = match target {
            TransferState::Send(l, (rh, rp)) => {
                format!("Send(Local({}) -> Remote({}:{}))",
                l.display(), rh, rp.display())
            }
            TransferState::Receive((rh, rp), l) => {
                format!("Receive(Remote({}:{}) -> Local({}))",
                rh, rp.display(), l.display())
            }
        };
        write!(f, "{}", pretty)
    }
}

impl Server {
    fn daemonize() {
        let stdout = Some(Path::new(&env::var("HOME").unwrap()).join(".shoop.log"));
        let stderr = stdout.clone();
        daemonize_redirect(stdout, stderr, ChdirMode::ChdirRoot).unwrap();
    }

    // TODO super basic
    fn expand_filename(s: &str) -> String {
        if s.starts_with("~/") {
            Path::new(&env::var("HOME").unwrap()).join(&s[2..])
                .to_str().unwrap().into()
        } else {
            s.into()
        }
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

        let expanded_filename = Server::expand_filename(filename);

        if !Path::new(&expanded_filename).is_file() {
            err = Some(ServerErr::File);
        }

        match err {
            None => {
                let sshconn: Vec<&str> = sshconnstr.split(' ').collect();
                let ip = sshconn[2].to_owned();
                let keybytes = connection::crypto::gen_key();
                let port = connection::Server::get_open_port(&port_range).unwrap();
                println!("shoop 0 {} {} {}", ip, port, hex::encode(&keybytes));
                Self::daemonize();
                info!("got request: serve \"{}\" on range {}", filename, port_range);
                info!("sent response: shoop 0 {} {} <key redacted>", ip, port);
                let conn = connection::Server::new(IpAddr::from_str(&ip).unwrap(), port, &keybytes);
                Ok(Server {
                    ip: ip,
                    conn: conn,
                    filename: expanded_filename,
                })
            }
            Some(e) => {
                println!("shooperr {}", e);
                Self::daemonize();
                info!("got request: serve \"{}\" on range {}", filename, port_range);
                error!("init error: {}", e);
                Err(e)
            }
        }
    }

    pub fn start(&mut self, mode: TransferMode) {
        self.conn.listen().unwrap();

        let mut connection_count: usize = 0;
        info!("listening...");
        loop {
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

            info!("waiting for connection...");
            let client = &mut match self.conn.accept() {
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
                    match self.send_file(client) {
                        Ok(_) => {
                            info!("done sending file");
                            let _ = client.close();
                            break;
                        }
                        Err(Error { kind: ErrorKind::Severed, msg, finished }) => {
                            info!("connection severed, msg: {:?}, finished: {}", msg, finished);
                            let _ = client.close();
                            continue;
                        }
                        Err(Error { kind: ErrorKind::Fatal, msg, finished }) => {
                            die!("connection fatal, msg: {:?}, finished: {}", msg, finished);
                        }
                    }
                }
                TransferMode::Receive => {
                    die!("receive not supported yet");
                }
            }
        }
        info!("stopped listening.");
    }

    fn recv_offset<T: Transceiver>(&mut self, client: &mut T) -> Result<u64, Error> {
        let mut buf = vec![0u8; 1024];
        match client.recv(&mut buf) {
            Ok(i) if i < 8 => return Err(Error::new(ErrorKind::Severed, &format!("msg too short"), 0)),
            Err(e) => return Err(Error::new(ErrorKind::Severed, &format!("0-length msg received. {:?}", e), 0)),
            _ => {}
        };
        let mut rdr = Cursor::new(buf);
        let offset = rdr.read_u64::<LittleEndian>().unwrap();
        Ok(offset)
    }

    fn send_remaining<T: Transceiver>(&mut self, client: &mut T, remaining: u64) -> Result<(), Error> {
        let mut buf = vec![0u8; 1024];
        let mut wtr = vec![];
        wtr.write_u64::<LittleEndian>(remaining).unwrap();
        buf[..wtr.len()].copy_from_slice(&wtr);
        client.send(&mut buf, wtr.len())
            .map_err(|e| Error::new(ErrorKind::Severed,
                                    &format!("failed to write filesize hdr. {:?}", e), remaining))
    }

    fn get_file_size(filename: &str) -> u64 {
        File::open(filename.to_owned()).unwrap()
             .metadata().unwrap()
             .len()
    }

    fn send_file<T: Transceiver>(&mut self, client: &mut T) -> Result<(), Error> {
        let mut buf = vec![0u8; connection::MAX_MESSAGE_SIZE];

        let offset = try!(self.recv_offset(client));
        info!("starting at offset {}", offset);

        let remaining = Server::get_file_size(&self.filename) - offset;
        info!("{} bytes remaining", remaining);

        try!(self.send_remaining(client, remaining));
        info!("sent remaining packet. sending file...");

        let reader = file::Reader::new(&self.filename, offset);
        loop {
            match reader.rx.recv() {
                Ok(ReadMsg::Finish) => {
                    break;
                }
                Ok(ReadMsg::Read(payload)) => {
                    buf[..payload.len()].copy_from_slice(&payload);
                    if let Err(e) = client.send(&mut buf, payload.len()) {
                        return Err(Error::new(ErrorKind::Severed,
                                                 &format!("{:?}", e),
                                                 remaining));
                    }
                }
                Err(_) | Ok(ReadMsg::Error) => {
                    client.close().expect("Error closing stream");
                    error!("failed to read from file");
                    panic!("failed to read from file");
                }
            }
        }

        if let Err(e) = client.recv(&mut buf[..]) {
            warn!("finished sending, but failed getting client confirmation");
            return Err(Error::new(ErrorKind::Severed,
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

        debug!("✍️  {}", state);

        Ok(Client {
            port_range: port_range,
            transfer_state: state
        })
    }

    pub fn start(&mut self, force_dl: bool) {
        let ssh = match self.transfer_state.clone() {
            TransferState::Send(..) => {
                panic!("sending unsupported");
            }
            TransferState::Receive((host, path), _) => {
                ssh::Connection::new(host, path, &self.port_range)
            }
        };

        overprint!(" - establishing SSH session...");

        let response = ssh.connect().unwrap_or_else(|e| {
            die!("ssh error: {}", e.msg);
        });

        debug!("init(version: {}, addr: {})",
               response.version, response.addr);

        let start_ts = Instant::now();
        let pb = Progress::new();
        match self.transfer_state.clone() {
            TransferState::Send(..) => {
                die!("send not supported");
            }
            TransferState::Receive(_, dest_path) => {
                self.receive(&dest_path,
                             force_dl,
                             response.addr,
                             &response.key,
                             &pb);
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
        pb.finish(format!("shooped it all up in {}\n", fmt_time.green().bold()));
    }

    fn confirm_overwrite() -> Result<(),()> {
        loop {
            print!("\n{} [y/n] ",
                   "file exists. overwrite?".yellow().bold());
            io::stdout().flush().expect("stdout flush fail");
            let mut input = String::new();
            io::stdin().read_line(&mut input).expect("stdio fail");
            let normalized = input.trim().to_lowercase();
            match normalized.as_ref() {
                "y" | "yes" | "yeah" | "heck yes" => break,
                "n" | "no" | "nah" | "heck naw" => return Err(()),
                "whatever" | "w/e" => {
                    println!("{}", "close enough.".green().bold());
                    break;
                },
                _ => println!("answer 'y' or 'n'.")
            }
        }
        Ok(())
    }

    fn receive(&mut self,
               dest_path: &PathBuf,
               force_dl: bool,
               addr: SocketAddr,
               keybytes: &[u8],
               pb: &Progress) {
        let mut offset = 0u64;
        let mut filesize = None;
        let path = Path::new(dest_path);
        if path.is_file() && !force_dl && Client::confirm_overwrite().is_err() {
            error!("sheepishly avoiding overwriting your data. you're welcome, jeez.");
            std::process::exit(0);
        }

        loop {
            overprint!(" - opening UDT connection...");
            let mut conn = connection::Client::new(addr, &keybytes);
            match conn.connect() {
                Ok(()) => {
                    overprint!(" - connection opened, shakin' hands, makin' frands");
                    info!("👍  UDT connection established")
                }
                Err(e) => {
                    die!("errrrrrrr connecting to {}:{} - {:?}", addr.ip(), addr.port(), e);
                }
            }
            let mut buf = vec![0u8; connection::MAX_MESSAGE_SIZE];
            let mut wtr = vec![];
            wtr.write_u64::<LittleEndian>(offset).unwrap();
            buf[..wtr.len()].copy_from_slice(&wtr);
            debug!("👉  offset({})", offset);
            if let Err(e) = conn.send(&mut buf, wtr.len()) {
                error!("{:?}", e);
                conn.close().unwrap();
                continue;
            }

            if let Ok(len) = conn.recv(&mut buf[..]) {
                if len != 8 {
                    error!("failed to get filesize from server, probable timeout.");
                    std::process::exit(1);
                }
                let mut rdr = Cursor::new(buf);
                let remaining = rdr.read_u64::<LittleEndian>().unwrap();
                debug!("👈  remaining({})", remaining);
                filesize = filesize.or_else(|| {
                    debug!("✍️  set total filesize to {}", remaining);
                    Some(remaining)
                });
                if filesize.unwrap() - remaining != offset {
                    error!("it seems the server filesize has changed. dying.");
                    std::process::exit(1);
                }
                buf = rdr.into_inner();
                pb.size(filesize.unwrap());
                pb.add(offset);
                pb.message(format!("{}  ",
                           dest_path.file_name().unwrap().to_string_lossy().blue()));
                match recv_file(&mut conn,
                                filesize.unwrap(),
                                path,
                                offset,
                                &pb) {
                    Ok(_) => {
                        debug!("👉  finish packet");
                        pb.message(format!("{} (done, sending confirmation)  ",
                                   dest_path.file_name().unwrap().to_string_lossy().green()));
                        buf[0] = 0;
                        if let Err(e) = conn.send(&mut buf, 1) {
                            warn!("failed to send close signal to server: {:?}", e);
                        }
                        pb.message(format!("{}  ",
                                   dest_path.file_name().unwrap().to_string_lossy().green()));
                        let _ = conn.close();
                        break;
                    }
                    Err(Error { kind: ErrorKind::Severed, finished, .. }) => {
                        pb.message(format!("{}", "[[conn severed]] ".yellow().bold()));
                        offset = finished;
                    }
                    Err(Error { kind: ErrorKind::Fatal, msg, .. }) => {
                        die!("{:?}", msg);
                    }
                }
            }
            let _ = conn.close();
        }
    }
}

fn recv_file<T: Transceiver>(conn: &mut T,
                             filesize: u64,
                             filename: &Path,
                             offset: u64,
                             pb: &Progress)
             -> Result<(), Error> {
    let f = file::Writer::new(filename.to_path_buf());
    f.seek(SeekFrom::Start(offset));
    debug!("✍️  seeking to pos {} in {}", offset, filename.display());
    let mut total = offset;
    let buf = &mut [0u8; connection::MAX_MESSAGE_SIZE];
    loop {
        let len = match conn.recv(buf) {
            Ok(len) if len > 0 => {
                len
            }
            Ok(_) => {
                f.close();
                warn!("\n\nempty msg, severing\n");
                return Err(Error::new(ErrorKind::Severed,
                                         "empty msg", total))
            }
            Err(e) => {
                f.close();
                warn!("\n\nUDT err, severing");
                return Err(Error::new(ErrorKind::Severed,
                                         &format!("{:?}", e), total))
            }
        };

        total += len as u64;
        pb.add(len as u64);
        f.write_all(buf[..len].to_owned());

        if total >= filesize {
            break;
        }
    }
    f.close();
    debug!("");
    debug!("👾  file writing thread joined and closed");
    Ok(())
}

