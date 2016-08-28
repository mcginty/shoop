#![cfg_attr(all(feature = "nightly", test), feature(test))]
#[macro_use]
extern crate log;
extern crate libc;
extern crate pbr;
extern crate getopts;
extern crate unix_daemonize;
extern crate byteorder;
extern crate udt;
extern crate ring;
extern crate time;
extern crate rustc_serialize;
extern crate colored;

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
use log::{LogRecord, LogLevel, LogMetadata};
use std::net::{SocketAddr, IpAddr};
use std::fs::File;
use std::io;
use std::io::{Cursor, Error, Seek, SeekFrom, Read, Write};
use std::path::{Path, PathBuf};
use std::{str, env, thread, fmt};
use std::str::FromStr;
use std::sync::mpsc;
use std::time::{Instant, Duration};
use progress::Progress;
use rustc_serialize::hex::ToHex;
use unix_daemonize::{daemonize_redirect, ChdirMode};
use file::ReadMsg;

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
                println!("shoop 0 {} {} {}", ip, port, keybytes.to_hex());
                Server::daemonize();
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
        let mut buf = Vec::with_capacity(connection::MAX_MESSAGE_SIZE);
        let recv_len = match client.recv(&mut buf[..]) {
            Ok(hdr) => hdr,
            Err(e) => return Err(ShoopErr::new(ShoopErrKind::Severed, &format!("{:?}", e), 0)),
        };
        let mut rdr = Cursor::new(buf);
        let offset = rdr.read_u64::<LittleEndian>().unwrap();
        buf = rdr.into_inner();
        let mut f = File::open(self.filename.clone()).unwrap();
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

        let reader = file::Reader::new(self.filename.clone());
        let mut payload = vec![0; 1300];
        info!("sending file...");
        loop {
            match reader.rx.recv() {
                Ok(ReadMsg::Finish) => {
                    break;
                }
                Ok(ReadMsg::Read(payload)) => {
                    if let Err(e) = client.send(&payload[..]) {
                        return Err(ShoopErr::new(ShoopErrKind::Severed,
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

    pub fn start(&self, force_dl: bool) {
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
            error!("ssh error: {}", e.msg);
            std::process::exit(1);
        });

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
            print!("\n{}[y/n] ",
                   "file exists. overwrite? ".yellow().bold());
            io::stdout().flush().expect("stdout flush fail");
            let mut input = String::new();
            io::stdin().read_line(&mut input).expect("stdio fail");
            let normalized = input.trim().to_lowercase();
            if normalized == "y" ||
               normalized == "yes" ||
               normalized == "yeah" ||
               normalized == "heck yes" {
                break;
            } else if normalized == "whatever" ||
                      normalized == "w/e" {
                println!("{}", "close enough.".green().bold());
                break;
            } else if normalized == "n" ||
                      normalized == "no" ||
                      normalized == "nah" ||
                      normalized == "heck naw" {
                return Err(())
            } else {
                println!("answer 'y' or 'n'.")
            }
        }
        Ok(())
    }

    fn receive(&self,
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
            let conn = connection::Client::new(addr, &keybytes);
            match conn.connect() {
                Ok(()) => {
                    overprint!(" - connection opened, shakin' hands, makin' frands");
                }
                Err(e) => {
                    die!("errrrrrrr connecting to {}:{} - {:?}", addr.ip(), addr.port(), e);
                }
            }
            let mut wtr = vec![];
            wtr.write_u64::<LittleEndian>(offset).unwrap();
            if let Err(_) = conn.send(&wtr[..]) {
                conn.close().unwrap();
                continue;
            }

            let mut buf = Vec::with_capacity(connection::MAX_MESSAGE_SIZE);
            if let Ok(len) = conn.recv(&mut buf[..]) {
                if len == 0 {
                    die!("failed to get filesize from server, probable timeout.");
                }
                let mut rdr = Cursor::new(buf);
                filesize = filesize.or_else(|| Some(rdr.read_u64::<LittleEndian>().unwrap()));
                pb.size(filesize.unwrap());
                pb.message(format!("{}  ",
                           dest_path.file_name().unwrap().to_string_lossy().blue()));
                match recv_file(&conn,
                                filesize.unwrap(),
                                path,
                                offset,
                                &pb) {
                    Ok(_) => {
                        pb.message(format!("{} (done, sending confirmation)  ",
                                   dest_path.file_name().unwrap().to_string_lossy().green()));
                        if let Err(e) = conn.send(&[0u8; 1]) {
                            warn!("failed to send close signal to server: {:?}", e);
                        }
                        pb.message(format!("{}  ",
                                   dest_path.file_name().unwrap().to_string_lossy().green()));
                        let _ = conn.close();
                        break;
                    }
                    Err(ShoopErr { kind: ShoopErrKind::Severed, finished, .. }) => {
                        pb.message(format!("{}", "[[conn severed]] ".yellow().bold()));
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

fn recv_file<T: Transceiver>(conn: &T,
                             filesize: u64,
                             filename: &Path,
                             offset: u64,
                             pb: &Progress)
             -> Result<(), ShoopErr> {
    let f = file::Writer::new(filename.to_path_buf());
    f.seek(SeekFrom::Start(offset));
    let mut total = offset;
    let mut packet_count = 0u64;
    let mut elapsed_bytes = 0u64;
    let buf = &mut [0u8; connection::MAX_MESSAGE_SIZE];
    loop {
        let len = try!(conn.recv(buf)
            .map_err(|e| ShoopErr::new(ShoopErrKind::Severed, &format!("{:?}", e), total)));
        if len < 1 {
            return Err(ShoopErr::new(ShoopErrKind::Severed, "empty msg", total));
        }

        total += len as u64;
        elapsed_bytes += len as u64;
        if packet_count % 8 == 0 {
            pb.add(elapsed_bytes);
            elapsed_bytes = 0;
        }
        packet_count += 1;
        f.write_all(buf[..len].to_owned());

        if total >= filesize {
            pb.add(elapsed_bytes);
            break;
        }
    }
    f.close();
    Ok(())
}

