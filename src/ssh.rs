extern crate rustc_serialize;

use connection::PortRange;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Command;
use std::str::FromStr;
use rustc_serialize::hex::FromHex;

pub struct Connection {
    hostname: String,
    path: PathBuf,
    port_range: PortRange,
}

pub struct Response {
    pub version: usize,
    pub addr: SocketAddr,
    pub key: Vec<u8>,
}

pub struct Error {
    pub error_type: ErrorType,
    pub msg: String,
}

pub enum ErrorType {
    SshMissing,
    SshError,
    Server(usize),
    BadServerResponse
}

impl Error {
    fn new<S: Into<String>>(error_type: ErrorType, msg: S) -> Error {
        Error {
            error_type: error_type,
            msg: msg.into(),
        }
    }
}

impl Connection {
    pub fn new<S: Into<String>>(hostname: S, path: PathBuf, port_range: &PortRange) -> Connection {
        Connection {
            hostname: hostname.into(),
            path: path,
            port_range: port_range.to_owned(),
        }
    }

    fn command_exists(command: &str) -> bool {
        match Command::new("which").arg(command).output() {
            Ok(output) => output.status.success(),
            Err(_) => false,
        }
    }

    pub fn connect(&self) -> Result<Response, Error> {
        if !Connection::command_exists("ssh") {
            return Err(Error::new(ErrorType::SshMissing, "`ssh` is required!"));
        }

        let cmd = format!("shoop -s '{}' -p {}",
                          self.path.to_string_lossy(),
                          self.port_range);
        debug!("👉  ssh {} {}", &self.hostname, cmd);
        let output = try!(Command::new("ssh")
            .arg(&self.hostname)
            .arg(cmd)
            .output()
            .map_err(|e| {
                Error::new(ErrorType::SshError,
                           format!("failed to execute process: {}", e))
            }));

        let raw_response = try!(String::from_utf8(output.stdout).map_err(|e| {
            Error::new(ErrorType::BadServerResponse,
                       format!("couldn't decode server response: {}", e))
        }));

        let response = raw_response.trim();

        if response.starts_with("shooperr ") {
            let errblock = &response["shooperr ".len()..];
            let (code, msg) = errblock.split_at(errblock.find(' ').unwrap());
            let code_int = try!(code.parse::<usize>().map_err(|_| {
                Error::new(ErrorType::BadServerResponse,
                           format!("server gave bad error code: {}", code))
            }));

            return Err(Error::new(ErrorType::Server(code_int), msg));
        }

        let info: Vec<&str> = response.split(' ').collect();
        if info.len() != 5 {
            return Err(Error::new(ErrorType::BadServerResponse,
                                  format!("{}\n{}: {}",
                                          "unexpected response length from server",
                                          "server said",
                                          response)));
        }

        let (magic, version, ip, port, keyhex) = (info[0], info[1], info[2], info[3], info[4]);
        if magic != "shoop" {
            return Err(Error::new(ErrorType::BadServerResponse,
                                  "unexpected response start from server"));
        }

        let version_code = try!(version.parse::<usize>().map_err(|_| {
            Error::new(ErrorType::BadServerResponse,
                       "unparseable version")
        }));

        if version_code != 0 {
            return Err(Error::new(ErrorType::BadServerResponse,
                                  "unsupported protocol version"));
        }

        let mut keybytes = Vec::with_capacity(32);
        keybytes.extend_from_slice(&keyhex.from_hex().unwrap()[..]);
        let addr: SocketAddr = try!(SocketAddr::from_str(&format!("{}:{}", ip, port)[..])
            .map_err(|_| {
                Error::new(ErrorType::BadServerResponse,
                           "ip/port server sent aren't nice looking")
            }));

        Ok(Response {
            version: version_code,
            addr: addr,
            key: keybytes,
        })
    }
}
