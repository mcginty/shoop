use connection::PortRange;
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::str::FromStr;
use hex::FromHex;

lazy_static! {
    static ref SECURE_OPTS_MAP: HashMap<&'static str, &'static str> = {
        let mut m = HashMap::new();
        m.insert("Protocol", "2");
        m.insert("Ciphers", "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr");
        m.insert("KexAlgorithms", "curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256");
        m.insert("MACs", "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com");
        m
    };

    static ref SECURE_OPTS: Vec<String> = ssh_args_for_config(&SECURE_OPTS_MAP);
}

fn ssh_args_for_config(map: &HashMap<&'static str, &'static str>) -> Vec<String> {
    let mut args: Vec<String> = Vec::new();
    for (key, val) in map {
        args.push("-o".into());
        args.push(format!("{}={}", key, val));
    }
    args
}

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

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        Error::new(ErrorType::SshError,
                   format!("failed to execute ssh: {}", e))
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

    fn verify_command_exists(command: &str) -> Result<(), Error> {
        if let Ok(output) = Command::new("which").arg(command).output() {
            if output.status.success() {
                return Ok(());
            }
        }
        Err(Error::new(ErrorType::SshMissing, "`ssh` is required!"))
    }

    fn exec(&self, extra_args: &Vec<String>) -> Result<Output, Error> {
        try!(Self::verify_command_exists("ssh"));

        let cmd = format!("shoop -s '{}' -p {}",
                          self.path.to_string_lossy(),
                          self.port_range);
        debug!("👉  ssh {} {}", &self.hostname, cmd);
        let mut command = Command::new("ssh");
        for arg in extra_args {
            command.arg(&arg);
        }
        let output = try!(command.arg(&self.hostname)
               .arg(cmd)
               .output());

        if !output.status.success() {
            Err(Error::new(ErrorType::SshError, "ssh returned failure exit code"))
        } else {
            Ok(output)
        }
    }

    pub fn connect(&self) -> Result<Response, Error> {

        let output = match self.exec(&SECURE_OPTS) {
            Ok(output) => output,
            _ => {
                println!("\n");
                error!("strong SSH crypto appears to be unavailable.");
                error!("this session is sketch, and shoop may simply refuse to work in the future.\n");
                try!(self.exec(&Vec::new()))
            }
        };

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

        let keybytes = Vec::<u8>::from_hex(keyhex).unwrap();
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
