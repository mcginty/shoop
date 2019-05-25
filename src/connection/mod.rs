extern crate udt;

pub mod crypto;

use byteorder::{ReadBytesExt, WriteBytesExt, LittleEndian};
use core::ops::DerefMut;
use std::fmt;
use std::io::Cursor;
use std::net::{UdpSocket, SocketAddr, IpAddr};
use std::str;
use std::sync::{Arc, Mutex};
use udt::{UdtSocket, UdtError, UdtOpts, SocketType, SocketFamily};

// TODO config
const UDT_BUF_SIZE: i32 = 4096000;
pub const MAX_MESSAGE_SIZE: usize = 1024000;

fn new_udt_socket() -> UdtSocket {
    udt::init();
    let sock = UdtSocket::new(SocketFamily::AFInet, SocketType::Stream).unwrap();
    sock.setsockopt(UdtOpts::UDP_RCVBUF, UDT_BUF_SIZE).unwrap();
    sock.setsockopt(UdtOpts::UDP_SNDBUF, UDT_BUF_SIZE).unwrap();
    sock
}

trait ExactIO {
    fn send_exact(&self, buf: &[u8]) -> Result<(), UdtError>;
    fn recv_exact(&self, buf: &mut [u8], len: usize) -> Result<(), UdtError>;
}

impl ExactIO for UdtSocket {
    fn send_exact(&self, buf: &[u8]) -> Result<(), UdtError> {
        let mut total: usize = 0;
        while total < buf.len() {
            total += try!(self.send(&buf[total..])) as usize;
        }
        Ok(())
    }

    fn recv_exact(&self, buf: &mut [u8], len: usize) -> Result<(), UdtError> {
        let mut total: usize = 0;
        while total < len {
            let remaining = len - total;
            total += try!(self.recv(&mut buf[total..], remaining)) as usize;
        }
        Ok(())
    }
}

fn send(sock: &UdtSocket, crypto: &mut crypto::Handler, buf: &mut [u8], len: usize) -> Result<(), UdtError> {
    // FIXME don't unwrap, create an Error struct that can handle everything
    if let Ok(sealed_len) = crypto.seal(buf, len) {
        assert!(sealed_len <= u32::max_value() as usize, "single chunk must be 32-bit length");

        let mut wtr = vec![];
        wtr.write_u32::<LittleEndian>(sealed_len as u32).unwrap();
        wtr.extend_from_slice(&buf[..sealed_len]);
        sock.send_exact(&wtr)
    } else {
        Err(UdtError {
            err_code: -1,
            err_msg: "encryption failure".into(),
        })
    }
}

fn recv(sock: &UdtSocket, crypto: &mut crypto::Handler, buf: &mut [u8]) -> Result<usize, UdtError> {
    let mut len_buf = vec![0u8; 4];
    try!(sock.recv_exact(&mut len_buf, 4)); // u32
    let mut rdr = Cursor::new(len_buf);
    let len = rdr.read_u32::<LittleEndian>().unwrap() as usize;

    try!(sock.recv_exact(buf, len));
    crypto.open(&mut buf[..len]).map_err(|_| {
        UdtError {
            err_code: -1,
            err_msg: String::from("decryption failure"),
        }
    })
}

#[derive(Copy,Clone)]
pub struct PortRange {
    start: u16,
    end: u16,
}


pub struct Server {
    pub ip_addr: IpAddr,
    pub port: u16,
    crypto: Arc<Mutex<crypto::Handler>>,
    sock: UdtSocket,
}

pub struct Client {
    addr: SocketAddr,
    sock: UdtSocket,
    crypto: crypto::Handler,
}

pub struct ServerConnection {
    crypto: Arc<Mutex<crypto::Handler>>,
    sock: UdtSocket,
}

impl Client {
    pub fn new(addr: SocketAddr, key: &[u8]) -> Client {
        let sock = new_udt_socket();
        Client {
            addr: addr,
            sock: sock,
            crypto: crypto::Handler::new(key),
        }
    }

    pub fn connect(&self) -> Result<(), UdtError> {
        self.sock.connect(self.addr)
    }
}

pub trait Transceiver {
    fn send(&mut self, buf: &mut [u8], len: usize) -> Result<(), UdtError>;
    fn recv(&mut self, buf: &mut [u8]) -> Result<usize, UdtError>;
    fn close(&self) -> Result<(), UdtError>;
}

impl Transceiver for Client {
    fn send(&mut self, buf: &mut [u8], len: usize) -> Result<(), UdtError> {
        send(&self.sock, &mut self.crypto, buf, len)
    }

    fn recv(&mut self, buf: &mut [u8]) -> Result<usize, UdtError> {
        recv(&self.sock, &mut self.crypto, buf)
    }

    fn close(&self) -> Result<(), UdtError> {
        self.sock.close()
    }
}

impl Transceiver for ServerConnection {
    fn send(&mut self, buf: &mut [u8], len: usize) -> Result<(), UdtError> {
        let mutex = &self.crypto;
        let mut crypto = mutex.lock().unwrap();
        send(&self.sock, crypto.deref_mut(), buf, len)
    }

    fn recv(&mut self, buf: &mut [u8]) -> Result<usize, UdtError> {
        let mutex = &self.crypto;
        let mut crypto = mutex.lock().unwrap();
        recv(&self.sock, crypto.deref_mut(), buf)
    }

    fn close(&self) -> Result<(), UdtError> {
        self.sock.close()
    }
}

impl Server {
    pub fn get_open_port(range: &PortRange) -> Result<u16, ()> {
        for p in range.start..range.end {
            if let Ok(_) = UdpSocket::bind(&format!("0.0.0.0:{}", p)[..]) {
                return Ok(p);
            }
        }
        Err(())
    }

    pub fn new(ip_addr: IpAddr, port: u16, key: &[u8]) -> Server {
        let sock = new_udt_socket();
        sock.bind(SocketAddr::new(ip_addr, port)).unwrap();
        Server {
            sock: sock,
            ip_addr: ip_addr,
            port: port,
            crypto: Arc::new(Mutex::new(crypto::Handler::new(key))),
        }
    }

    pub fn listen(&self) -> Result<(), UdtError> {
        self.sock.listen(1)
    }

    pub fn accept(&self) -> Result<ServerConnection, UdtError> {
        self.sock.accept().map(move |(sock, _)| {
            ServerConnection {
                crypto: self.crypto.clone(),
                sock: sock,
            }
        })
    }
}

impl ServerConnection {
    pub fn getpeer(&self) -> Result<SocketAddr, UdtError> {
        self.sock.getpeername()
    }
}

impl PortRange {
    fn new(start: u16, end: u16) -> Result<PortRange, String> {
        if start > end {
            Err("range end must be greater than or equal to start".into())
        } else {
            Ok(PortRange {
                start: start,
                end: end,
            })
        }
    }

    pub fn from(s: &str) -> Result<PortRange, String> {
        let sections: Vec<&str> = s.split('-').collect();
        if sections.len() != 2 {
            return Err("Range must be specified in the form of \"<start>-<end>\"".into());
        }
        let (start, end) = (sections[0].parse::<u16>(), sections[1].parse::<u16>());
        if start.is_err() || end.is_err() {
            return Err("improperly formatted port range".into());
        }
        PortRange::new(start.unwrap(), end.unwrap())
    }
}

impl fmt::Display for PortRange {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}-{}", self.start, self.end)
    }
}
