extern crate ring;
extern crate utp;

use byteorder::{ReadBytesExt, WriteBytesExt, LittleEndian};
use std::net::{UdpSocket, SocketAddr, IpAddr};
use std::str;
use std::fmt;
use std::io;
use std::io::{Cursor, ErrorKind, Write, Read};
use utp::{UtpListener, UtpStream};

// TODO config
pub const MAX_MESSAGE_SIZE: usize = 1024000;

pub mod crypto {
    use ring::aead;
    use ring::aead::{SealingKey, OpeningKey, Algorithm};
    use ring::rand::SystemRandom;
    static ALGORITHM: &'static Algorithm = &aead::AES_128_GCM;
    lazy_static! {
        static ref RAND: SystemRandom = SystemRandom::new();
    }

    pub struct Key {
        bytes: Vec<u8>,
        opening: OpeningKey,
        sealing: SealingKey,
    }

    impl Key {
        pub fn new(bytes: &[u8]) -> Key {
            Key {
                bytes: bytes.to_owned(),
                opening: OpeningKey::new(ALGORITHM, &bytes).unwrap(),
                sealing: SealingKey::new(ALGORITHM, &bytes).unwrap(),
            }
        }
    }

    impl Clone for Key {
        fn clone(&self) -> Key {
            Key::new(&self.bytes)
        }
    }

    #[derive(Clone)]
    pub struct Handler {
        _working_nonce_buf: [u8; 32],
        _working_seal_buf: Vec<u8>,
        key: Key,
    }


    pub fn gen_key() -> Vec<u8> {
        let mut keybytes = vec![0u8; ALGORITHM.key_len()];
        RAND.fill(&mut keybytes).unwrap();
        keybytes
    }

    impl Handler {
        pub fn new(key: &[u8]) -> Handler {
            Handler {
                _working_seal_buf: vec![0u8; super::MAX_MESSAGE_SIZE],
                _working_nonce_buf: [0u8; 32],
                key: Key::new(key),
            }
        }

        pub fn seal(&mut self, buf: &mut [u8], len: usize) -> Result<usize, ()> {
            let nonce_len = ALGORITHM.nonce_len();
            let max_suffix_len = ALGORITHM.max_overhead_len();

            assert!(nonce_len < u8::max_value() as usize,
                    "Uh, why is the nonce size this big?");

            assert!(len <= buf.len() - max_suffix_len,
                    "Buffer doesn't have enough suffix padding.");

            let mut nonce = &mut self._working_nonce_buf[..nonce_len];
            RAND.fill(&mut nonce).unwrap();

            let mut sealed = &mut self._working_seal_buf[..len + max_suffix_len];
            sealed[0..len].copy_from_slice(&buf[..len]);
            match aead::seal_in_place(&self.key.sealing,
                                      &nonce,
                                      &mut sealed,
                                      max_suffix_len,
                                      &[]) {
                Ok(seal_len) => {
                    buf[..nonce_len].copy_from_slice(&nonce[..]);
                    buf[nonce_len..nonce_len+seal_len].copy_from_slice(&sealed[..seal_len]);
                    Ok(nonce_len + seal_len)
                }
                Err(_) => {
                    Err(())
                }
            }
        }

        pub fn open(&mut self, buf: &mut [u8]) -> Result<usize, String> {
            let nonce_len = ALGORITHM.nonce_len();

            if buf.len() < nonce_len {
                return Err("msg not long enough to contain nonce".into());
            } else if buf.len() > super::MAX_MESSAGE_SIZE {
                return Err("max message size exceeded".into());
            }

            let nonce = &mut self._working_nonce_buf[..nonce_len];
            nonce.copy_from_slice(&buf[..nonce_len]);

            aead::open_in_place(&self.key.opening, &nonce, nonce_len, buf, &[])
                .map_err(|_| String::from("decrypt failed"))
        }
    }

    // Tests for the crypto module
    #[cfg(test)]
    mod test {

        #[test]
        fn raw_roundtrip() {
            use ring::aead;
            use ring::aead::{SealingKey, OpeningKey, Algorithm};
            use ring::rand::{SystemRandom, SecureRandom};

            let rng = SystemRandom::new();
            let mut key_bytes = vec![0u8; super::ALGORITHM.key_len()];
            let mut nonce_bytes = vec![0u8; super::ALGORITHM.nonce_len()];
            rng.fill(&mut key_bytes).unwrap();
            rng.fill(&mut nonce_bytes).unwrap();
            let key = SealingKey::new(super::ALGORITHM, &key_bytes).unwrap();

            let data = [1u8; 1350];
            let out_suffix_capacity = super::ALGORITHM.max_overhead_len();
            let mut in_out = vec![1u8; data.len() + out_suffix_capacity];
            aead::seal_in_place(&key, &nonce_bytes,
                                &mut in_out, out_suffix_capacity,
                                &[]).unwrap();

            let opening_key = OpeningKey::new(super::ALGORITHM, &key_bytes).unwrap();
            let len = aead::open_in_place(&opening_key, &nonce_bytes,
                                          0, &mut in_out, &[]).unwrap();

            assert_eq!(len, 1350);
            assert_eq!(&in_out[..len], &data[..]);
        }

        #[test]
        fn roundtrip() {
            use ::rand;
            use ::rand::distributions::{IndependentSample, Range};
            // generate some data, seal it, and then make sure it unseals to the same thing
            let mut rng = rand::thread_rng();
            let between = Range::new(10, 10000);

            let key = super::gen_key();
            let mut handler = super::Handler::new(&key);
            let data_size: usize = between.ind_sample(&mut rng);
            let mut data = vec![0u8; super::super::MAX_MESSAGE_SIZE];
            for i in 0..data_size {
                data[i] = rand::random();
            }

            let orig = data[..data_size].to_owned();

            let cipher_len = handler.seal(&mut data, data_size).unwrap();
            let decrypted_len = handler.open(&mut data[..cipher_len]).unwrap();
            assert_eq!(decrypted_len, data_size);
            assert_eq!(orig, &data[..decrypted_len], "original and decrypted don't match!");
        }

        #[test]
        fn key_sanity() {
            use std::collections::HashSet;

            let mut set: HashSet<Vec<u8>> = HashSet::with_capacity(10000);

            for _ in 0..10000 {
                let key = super::gen_key();
                assert!(set.insert(key));
            }
        }
    }

    #[cfg(all(feature = "nightly", test))]
    mod bench {
        extern crate test;
        const DATA_SIZE: usize = 1300;

        #[bench]
        fn bench_raw_seal(b: &mut test::Bencher) {
            use ring::aead;
            use ring::aead::{SealingKey, OpeningKey, Algorithm};
            use ring::rand::{SystemRandom, SecureRandom};

            let rng = SystemRandom::new();
            let mut key_bytes = vec![0u8; super::ALGORITHM.key_len()];
            let mut nonce_bytes = vec![0u8; super::ALGORITHM.nonce_len()];
            rng.fill(&mut key_bytes).unwrap();
            let key = SealingKey::new(super::ALGORITHM, &key_bytes).unwrap();

            let data = [1u8; DATA_SIZE];
            let out_suffix_capacity = super::ALGORITHM.max_overhead_len();
            let mut in_out = vec![1u8; data.len() + out_suffix_capacity];

            b.bytes = DATA_SIZE as u64;
            b.iter(|| {
                rng.fill(&mut nonce_bytes).unwrap();
                aead::seal_in_place(&key, &nonce_bytes, &mut in_out,
                                    out_suffix_capacity, &[]).unwrap()
            })
        }

        #[bench]
        fn bench_raw_open(b: &mut test::Bencher) {
            use ring::aead;
            use ring::aead::{SealingKey, OpeningKey, Algorithm};
            use ring::rand::{SystemRandom, SecureRandom};

            let rng = SystemRandom::new();
            let mut key_bytes = vec![0u8; super::ALGORITHM.key_len()];
            let mut nonce_bytes = vec![0u8; super::ALGORITHM.nonce_len()];
            rng.fill(&mut key_bytes).unwrap();
            rng.fill(&mut nonce_bytes).unwrap();
            let key = SealingKey::new(super::ALGORITHM, &key_bytes).unwrap();
            let opening_key = OpeningKey::new(super::ALGORITHM, &key_bytes).unwrap();

            let data = [1u8; DATA_SIZE];
            let out_suffix_capacity = super::ALGORITHM.max_overhead_len();
            let mut in_out = vec![1u8; data.len() + out_suffix_capacity];

            b.bytes = DATA_SIZE as u64;

            let sealed_len = aead::seal_in_place(&key, &nonce_bytes, &mut in_out,
                                                 out_suffix_capacity, &[]).unwrap();
            b.iter(|| aead::open_in_place(&opening_key, &nonce_bytes,
                                               0, &mut in_out, &[]))
        }

        #[bench]
        fn bench_seal(b: &mut test::Bencher) {
            let key = super::gen_key();
            let mut handler = super::Handler::new(&key);
            let mut buf = vec![0u8; super::super::MAX_MESSAGE_SIZE];
            b.bytes = DATA_SIZE as u64;
            b.iter(|| handler.seal(&mut buf, DATA_SIZE))
        }

        #[bench]
        fn bench_open(b: &mut test::Bencher) {
            let key = super::gen_key();
            let mut handler = super::Handler::new(&key);
            let mut buf = vec![0u8; super::super::MAX_MESSAGE_SIZE];
            let sealed_len = handler.seal(&mut buf, DATA_SIZE).unwrap();
            b.bytes = DATA_SIZE as u64;
            b.iter(|| handler.open(&mut buf[..sealed_len]))
        }
    }
}

fn send(sock: &mut UtpStream, crypto: &mut crypto::Handler, buf: &mut [u8], len: usize) -> io::Result<()> {
    // FIXME don't unwrap, create an Error struct that can handle everything
    if let Ok(sealed_len) = crypto.seal(buf, len) {
        let u32len = sealed_len as u32;
        let mut wtr = vec![];
        wtr.write_u32::<LittleEndian>(u32len).unwrap();
        try!(sock.write_all(&wtr));
        try!(sock.write_all(&buf[..u32len as usize]));
        Ok(())
    } else {
        Err(io::Error::new(ErrorKind::Other, "encryption failure"))
    }
}

fn recv(sock: &mut UtpStream, crypto: &mut crypto::Handler, buf: &mut [u8]) -> io::Result<usize> {
    let mut len_buf = vec![0u8; 4];
    try!(sock.read_exact(&mut len_buf)); // u32
    let mut rdr = Cursor::new(len_buf);
    let len = rdr.read_u32::<LittleEndian>().unwrap() as usize;

    try!(sock.read_exact(&mut buf[..len]));
    crypto.open(&mut buf[..len]).map_err(|_| {
        io::Error::new(ErrorKind::Other, "decryption failure")
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
    crypto: crypto::Handler,
    sock: UtpListener,
}

pub struct Client {
    sock: UtpStream,
    crypto: crypto::Handler,
}

pub struct ServerConnection {
    crypto: crypto::Handler,
    peer: SocketAddr,
    sock: UtpStream,
}

impl Client {
    pub fn connect(addr: SocketAddr, key: &[u8]) -> io::Result<Client> {
        Ok(Client {
            sock: try!(UtpStream::connect(addr)),
            crypto: crypto::Handler::new(key),
        })
    }
}

pub trait Transceiver {
    fn send(&mut self, buf: &mut [u8], len: usize) -> io::Result<()>;
    fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize>;
    fn close(&mut self) -> io::Result<()>;
}

impl Transceiver for Client {
    fn send(&mut self, buf: &mut [u8], len: usize) -> io::Result<()> {
        send(&mut self.sock, &mut self.crypto, buf, len)
    }

    fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        recv(&mut self.sock, &mut self.crypto, buf)
    }

    fn close(&mut self) -> io::Result<()> {
        self.sock.close()
    }
}

impl Transceiver for ServerConnection {
    fn send(&mut self, buf: &mut [u8], len: usize) -> io::Result<()> {
        send(&mut self.sock, &mut self.crypto, buf, len)
    }

    fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        recv(&mut self.sock, &mut self.crypto, buf)
    }

    fn close(&mut self) -> io::Result<()> {
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
        let sock = UtpListener::bind(SocketAddr::new(ip_addr, port)).unwrap();
        Server {
            sock: sock,
            ip_addr: ip_addr,
            port: port,
            crypto: crypto::Handler::new(key),
        }
    }

    pub fn accept(&mut self) -> io::Result<ServerConnection> {
        self.sock.accept().map(move |(sock, peer)| {
            ServerConnection {
                crypto: self.crypto.clone(),
                peer: peer,
                sock: UtpStream::from(sock),
            }
        })
    }
}

impl ServerConnection {
    pub fn getpeer(&self) -> SocketAddr {
        self.peer
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
