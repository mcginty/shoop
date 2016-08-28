extern crate ring;
extern crate udt;

use std::net::{UdpSocket, SocketAddr, IpAddr};
use std::str;
use std::fmt;
use udt::{UdtSocket, UdtError, UdtOpts, SocketType, SocketFamily};
use ring::aead;
use ring::rand;

// TODO config
const UDT_BUF_SIZE: i32 = 4096000;
pub const MAX_MESSAGE_SIZE: usize = 1024000;

pub mod crypto {
    use ring::aead;
    use ring::aead::{SealingKey, OpeningKey, Algorithm};
    use ring::rand::{SystemRandom, SecureRandom};
    static ALGORITHM: &'static Algorithm = &aead::CHACHA20_POLY1305;

    pub struct Handler {
        _working_buf: [u8; super::MAX_MESSAGE_SIZE],
        rand: SystemRandom,
        opening_key: OpeningKey,
        sealing_key: SealingKey,
    }

    pub fn gen_key() -> Vec<u8> {
        let rand = SystemRandom::new();
        let mut keybytes = vec![0u8; ALGORITHM.key_len()];
        rand.fill(&mut keybytes);
        keybytes
    }

    impl Handler {
        pub fn new(key: &[u8]) -> Handler {
            Handler {
                _working_buf: [0u8; super::MAX_MESSAGE_SIZE],
                rand: SystemRandom::new(),
                opening_key: aead::OpeningKey::new(ALGORITHM, key).unwrap(),
                sealing_key: aead::SealingKey::new(ALGORITHM, key).unwrap(),
            }
        }

        pub fn seal(&mut self, buf: &mut [u8], len: usize) -> Result<usize, ()> {
            let nonce_len = ALGORITHM.nonce_len();
            let max_suffix_len = ALGORITHM.max_overhead_len();

            assert!(nonce_len < u8::max_value() as usize,
                    "Uh, why is the nonce size this big?");

            assert!(len <= buf.len() - max_suffix_len,
                    "Buffer doesn't have enough suffix padding.");

            let mut nonce = vec![0u8; nonce_len];
            self.rand.fill(&mut nonce).unwrap();

            let mut sealed = vec![0u8; len + max_suffix_len];
            sealed[0..len].copy_from_slice(&buf[..len]);
            match aead::seal_in_place(&self.sealing_key,
                                      &nonce,
                                      &mut sealed,
                                      max_suffix_len,
                                      &[]) {
                Ok(seal_len) => {
                    buf[..nonce_len].copy_from_slice(&nonce[..]);
                    buf[nonce_len..nonce_len+seal_len].copy_from_slice(&sealed[..seal_len]);
                    Ok(nonce_len + seal_len)
                }
                Err(e) => {
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
            let nonce = buf[..nonce_len].to_owned();
            self._working_buf[..buf.len()-nonce_len].copy_from_slice(&buf[nonce_len..]);

            match aead::open_in_place(&self.opening_key, &nonce, 0, &mut self._working_buf[..buf.len()-nonce_len], &[]) {
                Ok(opened_len) => {
                    buf[..opened_len].copy_from_slice(&self._working_buf[..opened_len]);
                    Ok(opened_len)
                }
                Err(_) => {
                    Err("decrypt failed".into())
                }
            }

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

        //#[test]
        //fn key_sanity() {
        //    use std::collections::HashSet;
        //    use sodiumoxide::crypto::secretbox;
        //    use sodiumoxide::crypto::secretbox::xsalsa20poly1305::Key;

        //    let mut set: HashSet<[u8;32]> = HashSet::with_capacity(10000);

        //    for _ in 0..10000 {
        //        let key = secretbox::gen_key();
        //        let Key(keybytes) = key;
        //        assert!(set.insert(keybytes));
        //    }
        //}

        //#[test]
        //fn nonce_sanity() {
        //    use std::collections::HashSet;
        //    use sodiumoxide::crypto::secretbox;
        //    use sodiumoxide::crypto::secretbox::xsalsa20poly1305::Nonce;

        //    let mut set: HashSet<[u8;24]> = HashSet::with_capacity(10000);

        //    for _ in 0..10000 {
        //        let nonce = secretbox::gen_nonce();
        //        let Nonce(noncebytes) = nonce;
        //        assert!(set.insert(noncebytes));
        //    }
        //}
    }

    // #[cfg(all(feature = "nightly", test))]
    // mod bench {
    //    extern crate test;
    //
    //    #[bench]
    //    fn bench_seal(b: &mut test::Bencher) {
    //        use sodiumoxide::crypto::secretbox;
    //        let key = secretbox::gen_key();
    //        b.iter(move || super::seal(&[0; 1300], &key))
    //    }
    //
    //    #[bench]
    //    fn bench_gen_key(b: &mut test::Bencher) {
    //        use sodiumoxide::crypto::secretbox;
    //        b.iter(|| secretbox::gen_key());
    //    }
    // }
}

fn new_udt_socket() -> UdtSocket {
    udt::init();
    let sock = UdtSocket::new(SocketFamily::AFInet, SocketType::Datagram).unwrap();
    sock.setsockopt(UdtOpts::UDP_RCVBUF, UDT_BUF_SIZE).unwrap();
    sock.setsockopt(UdtOpts::UDP_SNDBUF, UDT_BUF_SIZE).unwrap();
    sock
}

fn send(sock: &UdtSocket, key: &aead::SealingKey, buf: &mut [u8], len: usize) -> Result<(), UdtError> {
    unimplemented!();
    // FIXME don't unwrap, create an Error struct that can handle everything
    // if let Ok(sealed_len) = crypto::seal(buf, len, key) {
    //     sock.sendmsg(&buf[..sealed_len]).map(|_| ())
    // } else {
    //     Err(UdtError {
    //         err_code: -1,
    //         err_msg: "encryption failure".into(),
    //     })
    // }
}

fn recv(sock: &UdtSocket, key: &aead::OpeningKey, buf: &mut [u8]) -> Result<usize, UdtError> {
    unimplemented!();
    // let size = try!(sock.recvmsg(buf));
    // crypto::open(&mut buf[..size], key).map_err(|_| {
    //     UdtError {
    //         err_code: -1,
    //         err_msg: String::from("decryption failure"),
    //     }
    // })
}

pub struct PortRange {
    start: u16,
    end: u16,
}

pub trait Transceiver {
    fn send(&self, buf: &[u8]) -> Result<(), UdtError>;
    fn recv(&self, buf: &mut [u8]) -> Result<usize, UdtError>;
    fn close(&self) -> Result<(), UdtError>;
}

pub struct Server {
    pub ip_addr: IpAddr,
    pub port: u16,
    crypto: crypto::Handler,
    sock: UdtSocket,
}

pub struct Client {
    addr: SocketAddr,
    sock: UdtSocket,
    crypto: crypto::Handler,
}

pub struct ServerConnection<'a> {
    crypto: &'a crypto::Handler,
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

impl Transceiver for Client {
    fn send(&self, buf: &[u8]) -> Result<(), UdtError> {
        unimplemented!();
        // send(&self.sock, &self.sealing_key, buf)
    }

    fn recv(&self, buf: &mut [u8]) -> Result<usize, UdtError> {
        unimplemented!();
        // recv(&self.sock, &self.opening_key, buf)
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
            crypto: crypto::Handler::new(key),
        }
    }

    pub fn listen(&self) -> Result<(), UdtError> {
        self.sock.listen(2)
    }

    pub fn accept(&self) -> Result<ServerConnection, UdtError> {
        self.sock.accept().map(|(sock, _)| {
            ServerConnection {
                crypto: &self.crypto,
                sock: sock,
            }
        })
    }
}

impl<'a> ServerConnection<'a> {
    pub fn getpeer(&self) -> Result<SocketAddr, UdtError> {
        self.sock.getpeername()
    }
}

impl<'a> Transceiver for ServerConnection<'a> {
    fn send(&self, buf: &[u8]) -> Result<(), UdtError> {
        unimplemented!();
        // send(&self.sock, self.key, buf)
    }

    fn recv(&self, buf: &mut [u8]) -> Result<usize, UdtError> {
        unimplemented!();
        // recv(&self.sock, self.key, buf)
    }

    fn close(&self) -> Result<(), UdtError> {
        self.sock.close()
    }
}

impl<'a> PortRange {
    fn new(start: u16, end: u16) -> Result<PortRange, &'a str> {
        if start > end {
            Err("range end must be greater than or equal to start")
        } else {
            Ok(PortRange {
                start: start,
                end: end,
            })
        }
    }

    pub fn from(s: &str) -> Result<PortRange, &'a str> {
        let sections: Vec<&str> = s.split('-').collect();
        if sections.len() != 2 {
            return Err("Range must be specified in the form of \"<start>-<end>\"");
        }
        let (start, end) = (sections[0].parse::<u16>(), sections[1].parse::<u16>());
        if start.is_err() || end.is_err() {
            return Err("improperly formatted port range");
        }
        PortRange::new(start.unwrap(), end.unwrap())
    }
}

impl fmt::Display for PortRange {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}-{}", self.start, self.end)
    }
}
