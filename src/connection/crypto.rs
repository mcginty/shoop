extern crate ring;

use byteorder::{WriteBytesExt, LittleEndian};
use ring::aead;
use ring::aead::{SealingKey, OpeningKey, Algorithm};
use ring::rand::{SecureRandom, SystemRandom};

const MAX_NONCE: u64 = ::std::u64::MAX;

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

#[derive(Default)]
pub struct Nonce {
    counter: u64,
}

impl Nonce {
    #[cfg(test)]
    pub fn starting_from(start: u64) -> Nonce {
        Nonce { counter: start }
    }

    pub fn next(&mut self) -> Result<Vec<u8>, ()> {
        if self.counter >= MAX_NONCE {
            Err(())
        } else {
            let mut nonce_bytes = Vec::with_capacity(12);
            nonce_bytes.write_u64::<LittleEndian>(self.counter).map_err(|_| ())?;
            nonce_bytes.extend_from_slice(&[0u8; 4]);
            self.counter += 1;

            Ok(nonce_bytes)
        }
    }
}

pub struct Handler {
    _working_nonce_buf: [u8; 32],
    _working_seal_buf: Vec<u8>,
    key: Key,
    nonce: Nonce,
}

pub fn gen_key() -> Vec<u8> {
    let mut keybytes = vec![0u8; ALGORITHM.key_len()];
    RAND.fill(&mut keybytes).unwrap();
    keybytes
}

impl Handler {
    pub fn new(key: &[u8]) -> Handler {
        debug!("👾  AEAD key len: {}", ALGORITHM.key_len());
        debug!("👾  AEAD nonce len: {}", ALGORITHM.nonce_len());
        debug!("👾  AEAD max overhead len: {}", ALGORITHM.tag_len());
        Handler {
            _working_seal_buf: vec![0u8; super::MAX_MESSAGE_SIZE],
            _working_nonce_buf: [0u8; 32],
            key: Key::new(key),
            nonce: Nonce::default(),
        }
    }

    pub fn seal(&mut self, buf: &mut [u8], len: usize) -> Result<usize, ()> {
        let nonce_len = ALGORITHM.nonce_len();
        let max_suffix_len = ALGORITHM.tag_len();

        debug_assert!(nonce_len < u8::max_value() as usize,
                "Uh, why is the nonce size this big?");

        assert!(len <= buf.len() - max_suffix_len,
                "Buffer doesn't have enough suffix padding.");

        let nonce = &mut self._working_nonce_buf[..nonce_len];
        let nonce_bytes = self.nonce.next().unwrap();
        nonce[..nonce_bytes.len()].copy_from_slice(&nonce_bytes);

        let mut sealed = &mut self._working_seal_buf[..len + max_suffix_len];
        sealed[0..len].copy_from_slice(&buf[..len]);
        match aead::seal_in_place(&self.key.sealing,
                                  aead::Nonce::try_assume_unique_for_key(nonce).unwrap(),
                                  aead::Aad::empty(),
                                  &mut sealed,
                                  max_suffix_len) {
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

        aead::open_in_place(&self.key.opening, aead::Nonce::try_assume_unique_for_key(nonce).unwrap(), aead::Aad::empty(), nonce_len, buf)
            .map(|buf| buf.len())
            .map_err(|_| String::from("decrypt failed"))
    }
}

// Tests for the crypto module
#[cfg(test)]
mod test {

    #[test]
    fn nonce_sanity() {
        let mut nonce = super::Nonce::default();
        let first = nonce.next().unwrap();
        let second = nonce.next().unwrap();
        assert!(first != second, "two nonces were the same! death! shame!");
    }

    #[test]
    fn nonce_overflow() {
        let mut nonce = super::Nonce::starting_from(super::MAX_NONCE - 1);
        if let Err(_) = nonce.next() {
            panic!("2^96 - 1 should be a valid nonce");
        }
        if let Ok(_) = nonce.next() {
            panic!("2^96 is not a valid nonce, it should overflow and fail.");
        }
    }

    #[test]
    fn raw_roundtrip() {
        use ring::aead;
        use ring::aead::{SealingKey, OpeningKey};
        use ring::rand::{SecureRandom, SystemRandom};

        let rng = SystemRandom::new();
        let mut key_bytes = vec![0u8; super::ALGORITHM.key_len()];
        let mut nonce_bytes = vec![0u8; super::ALGORITHM.nonce_len()];
        rng.fill(&mut key_bytes).unwrap();
        rng.fill(&mut nonce_bytes).unwrap();
        let key = SealingKey::new(super::ALGORITHM, &key_bytes).unwrap();

        let data = [1u8; 1350];
        let out_suffix_capacity = super::ALGORITHM.tag_len();
        let mut in_out = vec![1u8; data.len() + out_suffix_capacity];
        aead::seal_in_place(&key, aead::Nonce::try_assume_unique_for_key(&nonce_bytes).unwrap(), aead::Aad::empty(),
                            &mut in_out, out_suffix_capacity).unwrap();

        let opening_key = OpeningKey::new(super::ALGORITHM, &key_bytes).unwrap();
        let buf = aead::open_in_place(&opening_key, aead::Nonce::try_assume_unique_for_key(&nonce_bytes).unwrap(), aead::Aad::empty(),
                                      0, &mut in_out).unwrap();

        assert_eq!(buf.len(), 1350);
        assert_eq!(buf, &data[..]);
    }

    #[test]
    fn roundtrip() {
        use ::rand::{self, Rng};
        use ::rand::distributions::{Distribution, Uniform};
        // generate some data, seal it, and then make sure it unseals to the same thing
        let mut rng = rand::thread_rng();

        let key = super::gen_key();
        let mut handler = super::Handler::new(&key);
        let data_size: usize = rng.gen_range(10, 10000);
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

    #[test]
    fn arc_encryption_uniqueness() {
        use core::ops::DerefMut;
        use std::sync::{Arc, Mutex};

        let key = super::gen_key();
        let handler = Arc::new(Mutex::new(super::Handler::new(&key)));
        let handler2 = handler.clone();

        let mut data = vec![0u8; super::super::MAX_MESSAGE_SIZE];

        let first = {
            let mutex = &handler;
            let mut crypto = mutex.lock().unwrap();
            let cipher_len = crypto.deref_mut().seal(&mut data, 4096).unwrap();
            data[..cipher_len].to_owned()
        };
        let second = {
            let mutex = &handler2;
            let mut crypto = mutex.lock().unwrap();
            let cipher_len = crypto.deref_mut().seal(&mut data, 4096).unwrap();
            data[..cipher_len].to_owned()
        };

        println!("{:?}", &first);
        println!("{:?}", &second);
        assert!(first != second);
    }
}

#[cfg(all(feature = "nightly", test))]
mod bench {
    extern crate test;
    const DATA_SIZE: usize = 16384;

    #[bench]
    fn bench_nonce_output(b: &mut test::Bencher) {
        let mut nonce = super::Nonce { counter: 0 };
        b.bytes = 12; // kind of
        b.iter(|| {
            nonce.next()
        })
    }

    #[bench]
    fn bench_raw_seal(b: &mut test::Bencher) {
        use ring::aead;
        use ring::aead::SealingKey;
        use ring::rand::{SecureRandom, SystemRandom};

        let rng = SystemRandom::new();
        let mut key_bytes = vec![0u8; super::ALGORITHM.key_len()];
        let mut nonce_bytes = vec![0u8; super::ALGORITHM.nonce_len()];
        rng.fill(&mut key_bytes).unwrap();
        let key = SealingKey::new(super::ALGORITHM, &key_bytes).unwrap();

        let data = [1u8; DATA_SIZE];
        let out_suffix_capacity = super::ALGORITHM.tag_len();
        let mut in_out = vec![1u8; data.len() + out_suffix_capacity];

        b.bytes = DATA_SIZE as u64;
        b.iter(|| {
            rng.fill(&mut nonce_bytes).unwrap();
            aead::seal_in_place(&key, aead::Nonce::try_assume_unique_for_key(&nonce_bytes).unwrap(), aead::Aad::empty(), &mut in_out,
                                out_suffix_capacity).unwrap()
        })
    }

    #[bench]
    fn bench_raw_open(b: &mut test::Bencher) {
        use ring::aead;
        use ring::aead::{SealingKey, OpeningKey};
        use ring::rand::{SecureRandom, SystemRandom};

        let rng = SystemRandom::new();
        let mut key_bytes = vec![0u8; super::ALGORITHM.key_len()];
        let mut nonce_bytes = vec![0u8; super::ALGORITHM.nonce_len()];
        rng.fill(&mut key_bytes).unwrap();
        rng.fill(&mut nonce_bytes).unwrap();
        let key = SealingKey::new(super::ALGORITHM, &key_bytes).unwrap();
        let opening_key = OpeningKey::new(super::ALGORITHM, &key_bytes).unwrap();

        let data = [1u8; DATA_SIZE];
        let out_suffix_capacity = super::ALGORITHM.tag_len();
        let mut in_out = vec![1u8; data.len() + out_suffix_capacity];

        b.bytes = DATA_SIZE as u64;

        let sealed_len = aead::seal_in_place(&key, aead::Nonce::try_assume_unique_for_key(&nonce_bytes).unwrap(), aead::Aad::empty(), &mut in_out,
                                             out_suffix_capacity).unwrap();
        b.iter(|| { aead::open_in_place(&opening_key, aead::Nonce::try_assume_unique_for_key(&nonce_bytes).unwrap(), aead::Aad::empty(),
                                        0, &mut in_out[..sealed_len]).unwrap(); });
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
