use std::sync::mpsc;
use std::thread;
use std::path::PathBuf;
use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write, Read};
use std::time::{Duration, Instant};

pub struct Writer {
    thread: thread::JoinHandle<()>,
    tx: mpsc::SyncSender<WriteMsg>,
}

pub struct Reader {
    pub rx: mpsc::Receiver<ReadMsg>,
}

pub enum WriteMsg {
    Seek(SeekFrom),
    Write(Vec<u8>),
    Finish,
}

pub enum ReadMsg {
    Read(Vec<u8>),
    Finish,
    Error,
}

impl Writer {
    pub fn new(filename: PathBuf) -> Writer {
        let (tx, rx) = mpsc::sync_channel(1024*10);
        let builder = thread::Builder::new().name("file_writer".into());
        let t = builder.spawn(move || {
            let mut f = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(false)
                .open(filename)
                .unwrap();

            loop {
                match rx.recv().unwrap() {
                    WriteMsg::Seek(from) => {
                        f.seek(from).unwrap();
                    }
                    WriteMsg::Write(buf) => {
                        f.write_all(&buf[..]).unwrap();
                    }
                    WriteMsg::Finish => {
                        break;
                    }
                }
            }
        }).unwrap();
        Writer {
            thread: t,
            tx: tx,
        }
    }

    pub fn seek(&self, from: SeekFrom) {
        self.tx.send(WriteMsg::Seek(from)).unwrap();
    }

    pub fn write_all(&self, buf: Vec<u8>) {
        match self.tx.try_send(WriteMsg::Write(buf)) {
            Err(mpsc::TrySendError::Full(d)) => {
                warn!("file write buffer full.");
                self.tx.send(d).unwrap();
            }
            Err(_) => {
                panic!("disconnect");
            }
            Ok(_) => {}
        }
    }

    pub fn close(self) {
        self.tx.send(WriteMsg::Finish).unwrap_or_else(|e| error!("{:?}", e));
        if let Err(e) = self.thread.join() {
            error!("\n\n{:?}\n\n", e);
        }
    }
}

impl Reader {
    pub fn new(filename: String) -> Reader {
        let (tx, rx) = mpsc::sync_channel(1024*10);
        let builder = thread::Builder::new().name("file_reader".into());
        let _ = builder.spawn(move || {
            let mut f = File::open(filename).unwrap();
            let mut payload = vec![0; 1350];
            let mut last_buffer_warn = Instant::now();
            f.seek(SeekFrom::Start(0)).unwrap();
            loop {
                match f.read(&mut payload) {
                    Ok(0) => {
                        tx.send(ReadMsg::Finish).unwrap();
                        break;
                    }
                    Ok(read) => {
                        let mut owned = Vec::with_capacity(read);
                        owned.extend_from_slice(&payload[..read]);
                        match tx.try_send(ReadMsg::Read(owned)) {
                            Err(mpsc::TrySendError::Full(d)) => {
                                if last_buffer_warn.elapsed() > Duration::from_secs(3) {
                                    warn!("file read buffer full.");
                                    last_buffer_warn = Instant::now();
                                }
                                tx.send(d).unwrap();
                            }
                            Err(_) => {
                                panic!("disconnect");
                            }
                            Ok(_) => {}
                        }
                    }
                    Err(_) => {
                        tx.send(ReadMsg::Error).unwrap();
                        panic!("ruh roh");
                    }
                }
            }
        });

        Reader {
            rx: rx,
        }
    }
}

