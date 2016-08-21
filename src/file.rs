use std::sync::mpsc;
use std::thread;
use std::path::PathBuf;
use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write, Read};

pub struct Writer {
    thread: thread::JoinHandle<()>,
    tx: mpsc::SyncSender<WriteMsg>,
}

pub struct Reader {
    thread: thread::JoinHandle<()>,
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
        let (tx, rx) = mpsc::sync_channel(1024);
        let t = thread::spawn(move || {
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
        });
        Writer {
            thread: t,
            tx: tx,
        }
    }

    pub fn seek(&self, from: SeekFrom) {
        self.tx.send(WriteMsg::Seek(from)).unwrap();
    }

    pub fn write_all(&self, buf: Vec<u8>) {
        self.tx.send(WriteMsg::Write(buf)).unwrap();
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
        let (tx, rx) = mpsc::sync_channel(1024);
        let t = thread::spawn(move || {
            let mut f = File::open(filename).unwrap();
            let mut payload = vec![0; 1300];
            f.seek(SeekFrom::Start(0)).unwrap();
            loop {
                match f.read(&mut payload) {
                    Ok(0) => {
                        tx.send(ReadMsg::Finish);
                    }
                    Ok(read) => {
                        let mut owned = Vec::with_capacity(read);
                        owned.extend_from_slice(&payload[..read]);
                        tx.send(ReadMsg::Read(owned));
                    }
                    Err(_) => {
                        tx.send(ReadMsg::Error);
                        panic!("ruh roh");
                    }
                }
            }
        });

        Reader {
            thread: t,
            rx: rx,
        }
    }
}

