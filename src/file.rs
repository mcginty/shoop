use std::sync::mpsc;
use std::thread;
use std::path::{Path, PathBuf};
use std::fs::{OpenOptions, File};
use std::io::{Cursor, Error, Seek, SeekFrom, Read, Write};

pub struct Writer {
    thread: thread::JoinHandle<()>,
    tx: mpsc::SyncSender<Msg>,
}

pub enum Msg {
    Seek(SeekFrom),
    Write(Vec<u8>),
    Finish,
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
                    Msg::Seek(from) => {
                        f.seek(from).unwrap();
                    }
                    Msg::Write(buf) => {
                        f.write_all(&buf[..]).unwrap();
                    }
                    Msg::Finish => {
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
        self.tx.send(Msg::Seek(from)).unwrap();
    }

    pub fn write_all(&self, buf: Vec<u8>) {
        self.tx.send(Msg::Write(buf)).unwrap();
    }

    pub fn close(self) {
        self.tx.send(Msg::Finish).unwrap_or_else(|e| error!("{:?}", e));
        if let Err(e) = self.thread.join() {
            error!("\n\n{:?}\n\n", e);
        }
    }
}

