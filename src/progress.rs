use std::sync::mpsc;
use std::sync::mpsc::TryRecvError;
use std::time::Duration;
use std::thread;
use pbr::{ProgressBar, Units};

// like a beautiful film
static REFRESH_DELAY: u64 = 1000 / 15;

pub struct Progress {
    thread: thread::JoinHandle<()>,
    tx: mpsc::Sender<Msg>,
}

pub enum Msg {
    SetMessage(String),
    SetSize(u64),
    Add(u64),
    Finish(String),
}

fn new_pb(size: u64) -> ProgressBar<::std::io::Stdout> {
    let mut pb = ProgressBar::new(size);
    pb.set_units(Units::Bytes);
    pb.format(" =💃 ⛩");
    pb.tick_format("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏");
    pb
}

impl Progress {
    pub fn new() -> Progress {
        let (tx, rx) = mpsc::channel();
        let t = thread::spawn(move || {
            let mut pb = new_pb(0);
            let mut frame_total: u64 = 0;
            let mut frame_message: Option<String> = None;

            loop {
                match rx.try_recv() {
                    Ok(Msg::SetMessage(msg)) => {
                        frame_message = Some(msg);
                    }
                    Ok(Msg::SetSize(size)) => {
                        pb = new_pb(size);
                    }
                    Ok(Msg::Add(size)) => {
                        frame_total += size;
                    }
                    Ok(Msg::Finish(msg)) => {
                        pb.finish_print(&msg);
                        break;
                    }
                    Err(TryRecvError::Empty) => {
                        if let Some(msg) = frame_message {
                            pb.message(&msg);
                        }
                        if pb.total > 0 {
                            pb.add(frame_total);
                        }
                        frame_message = None;
                        frame_total = 0;
                        thread::sleep(Duration::from_millis(REFRESH_DELAY));
                    }
                    _ => {
                        panic!("disconnected channel");
                    }
                }
            }
        });
        Progress {
            thread: t,
            tx: tx,
        }
    }

    pub fn message<S: Into<String>>(&self, msg: S) {
        self.tx.send(Msg::SetMessage(msg.into())).unwrap();
    }

    pub fn finish<S: Into<String>>(self, msg: S) {
        self.tx.send(Msg::Finish(msg.into())).unwrap();
        let _ = self.thread.join();
    }

    pub fn add(&self, amount: u64) {
        self.tx.send(Msg::Add(amount)).unwrap();
    }

    pub fn size(&self, size: u64) {
        self.tx.send(Msg::SetSize(size)).unwrap();
    }
}

