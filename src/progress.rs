use std::sync::mpsc;
use std::sync::mpsc::TryRecvError;
use std::time::{Instant, Duration};
use std::thread;
use std::io::Stdout;
use pbr::{ProgressBar, Units};

// like a beautiful film
static REFRESH_DELAY: u64 = 1000 / 10;

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

fn new_pb(size: u64) -> ProgressBar<Stdout> {
    let mut pb = ProgressBar::new(size);
    pb.set_units(Units::Bytes);
    pb.format("⸨▱▱ ⸩");
    pb.tick_format("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏");
    pb
}

fn do_maybe<F>(pb_maybe: &mut Option<ProgressBar<Stdout>>, f: F)
    where F : Fn(&mut ProgressBar<Stdout>) -> ()
{
    if let Some(ref mut pb) = pb_maybe.as_mut() {
        f(pb);
    }
}

impl Progress {
    pub fn new() -> Progress {
        let (tx, rx) = mpsc::channel();
        let builder = thread::Builder::new().name("progress".into());
        let t = builder.spawn(move || {
            let mut pb = None;
            let mut last_add = Instant::now();
            let mut frame_total: u64 = 0;
            let mut frame_message: Option<String> = None;

            loop {
                match rx.try_recv() {
                    Ok(Msg::SetMessage(msg)) => {
                        frame_message = Some(msg);
                    }
                    Ok(Msg::SetSize(size)) => {
                        pb = Some(new_pb(size));
                    }
                    Ok(Msg::Add(size)) => {
                        frame_total += size;
                    }
                    Ok(Msg::Finish(msg)) => {
                        do_maybe(&mut pb, |pb| pb.finish_println(&msg));
                        break;
                    }
                    Err(TryRecvError::Empty) => {
                        if let Some(msg) = frame_message {
                            do_maybe(&mut pb, |pb| pb.message(&msg));
                        }
                        if frame_total > 0 {
                            last_add = Instant::now();
                            do_maybe(&mut pb, |pb| { pb.add(frame_total); });
                        } else if last_add.elapsed() < Duration::from_secs(5) {
                            do_maybe(&mut pb, |pb| pb.tick());
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
        }).unwrap();
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

