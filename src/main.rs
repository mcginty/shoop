#[macro_use] extern crate log;
extern crate structopt;
extern crate shoop;

use structopt::StructOpt;
use shoop::{ShoopLogger, ShoopMode, LogVerbosity, TransferMode,
            Target, Server, Client};
use shoop::connection::PortRange;

#[derive(StructOpt, Debug)]
#[structopt(name = "shoop")]
struct Opt {
    #[structopt(short = "d", long = "debug", help = "Extra debugging output")]
    debug: bool,

    #[structopt(short = "f", long = "force", help = "Force overwrite of file")]
    force: bool,

    #[structopt(short = "s", long = "server", help = "Server mode")]
    server: bool,

    #[structopt(short = "p", long = "port-range", default_value = "55000-55050")]
    port_range: String,

    #[structopt(name = "SOURCE", help = "The source target, ex. \"my.server.com:~/file.bin\"")]
    source: String,

    #[structopt(name = "DEST", default_value = ".", help = "The optional destination (either a folder or file)")]
    dest: String,
}

fn main() {
    let opt = Opt::from_args();

    let mode = match opt.server {
        true => ShoopMode::Server,
        _    => ShoopMode::Client,
    };

    let verbosity = match opt.debug {
        true => LogVerbosity::Debug,
        _    => LogVerbosity::Normal,
    };

    let port_range = PortRange::from(&opt.port_range).unwrap();

    ShoopLogger::init(mode, verbosity).expect("Error starting shoop logger.");

    match mode {
        ShoopMode::Server => {
            let transfer_mode = TransferMode::Send;

            if let Ok(mut server) = Server::new(port_range, &opt.source) {
                server.start(transfer_mode);
                info!("exiting.");
            }
        },
        ShoopMode::Client => {
            let source = Target::from(opt.source.clone());
            let dest = Target::from(opt.dest.clone());

            match Client::new(source, dest, port_range) {
                Ok(mut client) => client.start(opt.force),
                Err(e) => error!("{}", e),
            }
        }
    }
}
