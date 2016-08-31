// #![feature(alloc_system)]
// extern crate alloc_system;

#[macro_use]
extern crate log;
#[macro_use]
extern crate shoop;
#[macro_use]
extern crate clap;

use clap::App;
use std::str;
use shoop::{ShoopLogger, ShoopMode, LogVerbosity, TransferMode,
            Target, Server, Client};
use shoop::connection::PortRange;

const DEFAULT_PORT_RANGE: &'static str = "55000-55050";

fn main() {
    let matches = App::new("shoop")
        .version(crate_version!())
        .author(crate_authors!())
        .about("Shoop is a ultrafast, (hopefully) secure file transfer tool, that is (hopefully) ideal for transferring large files.")
        .args_from_usage(
            "-p --port-range=[RANGE] 'server UDP port range (ex. \"55000-55050\")'
             -f --force              'overwrite the output file if it exists'
             -d --debug              'output verbose debug information'
             -s --server             'server mode'
             -r --receive            'receive mode (server mode only)'
             <SOURCE>                'input \"host:path\", just like scp (ex. \"myseedbox.com:~/downloads/linux.iso\")'
             [DEST]                  'optional output path (directory or file, ex. \".\" or \"~/isos\" or \"~/isos/totallynotporn.iso\")'")
        // .subcommand(SubCommand::with_name("server")
        //             .about("Shoop server mode.")
        //             .args_from_usage(
        //                 "-r --receive 'receive mode (client -> server)'"))
        .get_matches();

    let raw_source = matches.value_of("SOURCE").unwrap();

    let mode = match matches.is_present("server") {
        true => ShoopMode::Server,
        _    => ShoopMode::Client,
    };

    let verbosity = match matches.is_present("debug") {
        true => LogVerbosity::Debug,
        _    => LogVerbosity::Normal,
    };

    let port_range = {
        let range = matches.value_of("port-range")
            .unwrap_or_else(|| DEFAULT_PORT_RANGE.into());
        PortRange::from(range).unwrap()
    };

    ShoopLogger::init(mode, verbosity).expect("Error starting shoop logger.");

    match mode {
        ShoopMode::Server => {
            let transfer_mode = match matches.is_present("receive") {
                true => TransferMode::Receive,
                _    => TransferMode::Send,
            };

            if let Ok(mut server) = Server::new(port_range, &raw_source) {
                server.start(transfer_mode);
                info!("exiting.");
            }
        },
        ShoopMode::Client => {
            let raw_dest = matches.value_of("DEST")
                .unwrap_or_else(|| ".".into());

            let source = Target::from(raw_source.to_owned());
            let dest = Target::from(raw_dest.to_owned());

            match Client::new(source, dest, port_range) {
                Ok(mut client) => client.start(matches.is_present("force")),
                Err(e) => error!("{}", e),
            }
        }
    }
}
