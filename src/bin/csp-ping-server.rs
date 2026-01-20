use anyhow::Result;
use clap::Parser;
use csp_tools::{
    csp::{Header, PING_PORT},
    interfaces::{Interface, open_csp_interfaces},
};

/// CSP ping server.
#[derive(Parser, Debug, Clone, PartialEq)]
#[command(version, about, long_about = None)]
struct Args {
    /// CAN interface (if not specified, ZMQ is used instead).
    #[arg(long)]
    can: Option<String>,
    /// ZMQ socket to which frames are sent.
    #[arg(long, default_value = "tcp://127.0.0.1:6000")]
    zmq_tx_socket: String,
    /// ZMQ socket from which frames are received.
    #[arg(long, default_value = "tcp://127.0.0.1:7000")]
    zmq_rx_socket: String,
    /// CSP address.
    #[arg(long, value_parser=clap::value_parser!(u8).range(..32))]
    addr: u8,
    /// CSP port (default is CSP ping service port).
    #[arg(long, default_value_t = PING_PORT, value_parser=clap::value_parser!(u8).range(..64))]
    port: u8,
    /// Via address (by default use the CSP destination address).
    #[arg(long, value_parser=clap::value_parser!(u8).range(..32))]
    via_addr: Option<u8>,
    /// Reply size (by default use the same size as the request packet).
    #[arg(long)]
    reply_size: Option<usize>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let (mut tx_interface, mut rx_interface) = open_csp_interfaces(
        args.can.as_ref(),
        &args.zmq_tx_socket,
        &args.zmq_rx_socket,
        args.addr,
    )?;

    loop {
        let mut packet = rx_interface.receive()?;
        if packet.header.destination_address != args.addr {
            // not addressed to us; ignore
            continue;
        }
        if packet.header.destination_port != args.port {
            // not address to our port; ignore
            continue;
        }
        packet.header = Header {
            source_address: args.addr,
            source_port: args.port,
            destination_address: packet.header.source_address,
            destination_port: packet.header.source_port,
            ..packet.header
        };
        packet.via = args.via_addr;
        if let Some(reply_size) = args.reply_size {
            let overhead = packet.csp_overhead_len();
            anyhow::ensure!(
                reply_size >= overhead,
                "reply size {reply_size} is smaller than the packet CSP overhead ({overhead} bytes)"
            );
            let new_size = reply_size - overhead;
            if new_size <= packet.payload.len() {
                packet.payload.truncate(new_size);
            } else {
                packet
                    .payload
                    .extend((packet.payload.len()..new_size).map(|n| n as u8));
            }
            assert_eq!(packet.payload.len(), new_size);
        }
        tx_interface.send(&packet)?;
    }
}
