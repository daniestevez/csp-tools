use anyhow::{Context, Result};
use clap::Parser;
use csp_tools::interfaces::{CanInterface, CspInterface, Interface, ZmqInterface};
use pcap_file::pcap::{PcapWriter, RawPcapPacket};
use socketcan::{CanFrame, CanSocket, Frame, Socket, frame::AsPtr};
use std::{cell::RefCell, fs::File, path::PathBuf};

/// tcpdump-like tool for CSP.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// CAN interface (if not specified, ZMQ is used instead).
    #[arg(long)]
    can: Option<String>,
    /// ZMQ socket from which frames are received.
    #[arg(long, default_value = "tcp://127.0.0.1:7000")]
    zmq_socket: String,
    /// PCAP output file for CSP packets.
    #[arg(long)]
    pcap_file: PathBuf,
    /// Include CAN frames in PCAP output (requires --can).
    #[arg(long)]
    include_can_frames: bool,
}

fn write_can_frame(pcap_writer: &mut PcapWriter<File>, frame: &CanFrame) -> Result<()> {
    // this unwrap should not panic, since SystemTime::now() is assumed to
    // be after the UNIX_EPOCH
    let t = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap();
    let mut sll_header = vec![0u8; 16];
    sll_header[1] = 1; // broadcast
    // CAN
    sll_header[2] = 0x01;
    sll_header[3] = 0x18;
    sll_header[15] = 0x0c;
    let mut data = frame.as_bytes().to_vec();
    // overwrite id_word with big-endian bytes, as required by PCAP
    data[..4].copy_from_slice(&u32::to_be_bytes(frame.id_word()));
    sll_header.extend_from_slice(&data);
    let orig_len = u32::try_from(sll_header.len()).unwrap();
    let raw_packet = RawPcapPacket {
        ts_sec: u32::try_from(t.as_secs()).unwrap(),
        ts_frac: t.subsec_nanos(),
        incl_len: orig_len,
        orig_len,
        data: sll_header.into(),
    };
    pcap_writer
        .write_raw_packet(&raw_packet)
        .context("Error writing packet to PCAP file")?;
    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();
    if args.include_can_frames {
        anyhow::ensure!(
            args.can.is_some(),
            "--include-can-frames argument requires --can"
        );
    }

    let pcap_file = File::create(&args.pcap_file).with_context(|| {
        format!(
            "Failed to create output PCAP file {}",
            args.pcap_file.display()
        )
    })?;
    let pcap_header = pcap_file::pcap::PcapHeader {
        datalink: pcap_file::DataLink::LINUX_SLL,
        ts_resolution: pcap_file::TsResolution::NanoSecond,
        ..Default::default()
    };
    let pcap_writer = PcapWriter::with_header(pcap_file, pcap_header)
        .context("Failed to write header to PCAP file")?;
    let pcap_writer = RefCell::new(pcap_writer);

    let mut interface = if let Some(can_interface) = &args.can {
        let pcap_writer = &pcap_writer;
        let callback = move |frame: &CanFrame| {
            if args.include_can_frames {
                write_can_frame(&mut pcap_writer.borrow_mut(), frame)?;
            }
            Ok(())
        };
        let can_socket = CanSocket::open(can_interface)
            .with_context(|| format!("Failed to open CAN interface {can_interface}"))?;
        CspInterface::Can(CanInterface::new_with_callback(can_socket, callback))
    } else {
        let zmq_context = zmq::Context::new();
        CspInterface::Zmq(ZmqInterface::new_promiscuous_sub(
            &zmq_context,
            &args.zmq_socket,
        )?)
    };

    loop {
        let packet = interface.receive_raw()?;
        // this unwrap should not panic, since SystemTime::now() is assumed to
        // be after the UNIX_EPOCH
        let t = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap();
        let mut sll_header = vec![0u8; 16];
        sll_header.extend_from_slice(&packet);
        let orig_len = u32::try_from(sll_header.len()).unwrap();
        let raw_packet = RawPcapPacket {
            ts_sec: u32::try_from(t.as_secs()).unwrap(),
            ts_frac: t.subsec_nanos(),
            incl_len: orig_len,
            orig_len,
            data: sll_header.into(),
        };
        pcap_writer
            .borrow_mut()
            .write_raw_packet(&raw_packet)
            .context("Error writing packet to PCAP file")?;
    }
}
