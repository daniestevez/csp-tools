use anyhow::Result;
use bandwidth::Bandwidth;
use clap::Parser;
use csp_tools::{
    csp::{CSP_CRC_SIZE, CSP_HEADER_SIZE, Flags, Header, PING_PORT, Packet, Priority},
    interfaces::{CspInterface, Interface, open_csp_interfaces},
};
use std::{
    cmp::Ordering,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering::Relaxed},
    },
    time::{Duration, Instant, SystemTime},
};

/// iperf-like tool using CSP.
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
    /// CSP source address.
    #[arg(long, value_parser=clap::value_parser!(u8).range(..32))]
    src_addr: u8,
    /// CSP source port (default is select and auto-increment outgoing port).
    #[arg(long, value_parser=clap::value_parser!(u8).range(..64))]
    src_port: Option<u8>,
    /// CSP destination address.
    #[arg(long, value_parser=clap::value_parser!(u8).range(..32))]
    dest_addr: u8,
    /// CSP destination port (default is CSP ping port).
    #[arg(long, default_value_t = PING_PORT, value_parser=clap::value_parser!(u8).range(..64))]
    dest_port: u8,
    /// Via address (by default use the CSP destination address).
    #[arg(long, value_parser=clap::value_parser!(u8).range(..32))]
    via_addr: Option<u8>,
    /// CSP packet size for request packets.
    #[arg(long)]
    packet_size: usize,
    /// CSP packet size for replies (default is the same as request size). This
    /// option is intended to be used with a ping server that modifies the reply
    /// size to achieve asymmetric rate.
    #[arg(long)]
    reply_size: Option<usize>,
    /// CSP maximum bindable ports (used to select outgoing ports).
    #[arg(long, default_value_t = 16, value_parser=clap::value_parser!(u8).range(..64))]
    csp_port_max_bind: u8,
    #[command(flatten)]
    rate: Rate,
    /// Period used to print statistics (in seconds).
    #[arg(long, default_value_t = 1.0)]
    stats_period: f64,
    /// Do not use CRC.
    #[arg(long)]
    no_crc: bool,
}

#[derive(clap::Args)]
#[group(required = true, multiple = false)]
#[derive(Debug, Copy, Clone, PartialEq)]
struct Rate {
    /// Throttle TX rate to this speed (in bits per second).
    #[arg(long)]
    tx_rate: Option<f64>,
    /// Throttle RX rate to this speed (in bits per second). This option is
    /// intended to be used with --reply-size and a ping server that modifies
    /// the reply size to achieve asymmetric rate.
    #[arg(long)]
    rx_rate: Option<f64>,
}

impl Args {
    fn overhead(&self) -> usize {
        CSP_HEADER_SIZE + if self.no_crc { 0 } else { CSP_CRC_SIZE }
    }

    fn tx_rate(&self) -> f64 {
        if let Some(tx_rate) = self.rate.tx_rate {
            return tx_rate;
        }
        // unwrap should not fail, because the options are mutually exclusive
        // but required (exactly one needs to be set)
        let rx_rate = self.rate.rx_rate.unwrap();
        if let Some(reply_size) = self.reply_size {
            self.packet_size as f64 * rx_rate / reply_size as f64
        } else {
            rx_rate
        }
    }

    fn request_has_timestamp(&self) -> bool {
        self.packet_size - self.overhead() >= std::mem::size_of::<u64>()
    }

    fn request_has_sequence_number(&self) -> bool {
        self.packet_size - self.overhead() >= 2 * std::mem::size_of::<u64>()
    }
}

#[derive(Debug)]
struct Stats {
    sent_packets: AtomicU64,
    recv_packets: AtomicU64,
    recv_bytes: AtomicU64,
    out_of_order_packets: AtomicU64,
    lost_packets: AtomicU64,
    mutex: Mutex<NonAtomicStats>,
}

#[derive(Debug)]
struct NonAtomicStats {
    rtts: Vec<Duration>,
}

impl Stats {
    fn new() -> Stats {
        Stats {
            sent_packets: AtomicU64::new(0),
            recv_packets: AtomicU64::new(0),
            out_of_order_packets: AtomicU64::new(0),
            lost_packets: AtomicU64::new(0),
            recv_bytes: AtomicU64::new(0),
            mutex: Mutex::new(NonAtomicStats {
                rtts: Vec::with_capacity(1024),
            }),
        }
    }
}

struct Transmitter {
    args: Args,
    bytes_per_second: f64,
    start: Instant,
    transmitted_bytes: usize,
    source_port: u8,
    sequence_number: u64,
    interface: CspInterface,
    stats: Arc<Stats>,
}

impl Transmitter {
    fn new(interface: CspInterface, args: Args, stats: Arc<Stats>) -> Transmitter {
        let bytes_per_second = args.tx_rate() / 8.0;
        let source_port = args.src_port.unwrap_or(args.csp_port_max_bind);
        Transmitter {
            args,
            bytes_per_second,
            start: Instant::now(),
            transmitted_bytes: 0,
            source_port,
            sequence_number: 0,
            interface,
            stats,
        }
    }

    fn run(&mut self) -> Result<()> {
        loop {
            self.send_one_packet()?;
        }
    }

    fn send_one_packet(&mut self) -> Result<()> {
        // wait to transmit before formatting packet, since the packet payload
        // contains the TX timestamp for RTT measurement
        self.wait_to_transmit();
        let packet = self.format_packet();
        self.interface.send(&packet)?;
        let packet_len = packet.csp_len();
        self.stats.sent_packets.fetch_add(1, Relaxed);
        self.transmitted_bytes += packet_len;
        self.sequence_number = self.sequence_number.wrapping_add(1);
        if self.args.src_port.is_none() {
            self.increment_source_port();
        }
        Ok(())
    }

    fn format_packet(&self) -> Packet {
        let payload_len = self.args.packet_size - self.args.overhead();
        let mut payload: Vec<u8> = (0..payload_len).map(|x| x as u8).collect();
        if self.args.request_has_timestamp() {
            // embed TX timestamp in payload
            let timestamp = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap();
            payload[..std::mem::size_of::<u64>()]
                .copy_from_slice(&u64::try_from(timestamp.as_nanos()).unwrap().to_be_bytes());
        }
        if self.args.request_has_sequence_number() {
            // embed sequence number in payload
            payload[std::mem::size_of::<u64>()..2 * std::mem::size_of::<u64>()]
                .copy_from_slice(&self.sequence_number.to_be_bytes());
        }
        Packet {
            via: self.args.via_addr,
            header: Header {
                priority: Priority::Normal,
                source_address: self.args.src_addr,
                destination_address: self.args.dest_addr,
                destination_port: self.args.dest_port,
                source_port: self.source_port,
                reserved: 0,
                flags: Flags {
                    hmac: false,
                    xtea: false,
                    rdp: false,
                    crc: !self.args.no_crc,
                },
            },
            payload,
        }
    }

    fn wait_to_transmit(&self) {
        let transmit_when = self.start
            + Duration::from_secs_f64(self.transmitted_bytes as f64 / self.bytes_per_second);
        if let Some(to_sleep) = transmit_when.checked_duration_since(Instant::now()) {
            std::thread::sleep(to_sleep);
        }
    }

    fn increment_source_port(&mut self) {
        self.source_port += 1;
        if self.source_port == 64 {
            self.source_port = self.args.csp_port_max_bind;
        }
    }
}

struct Receiver {
    interface: CspInterface,
    args: Args,
    stats: Arc<Stats>,
    expected_sequence: u64,
}

impl Receiver {
    fn new(interface: CspInterface, args: Args, stats: Arc<Stats>) -> Receiver {
        Receiver {
            interface,
            args,
            stats,
            expected_sequence: 0,
        }
    }

    fn run(&mut self) -> Result<()> {
        loop {
            self.receive_one_packet()?;
        }
    }

    fn receive_one_packet(&mut self) -> Result<()> {
        let packet = self.interface.receive()?;
        if packet.header.destination_address != self.args.src_addr {
            // not addressed to us; ignore the packet
            return Ok(());
        }
        if packet.header.source_port != self.args.dest_port {
            // not a ping reply; ignore the packet
            return Ok(());
        }
        if self.args.request_has_timestamp() && packet.payload.len() >= std::mem::size_of::<u64>() {
            // read embedded TX timestamp from payload
            let timestamp = SystemTime::UNIX_EPOCH
                + Duration::from_nanos(u64::from_be_bytes(
                    packet.payload[..std::mem::size_of::<u64>()]
                        .try_into()
                        .unwrap(),
                ));
            // set round-trip-time to zero if for some reason the packet
            // "travels back in time"
            let rtt = SystemTime::now()
                .duration_since(timestamp)
                .unwrap_or_default();
            self.stats.mutex.lock().unwrap().rtts.push(rtt);
        }
        if self.args.request_has_sequence_number()
            && packet.payload.len() >= 2 * std::mem::size_of::<u64>()
        {
            // read embedded sequence number from payload
            let sequence = u64::from_be_bytes(
                packet.payload[std::mem::size_of::<u64>()..2 * std::mem::size_of::<u64>()]
                    .try_into()
                    .unwrap(),
            );
            match sequence.cmp(&self.expected_sequence) {
                Ordering::Less => {
                    // packet arrived out of order
                    self.stats.out_of_order_packets.fetch_add(1, Relaxed);
                }
                Ordering::Greater => {
                    // lost packets
                    self.stats
                        .lost_packets
                        .fetch_add(sequence - self.expected_sequence, Relaxed);
                    self.expected_sequence = sequence + 1;
                }
                Ordering::Equal => {
                    self.expected_sequence = sequence + 1;
                }
            };
        }
        self.stats.recv_packets.fetch_add(1, Relaxed);
        self.stats
            .recv_bytes
            .fetch_add(u64::try_from(packet.csp_len()).unwrap(), Relaxed);
        Ok(())
    }
}

struct Monitor {
    args: Args,
    stats: Arc<Stats>,
    last_update: Instant,
}

impl Monitor {
    fn new(args: Args, stats: Arc<Stats>) -> Monitor {
        Monitor {
            args,
            stats,
            last_update: Instant::now(),
        }
    }

    fn run(&mut self) {
        loop {
            let next_update = self.last_update + Duration::from_secs_f64(self.args.stats_period);
            if let Some(to_sleep) = next_update.checked_duration_since(Instant::now()) {
                std::thread::sleep(to_sleep);
            }
            self.print_stats();
        }
    }

    fn print_stats(&mut self) {
        // collect data
        let system_time = SystemTime::now();
        let now = Instant::now();
        let tx_packets = self.stats.sent_packets.swap(0, Relaxed);
        let rx_packets = self.stats.recv_packets.swap(0, Relaxed);
        let rx_bytes = self.stats.recv_bytes.swap(0, Relaxed);
        let out_of_order_packets = self.stats.out_of_order_packets.swap(0, Relaxed);
        let lost_packets = self.stats.lost_packets.swap(0, Relaxed);
        let rtts = self
            .stats
            .mutex
            .lock()
            .unwrap()
            .rtts
            .drain(..)
            .collect::<Vec<_>>();

        // compute
        let elapsed = (now - self.last_update).as_secs_f64();
        let tx_rate =
            (tx_packets * u64::try_from(self.args.packet_size).unwrap() * 8) as f64 / elapsed;
        let rx_rate = (rx_bytes * 8) as f64 / elapsed;
        let timestamp = humantime::format_rfc3339(system_time);
        let max_rtt = rtts.iter().copied().max().unwrap_or_default();
        let min_rtt = rtts.iter().copied().min().unwrap_or_default();
        let avg_rtt = if !rtts.is_empty() {
            Duration::from_secs_f64(
                rtts.iter()
                    .map(|duration| duration.as_secs_f64())
                    .sum::<f64>()
                    / rtts.len() as f64,
            )
        } else {
            Duration::default()
        };

        // format and print
        let timestamp = console::style(format!("{timestamp}")).dim();
        let tx = console::style("TX").red().bold();
        let rx = console::style("RX").green().bold();
        let rtt = console::style("RTT").blue().bold();
        let tx_rate = human_bandwidth::format_bandwidth(Bandwidth::from_gbps_f64(tx_rate * 1e-9));
        let rx_rate = human_bandwidth::format_bandwidth(Bandwidth::from_gbps_f64(rx_rate * 1e-9));
        let packets = console::style("packets").dim();
        let max_rtt_ms = max_rtt.as_secs_f64() * 1e3;
        let min_rtt_ms = min_rtt.as_secs_f64() * 1e3;
        let avg_rtt_ms = avg_rtt.as_secs_f64() * 1e3;
        let ms = console::style("ms").dim();
        let lost = if lost_packets > 0 {
            format!(" {} {lost_packets}", console::style("lost").red().bold())
        } else {
            String::new()
        };
        let out_of_order = if out_of_order_packets > 0 {
            format!(
                " {} {out_of_order_packets}",
                console::style("out-of-order").yellow().bold()
            )
        } else {
            String::new()
        };
        eprintln!(
            "{timestamp} \
             {tx} {tx_rate} {tx_packets} {packets} \
             {rx} {rx_rate} {rx_packets} {packets} \
             {rtt} {min_rtt_ms:.3}/{avg_rtt_ms:.3}/{max_rtt_ms:.3} {ms}{lost}{out_of_order}"
        );

        self.last_update = now;
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    anyhow::ensure!(
        args.packet_size >= args.overhead(),
        "Packet size is too small"
    );

    let (tx_interface, rx_interface) = open_csp_interfaces(
        args.can.as_ref(),
        &args.zmq_tx_socket,
        &args.zmq_rx_socket,
        args.src_addr,
    )?;

    let (tx_error, rx_error) = std::sync::mpsc::sync_channel(0);
    let stats = Arc::new(Stats::new());

    let mut receiver = Receiver::new(rx_interface, args.clone(), stats.clone());
    std::thread::spawn({
        let tx_error = tx_error.clone();
        move || tx_error.send(receiver.run())
    });

    let mut transmitter = Transmitter::new(tx_interface, args.clone(), stats.clone());
    std::thread::spawn({
        let tx_error = tx_error.clone();
        move || tx_error.send(transmitter.run())
    });

    let mut monitor = Monitor::new(args, stats);
    std::thread::spawn(move || monitor.run());

    rx_error.recv().unwrap()
}
