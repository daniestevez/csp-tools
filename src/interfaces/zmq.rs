use super::Interface;
use crate::csp::{CSP_CRC_SIZE, CSP_HEADER_SIZE, Header, Packet};
use anyhow::{Context as _, Result};
use deku::prelude::*;
use zmq::{Context, Socket};

/// CSP ZMQ interface.
///
/// This struct represents a ZMQ socket that can send or receive CSP packets. In
/// ZMQ, CSP packets are sent to a ZMQ PUB socket, and they are received in a
/// ZMQ SUB socket. Each CSP packet is prepended with the via address so that
/// topic subscription can be used for address filtering.
pub struct ZmqInterface {
    socket: Socket,
}

impl ZmqInterface {
    /// Creates a ZMQ PUB socket that can send CSP packets.
    ///
    /// The `context` variable is the [`zmq`] context, and `address` is the
    /// address of the ZMQ socket.
    pub fn new_pub(context: &Context, address: &str) -> Result<ZmqInterface> {
        let socket = context
            .socket(zmq::PUB)
            .context("Failed to create ZMQ PUB socket")?;
        socket
            .connect(address)
            .with_context(|| format!("Failed to connect ZMQ PUB socket to {address}"))?;
        Ok(ZmqInterface { socket })
    }

    /// Creates a ZMQ SUB socket that can receive CSP packets.
    ///
    /// The `context` variable is the [`zmq`] context, and `address` is the
    /// address of the ZMQ socket. The `subscribe_addresses` argument indicates
    /// the CSP via addresses to which this SUB socket subscribes. Only messages
    /// sent to those via addresses will be received on the interface.
    pub fn new_sub(
        context: &Context,
        address: &str,
        subscribe_addresses: impl Iterator<Item = u8>,
    ) -> Result<ZmqInterface> {
        let socket = context
            .socket(zmq::SUB)
            .context("Failed to create ZMQ SUB socket")?;
        socket
            .connect(address)
            .with_context(|| format!("Failed to connect ZMQ SUB socket to {address}"))?;
        for csp_addr in subscribe_addresses {
            socket.set_subscribe(&[csp_addr]).with_context(|| {
                format!("Failed to subscribe ZMQ SUB socket to CSP address {csp_addr}")
            })?;
        }
        Ok(ZmqInterface { socket })
    }

    /// Creates a promiscuous ZMQ SUB socket that can receive CSP packets.
    ///
    /// This function creates a ZMQ SUB socket that can receive CSP packets sent
    /// to any via address. The `context` variable is the [`zmq`] context, and
    /// `address` is the address of the ZMQ socket.
    pub fn new_promiscuous_sub(context: &Context, address: &str) -> Result<ZmqInterface> {
        let socket = context
            .socket(zmq::SUB)
            .context("Failed to create ZMQ SUB socket")?;
        socket
            .connect(address)
            .with_context(|| format!("Failed to connect ZMQ SUB socket to {address}"))?;
        socket
            .set_subscribe(b"")
            .context("Failed to subscribe to all topics in ZMQ SUB socket")?;
        Ok(ZmqInterface { socket })
    }
}

impl Interface for ZmqInterface {
    fn send(&mut self, packet: &Packet) -> Result<()> {
        let flags = 0;
        self.socket.send(
            serialize_zmq(packet).context("Failed to format CSP-ZMQ packet")?,
            flags,
        )?;
        Ok(())
    }

    fn receive(&mut self) -> Result<Packet> {
        let packet = self.receive_raw()?;
        deserialize_zmq(&packet).context("Failed to parse CSP-ZMQ packet")
    }

    fn receive_raw(&mut self) -> Result<Vec<u8>> {
        let flags = 0;
        self.socket
            .recv_bytes(flags)
            .context("Failed to receive packet from ZMQ socket")
    }
}

const ZMQ_TOPIC_SIZE: usize = 1;

pub(super) fn serialize_zmq(packet: &Packet) -> Result<Vec<u8>> {
    let output_len = ZMQ_TOPIC_SIZE + CSP_HEADER_SIZE + packet.payload.len() + packet.crc_len();
    let mut output = Vec::with_capacity(output_len);
    output.push(packet.via_address());
    let header_bytes = packet.header.to_bytes()?;
    // the header needs to be reversed due to endianness used in ZMQ
    output.extend(header_bytes.into_iter().rev());
    output.extend_from_slice(&packet.payload_and_crc());
    assert_eq!(output.len(), output_len);
    Ok(output)
}

fn deserialize_zmq(data: &[u8]) -> Result<Packet> {
    anyhow::ensure!(
        data.len() >= ZMQ_TOPIC_SIZE + CSP_HEADER_SIZE,
        "CSP packet is shorter than ZMQ topic and CSP header"
    );
    let via = Some(data[0]);
    let mut header = data[ZMQ_TOPIC_SIZE..ZMQ_TOPIC_SIZE + CSP_HEADER_SIZE].to_vec();
    // the header needs to be reversed due to endianness used in ZMQ
    header.reverse();
    let header = Header::try_from(header.as_ref())?;
    let crc_size = if header.flags.crc { CSP_CRC_SIZE } else { 0 };
    anyhow::ensure!(
        data.len() >= crc_size + ZMQ_TOPIC_SIZE + CSP_HEADER_SIZE,
        "CSP packet is too short"
    );
    let payload = data[ZMQ_TOPIC_SIZE + CSP_HEADER_SIZE..data.len() - crc_size].to_vec();
    if header.flags.crc {
        anyhow::ensure!(
            Packet::crc_is_correct(
                &payload,
                data[data.len() - CSP_CRC_SIZE..].try_into().unwrap()
            ),
            "CSP CRC is wrong"
        );
    }
    Ok(Packet {
        via,
        header,
        payload,
    })
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::csp::{Flags, Priority};

    #[test]
    fn deserialize_packet() {
        let packet_bytes = [0x17, 0x01, 0x79, 0xa0, 0xac, 0x00, 0x52, 0x7d, 0x53, 0x51];
        let packet = deserialize_zmq(&packet_bytes).unwrap();
        assert_eq!(
            packet,
            Packet {
                via: Some(23),
                header: Header {
                    priority: Priority::Normal,
                    source_address: 22,
                    destination_address: 10,
                    destination_port: 1,
                    source_port: 57,
                    reserved: 0,
                    flags: Flags {
                        hmac: false,
                        xtea: false,
                        rdp: false,
                        crc: true,
                    }
                },
                payload: vec![0],
            }
        );
    }

    #[test]
    fn serialize_packet() {
        let packet = Packet {
            via: Some(23),
            header: Header {
                priority: Priority::Normal,
                source_address: 22,
                destination_address: 10,
                destination_port: 1,
                source_port: 57,
                reserved: 0,
                flags: Flags {
                    hmac: false,
                    xtea: false,
                    rdp: false,
                    crc: true,
                },
            },
            payload: vec![0],
        };
        let packet_bytes = serialize_zmq(&packet).unwrap();
        assert_eq!(
            packet_bytes,
            [0x17, 0x01, 0x79, 0xa0, 0xac, 0x00, 0x52, 0x7d, 0x53, 0x51]
        );
    }
}
