use super::Interface;
use crate::csp::{CSP_CRC_SIZE, CSP_HEADER_SIZE, Header, Packet};
use anyhow::{Context, Result};
use deku::prelude::*;
use socketcan::{
    BlockingCan, CanFilter, CanFrame, CanSocket, EmbeddedFrame, ExtendedId, Id, Socket,
};
use std::collections::{HashMap, hash_map::Entry};

/// CSP CAN interface.
///
/// This struct represents a CAN interface that can send and receive CSP packets
/// using CFP (CAN fragmentation protocol).
pub struct CanInterface<Callback = ()> {
    socket: CanSocket,
    tx_fragmentation_identifier: u16,
    defragmenter: CfpDefragmenter,
    can_frame_callback: Callback,
}

/// CAN frame callback.
///
/// This trait represents a callback function that is called for each received
/// CAN frame.
pub trait CallbackFn {
    /// Call the callback function.
    ///
    /// Calls the callback function with a [`CanFrame`].
    fn call(&mut self, frame: &CanFrame) -> Result<()>;
}

impl CallbackFn for () {
    fn call(&mut self, _frame: &CanFrame) -> Result<()> {
        Ok(())
    }
}

impl<F: FnMut(&CanFrame) -> Result<()>> CallbackFn for F {
    fn call(&mut self, frame: &CanFrame) -> Result<()> {
        self(frame)
    }
}

impl CanInterface {
    /// Open a CSP CAN interface.
    ///
    /// This function wraps a [`CanSocket`] into a [`CanInterface`] capable of
    /// sending and receiving CSP packets.
    pub fn new(socket: CanSocket) -> CanInterface {
        CanInterface {
            socket,
            tx_fragmentation_identifier: 0,
            defragmenter: CfpDefragmenter::default(),
            can_frame_callback: (),
        }
    }
}

impl<Callback> CanInterface<Callback> {
    /// Open a CSP CAN interface with a callback function.
    ///
    /// This function wraps a [`CanSocket`] into a [`CanInterface`] capable of
    /// sending and receiving CSP packets and registers the `can_frame_callback`
    /// callback function to be called for each CAN frame received on the
    /// interface.
    pub fn new_with_callback(
        socket: CanSocket,
        can_frame_callback: Callback,
    ) -> CanInterface<Callback> {
        CanInterface {
            socket,
            tx_fragmentation_identifier: 0,
            defragmenter: CfpDefragmenter::default(),
            can_frame_callback,
        }
    }
}

impl<Callback: CallbackFn> Interface for CanInterface<Callback> {
    fn send(&mut self, packet: &Packet) -> Result<()> {
        for frame in cfp_fragments(packet, self.tx_fragmentation_identifier)
            .context("Failed to fragment CSP packet using CFP")?
        {
            self.socket
                .transmit(&frame)
                .context("Failed to send CFP fragment to CAN interface")?;
        }
        self.tx_fragmentation_identifier = (self.tx_fragmentation_identifier + 1) % (1 << 10);
        Ok(())
    }

    fn receive(&mut self) -> Result<Packet> {
        loop {
            let frame = self
                .socket
                .read_frame()
                .context("Failed to read frame from CAN interface")?;
            let Id::Extended(identifier) = frame.id() else {
                // ignore any 11-bit ID traffic in the CAN bus
                continue;
            };
            self.can_frame_callback.call(&frame)?;
            let identifier = CanIdentifier::deserialize(identifier);
            match self.defragmenter.defragment(identifier, frame.data()) {
                Ok(Some(packet)) => return Ok(packet),
                Ok(None) => {}
                Err(err) => {
                    log::debug!("CFP defragmentation error: {err}");
                }
            }
        }
    }

    fn receive_raw(&mut self) -> Result<Vec<u8>> {
        // TODO: implement proper raw defragmentation that does not check CRC
        // and header format
        let packet = self.receive()?;
        super::zmq::serialize_zmq(&packet)
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, DekuRead, DekuWrite)]
#[deku(endian = "big")]
struct CanIdentifier {
    #[deku(bits = 5)]
    source_address: u8,
    #[deku(bits = 5)]
    destination_address: u8,
    fragment_type: FragmentType,
    #[deku(bits = 8)]
    remain: u8,
    #[deku(bits = 10)]
    fragmentation_identifier: u16,
}

const EXTENDED_ID_BITS: usize = 29;
const U32_BITS: usize = 32;
const U32_MINUS_EXTENDED_BITS: usize = U32_BITS - EXTENDED_ID_BITS;

impl CanIdentifier {
    fn serialize(&self) -> ExtendedId {
        ExtendedId::new(
            u32::from_be_bytes(self.to_bytes().unwrap().try_into().unwrap())
                >> U32_MINUS_EXTENDED_BITS,
        )
        .unwrap()
    }

    fn deserialize(identifier: ExtendedId) -> CanIdentifier {
        CanIdentifier::from_bytes((&identifier.as_raw().to_be_bytes(), U32_MINUS_EXTENDED_BITS))
            .unwrap()
            .1
    }

    fn defragmentation_key(&self) -> u32 {
        u32::from(self.fragmentation_identifier)
            | (u32::from(self.source_address) << 16)
            | (u32::from(self.destination_address) << 24)
    }
}

pub fn destination_address_can_filter(destination_address: u8) -> CanFilter {
    const SHIFT: usize = EXTENDED_ID_BITS - 10;
    CanFilter::new(u32::from(destination_address) << SHIFT, 0x1f << SHIFT)
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, DekuRead, DekuWrite)]
#[deku(id_type = "u8", bits = "1")]
#[deku(ctx = "endian: deku::ctx::Endian")]
enum FragmentType {
    #[deku(id = "0")]
    Begin,
    #[deku(id = "1")]
    More,
}

// Number of bits in remain field in CAN identifier
const REMAIN_FIELD_SIZE: usize = 8;

// Number of bytes in CAN frame payload
const CAN_PAYLOAD_SIZE: usize = 8;

// Number of bytes in CSP length field
const CSP_LENGTH_FIELD_SIZE: usize = std::mem::size_of::<u16>();

// Maximum size of a CSP frame that can be sent over CAN
const MAX_CSP_CAN_SIZE: usize = (1 << REMAIN_FIELD_SIZE) * CAN_PAYLOAD_SIZE - CSP_LENGTH_FIELD_SIZE;

fn cfp_fragments(packet: &Packet, fragmentation_identifier: u16) -> Result<Vec<CanFrame>> {
    anyhow::ensure!(
        packet.csp_len() <= MAX_CSP_CAN_SIZE,
        "CSP packet is too large to send over CAN"
    );

    let num_fragments = (packet.csp_len() + CSP_LENGTH_FIELD_SIZE).div_ceil(CAN_PAYLOAD_SIZE);
    let mut fragments = Vec::with_capacity(num_fragments);
    let payload = packet.payload_and_crc();

    // Format first fragment
    let identifier = CanIdentifier {
        source_address: packet.header.source_address,
        destination_address: packet.via_address(),
        fragment_type: FragmentType::Begin,
        remain: (num_fragments - 1).try_into().unwrap(),
        fragmentation_identifier,
    };
    let mut fragment = Vec::with_capacity(CAN_PAYLOAD_SIZE);
    fragment.extend_from_slice(&packet.header.to_bytes().unwrap());
    fragment.extend_from_slice(
        &u16::try_from(packet.csp_payload_len())
            .unwrap()
            .to_be_bytes(),
    );
    let available = 2;
    fragment.extend_from_slice(&payload[..available.min(payload.len())]);
    fragments.push(CanFrame::new(identifier.serialize(), &fragment).unwrap());

    // Format remaining fragments
    for n in 1..num_fragments {
        let identifier = CanIdentifier {
            source_address: packet.header.source_address,
            destination_address: packet.via_address(),
            fragment_type: FragmentType::More,
            remain: (num_fragments - n - 1).try_into().unwrap(),
            fragmentation_identifier,
        };
        let offset = 2 + CAN_PAYLOAD_SIZE * (n - 1);
        let end = (offset + CAN_PAYLOAD_SIZE).min(payload.len());
        fragments.push(CanFrame::new(identifier.serialize(), &payload[offset..end]).unwrap());
    }

    Ok(fragments)
}

#[derive(Debug, Clone, Eq, PartialEq, Default)]
struct CfpDefragmenter {
    map: HashMap<u32, CfpInProgress>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct CfpInProgress {
    packet: Packet,
    length: usize,
    remain: u8,
}

impl CfpDefragmenter {
    fn defragment(&mut self, identifier: CanIdentifier, data: &[u8]) -> Result<Option<Packet>> {
        let key = identifier.defragmentation_key();
        match identifier.fragment_type {
            FragmentType::Begin => {
                anyhow::ensure!(data.len() >= 6, "CFP begin fragment is too short");
                let via = Some(identifier.destination_address);
                let remain = identifier.remain;
                let header = Header::try_from(&data[..CSP_HEADER_SIZE])
                    .context("Failed to parse CSP header")?;
                let length = usize::from(u16::from_be_bytes(
                    data[CSP_HEADER_SIZE..CSP_HEADER_SIZE + CSP_LENGTH_FIELD_SIZE]
                        .try_into()
                        .unwrap(),
                ));
                let mut payload = Vec::with_capacity(length);
                payload.extend_from_slice(&data[CSP_HEADER_SIZE + CSP_LENGTH_FIELD_SIZE..]);
                let packet = Packet {
                    via,
                    header,
                    payload,
                };
                self.map.insert(
                    key,
                    CfpInProgress {
                        packet,
                        length,
                        remain,
                    },
                );
            }
            FragmentType::More => {
                let Entry::Occupied(mut entry) = self.map.entry(key) else {
                    anyhow::bail!(
                        "received CFP more fragment, but there are no previous fragments"
                    );
                };
                if identifier.remain != entry.get().remain - 1 {
                    entry.remove();
                    anyhow::bail!("CFP fragments lost, dropping existing fragments");
                }
                entry.get_mut().packet.payload.extend_from_slice(data);
                if entry.get().packet.payload.len() > entry.get().length {
                    entry.remove();
                    anyhow::bail!("accumulated CFP fragments are too long");
                }
                entry.get_mut().remain = identifier.remain;
            }
        }
        if let Entry::Occupied(entry) = self.map.entry(key)
            && entry.get().remain == 0
        {
            let defrag = entry.remove();
            let mut packet = defrag.packet;
            anyhow::ensure!(
                packet.payload.len() == defrag.length,
                "CFP defragmented length does not match length field"
            );
            if packet.header.flags.crc {
                let crc_offset = packet.payload.len() - CSP_CRC_SIZE;
                let (payload, crc) = packet.payload.split_at(crc_offset);
                anyhow::ensure!(
                    Packet::crc_is_correct(payload, crc.try_into().unwrap()),
                    "CSP CRC is wrong"
                );
                // remove CRC from payload
                packet.payload.truncate(crc_offset);
            }
            return Ok(Some(packet));
        };
        // TODO: prune old defragmentation entries
        Ok(None)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn serialize_identifier() {
        let identifier = CanIdentifier {
            source_address: 5,
            destination_address: 13,
            fragment_type: FragmentType::More,
            remain: 123,
            fragmentation_identifier: 754,
        };
        let serialized = identifier.serialize();
        let fragment_type = if identifier.fragment_type == FragmentType::More {
            1
        } else {
            0
        };
        let expected = ExtendedId::new(
            (u32::from(identifier.source_address) << 24)
                | (u32::from(identifier.destination_address) << 19)
                | (fragment_type << 18)
                | (u32::from(identifier.remain) << 10)
                | u32::from(identifier.fragmentation_identifier),
        )
        .unwrap();
        assert_eq!(serialized, expected);
    }

    #[test]
    fn deserialize_identifier() {
        let identifier = CanIdentifier::deserialize(ExtendedId::new(91090674).unwrap());
        let expected = CanIdentifier {
            source_address: 5,
            destination_address: 13,
            fragment_type: FragmentType::More,
            remain: 123,
            fragmentation_identifier: 754,
        };
        assert_eq!(identifier, expected);
    }

    #[test]
    fn fragment_defragment() {
        let packet = Packet {
            via: Some(17),
            header: Header {
                priority: crate::csp::Priority::Normal,
                source_address: 23,
                destination_address: 3,
                destination_port: 21,
                source_port: 57,
                reserved: 0,
                flags: crate::csp::Flags {
                    hmac: false,
                    xtea: false,
                    rdp: false,
                    crc: true,
                },
            },
            payload: (0..1000).map(|n| n as u8).collect(),
        };
        let fragmentation_identifier = 771;
        let fragments = cfp_fragments(&packet, fragmentation_identifier).unwrap();
        let mut defragmenter = CfpDefragmenter::default();
        for (n, fragment) in fragments.iter().enumerate() {
            let Id::Extended(identifier) = fragment.id() else {
                panic!();
            };
            let identifier = CanIdentifier::deserialize(identifier);
            let ret = defragmenter
                .defragment(identifier, fragment.data())
                .unwrap();
            if n == fragments.len() - 1 {
                assert_eq!(ret.as_ref(), Some(&packet));
            } else {
                assert!(ret.is_none());
            }
        }
    }
}
