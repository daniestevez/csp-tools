//! CSP.
//!
//! This module implements the Cubesat Space Protocol (CSP) v1 packet
//! format. The [`deku`] crate is used to implement serialization and
//! deserialization of the CSP header.

use deku::prelude::*;

/// CSP ping service port.
pub const PING_PORT: u8 = 1;

// CRC_32_ISCSI is the same as CRC-32C
const CRC_32C: crc::Crc<u32> = crc::Crc::<u32>::new(&crc::CRC_32_ISCSI);

/// CSP packet.
///
/// This structure contains a CSP packet and its related routing information.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Packet {
    /// Via routing information of the CSP packet.
    ///
    /// The via is the CSP address of the next hop. If this is `None`, then the
    /// via is missing, in which case the destination address in the CSP header
    /// is assumed to be the via.
    pub via: Option<u8>,
    /// CSP header.
    pub header: Header,
    /// Packet payload.
    pub payload: Vec<u8>,
}

/// CSP header size.
///
/// This indicates the CSP header size in bytes.
pub const CSP_HEADER_SIZE: usize = 4;

/// CSP CRC size.
///
/// This indicates the size of the CSP CRC-32C in bytes.
pub const CSP_CRC_SIZE: usize = 4;

impl Packet {
    /// Returns the length of the CSP packet.
    ///
    /// The length is measured in bytes and includes the CSP header, the
    /// payload, and the CRC if it is enabled.
    pub fn csp_len(&self) -> usize {
        CSP_HEADER_SIZE + self.payload.len() + self.crc_len()
    }

    /// Returns the length of the payload of the CSP packet.
    ///
    /// The length is measured in bytes and it includes both the payload data
    /// and the CRC if it is enabled.
    pub fn csp_payload_len(&self) -> usize {
        self.payload.len() + self.crc_len()
    }

    /// Returns the length of the framing overhead.
    ///
    /// The framing overhead is the CSP header, plus the CRC if it is enabled.
    pub fn csp_overhead_len(&self) -> usize {
        CSP_HEADER_SIZE + self.crc_len()
    }

    /// Returns the length of the CRC.
    ///
    /// This function returns [`CSP_CRC_SIZE`] if the CRC is enabled and zero if
    /// it is disabled.
    pub fn crc_len(&self) -> usize {
        if self.header.flags.crc {
            CSP_CRC_SIZE
        } else {
            0
        }
    }

    /// Returns the via address.
    ///
    /// If the via is missing, then the destination address in the CSP header is
    /// used as via.
    pub fn via_address(&self) -> u8 {
        self.via.unwrap_or(self.header.destination_address)
    }

    /// Returns the payload and CRC of the CSP packet.
    pub fn payload_and_crc(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(self.csp_payload_len());
        v.extend_from_slice(&self.payload[..]);
        if self.header.flags.crc {
            let crc = CRC_32C.checksum(&self.payload);
            v.extend_from_slice(&crc.to_be_bytes());
        }
        v
    }

    /// Returns whether the CRC is correct.
    ///
    /// This function returns `true` if `crc` is the CRC-32C of `payload`.
    pub fn crc_is_correct(payload: &[u8], crc: [u8; CSP_CRC_SIZE]) -> bool {
        let crc_computed = CRC_32C.checksum(payload);
        let crc_data = u32::from_be_bytes(crc);
        crc_computed == crc_data
    }
}

/// CSP header.
///
/// This struct contains the fields of the CSP header and uses [`deku`] for
/// serialization and deserialization.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, DekuRead, DekuWrite)]
pub struct Header {
    /// Priority.
    pub priority: Priority,
    /// Source CSP address.
    ///
    /// As any CSP address, this is a 5-bit integer.
    #[deku(bits = 5)]
    pub source_address: u8,
    /// Destination CSP address.
    ///
    /// As any CSP address, this is a 5-bit integer.
    #[deku(bits = 5)]
    pub destination_address: u8,
    /// Destination CSP port.
    ///
    /// As any CSP port, this is a 6-bit integer.
    #[deku(bits = 6)]
    pub destination_port: u8,
    /// Source CSP port.
    ///
    /// As any CSP port, this is a 6-bit integer.
    #[deku(bits = 6)]
    pub source_port: u8,
    /// Reserved bits.
    ///
    /// There are 4 bits in the CSP header which are reserved and must be zero.
    #[deku(bits = 4)]
    #[deku(assert_eq = "0")]
    pub reserved: u8,
    /// CSP flags.
    pub flags: Flags,
}

/// CSP priority.
///
/// The default priority is normal.
///
/// ```
/// use csp_tools::csp::Priority;
///
/// let priority = Priority::default();
/// assert_eq!(priority, Priority::Normal);
/// ```
#[derive(Debug, Copy, Clone, Eq, PartialEq, Default, Hash, DekuRead, DekuWrite)]
#[deku(id_type = "u8", bits = "2")]
pub enum Priority {
    /// Critical priority.
    #[deku(id = "0")]
    Critical,
    /// High priority.
    #[deku(id = "1")]
    High,
    /// Normal priority.
    ///
    /// This is the default priority returned by [`Priority::default()`].
    #[deku(id = "2")]
    #[default]
    Normal,
    /// Low priority.
    #[deku(id = "3")]
    Low,
}

/// CSP flags.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, DekuRead, DekuWrite)]
pub struct Flags {
    /// HMAC flag.
    ///
    /// This flag is asserted if HMAC is enabled.
    #[deku(bits = 1)]
    pub hmac: bool,
    /// XTEA flag.
    ///
    /// This flag is asserted if XTEA encryption is enabled.
    #[deku(bits = 1)]
    pub xtea: bool,
    /// RDP flag.
    ///
    /// This flag is asserted if the payload contains an RDP packet.
    #[deku(bits = 1)]
    pub rdp: bool,
    /// CRC flag.
    ///
    /// This flag is asserted if the packet contains a CRC-32C of the payload.
    #[deku(bits = 1)]
    pub crc: bool,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parse_header() {
        let header_bytes = [0xac, 0xa0, 0x79, 0x01];
        let header = Header::try_from(header_bytes.as_ref()).unwrap();
        assert_eq!(
            header,
            Header {
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
            }
        );
    }

    #[test]
    fn serialize_header() {
        let header = Header {
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
        };
        let header_bytes = [0xac, 0xa0, 0x79, 0x01];
        assert_eq!(header.to_bytes().unwrap(), &header_bytes);
    }
}
