//! CSP interfaces.
//!
//! This module contains code to handle network interfaces that can be used with
//! CSP. These interfaces are a CAN interface and a ZMQ socket.

use crate::csp::Packet;
use anyhow::{Context, Result};
use socketcan::{CanSocket, Socket, SocketOptions};

mod can;
mod zmq;

pub use can::CanInterface;
pub use zmq::ZmqInterface;

/// Abstract CSP interface.
///
/// This trait represents an abstract CSP network interface that can receive and
/// send packets.
pub trait Interface {
    /// Send CSP packet through the interface.
    ///
    /// This function sends the CSP packet `packet` through the interface. The
    /// function blocks until the packet is sent.
    fn send(&mut self, packet: &Packet) -> Result<()>;

    /// Receive a CSP packet through the interface.
    ///
    /// This function waits until a CSP packet is received by the interface and
    /// returns the packet.
    fn receive(&mut self) -> Result<Packet>;

    /// Receive a raw packet through the interface.
    ///
    /// This function attempts to wait until a packet is received by the
    /// interface and it returns the packet as a `Vec<u8>`. Unlike
    /// [`Interface::receive`], this function does not try to parse the packet
    /// as a CSP packet, so it can successfully return packets that are
    /// malformed when parsed as CSP packets.
    fn receive_raw(&mut self) -> Result<Vec<u8>>;
}

/// CSP interface.
///
/// This enum represents the possible CSP interfaces, which are a CAN interface
/// and a ZMQ socket. The CAN interface contains an optional callback function
/// that is called with every CAN frame received on the interface. The type
/// generic `Callback` is the type of the callback function. The default
/// `Callback = ()` means no callback.
pub enum CspInterface<Callback = ()> {
    /// CAN CSP interface.
    ///
    /// This is a CAN interface that transmits CSP packets using the
    /// [CAN Fragmentation Protocol]
    /// (<https://github.com/libcsp/libcsp/blob/develop/include/csp/interfaces/csp_if_can.h>)
    /// (CFP).
    Can(CanInterface<Callback>),
    /// ZMQ socket CSP interface.
    Zmq(ZmqInterface),
}

impl<Callback: can::CallbackFn> Interface for CspInterface<Callback> {
    fn send(&mut self, packet: &Packet) -> Result<()> {
        match self {
            CspInterface::Can(can) => can.send(packet),
            CspInterface::Zmq(zmq) => zmq.send(packet),
        }
    }

    fn receive(&mut self) -> Result<Packet> {
        match self {
            CspInterface::Can(can) => can.receive(),
            CspInterface::Zmq(zmq) => zmq.receive(),
        }
    }

    fn receive_raw(&mut self) -> Result<Vec<u8>> {
        match self {
            CspInterface::Can(can) => can.receive_raw(),
            CspInterface::Zmq(zmq) => zmq.receive_raw(),
        }
    }
}

/// Open CSP interfaces for TX and RX.
///
/// This function opens an interface according to the given arguments and
/// returns a pair of [`CspInterface`] objects that can be used respectively to
/// send (TX) and receive (RX) packets on that interface.
///
/// If `can_interface` is a `Some`, then a CAN interface is opened. If
/// `can_interface` is `None`, then the `zmq_tx_address` and `zmq_rx_address`
/// arguments are used to open a ZMQ interface.
///
/// The `source_address` is the CSP address corresponding to this interface, and
/// it is used to filter packets addressed to this destination in the RX
/// interface. In the case of a CAN interface, a CAN address filter is used. In
/// the case of a ZMQ interface, topic subscription is used to filter packets.
pub fn open_csp_interfaces(
    can_interface: Option<impl AsRef<str>>,
    zmq_tx_address: &str,
    zmq_rx_address: &str,
    source_address: u8,
) -> Result<(CspInterface, CspInterface)> {
    if let Some(can_interface) = can_interface {
        let can_interface = can_interface.as_ref();
        let tx_interface = CspInterface::Can(CanInterface::new(
            CanSocket::open(can_interface)
                .with_context(|| format!("Failed to open CAN interface {can_interface}"))?,
        ));
        let rx_socket = CanSocket::open(can_interface)
            .with_context(|| format!("Failed to open CAN interface {can_interface}"))?;
        rx_socket
            .set_filters(&[can::destination_address_can_filter(source_address)])
            .context("Failed to set CAN source address filter")?;
        let rx_interface = CspInterface::Can(CanInterface::new(rx_socket));
        Ok((tx_interface, rx_interface))
    } else {
        let zmq_context = ::zmq::Context::new();
        let tx_interface = CspInterface::Zmq(ZmqInterface::new_pub(&zmq_context, zmq_tx_address)?);
        let rx_interface = CspInterface::Zmq(ZmqInterface::new_sub(
            &zmq_context,
            zmq_rx_address,
            [source_address].into_iter(),
        )?);
        Ok((tx_interface, rx_interface))
    }
}
