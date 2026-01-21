# csp-tools

This is a Rust crate that contains some CLI tools for the [Cubesat Space
Protocol](https://en.wikipedia.org/wiki/Cubesat_Space_Protocol) (CSP). It can
also be used as a library for processing CSP and related protocols.

The tools included are:

- `cspdump`. A tool similar to `tcpdump`. It receives CSP packets from a ZMQ
  socket or a CAN interface and writes them to a PCAP file.

- `csp-iperf`. A tool similar to `iperf`. It sends CSP packets through a ZMQ
  socket or a CAN interface, expects these packets to be replied by a ping
  service, and measures throughput, RTT and lost packets.

- `csp-ping-server`. A tool that implements a ping service. It can be used in
  combination with `csp-iperf` to perform network performance measurements.

## Wireshark dissector

This repository also contains a Wireshark Lua dissector that can parse CSP and
RDP packets (in this context, RDP is the [reliable datagram
protocol](https://github.com/libcsp/libcsp/blob/develop/src/csp_rdp.c) used in
CSP for sequence controlled reliable delivery). The dissector can be installed
by running

```
just install-wireshark
```

Running this requires [just](github.com/casey/just).

There are also some recommended Wireshark coloring rules in
[wireshark-dissector/coloring-rules](./wireshark-dissector/coloring-rules). These
can be imported into Wireshark by going to "View > Coloring Rules..." and
clicking on "Import...".

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
