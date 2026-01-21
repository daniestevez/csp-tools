--
-- CSP ZMQ Wireshark dissector
--
-- Copyright (c) 2025 Daniel Estevez <daniel@destevez.net>
--
-- SPDX-License-Identifier: GPL-2.0-or-later
--

cspzmq_proto = Proto.new("CSP-ZMQ", "Cubesat Space Protocol over ZMQ")

csp_proto = Proto.new("CSP", "Cubesat Space Protocol")

rdp_proto = Proto.new("CSPRDP", "CSP Reliable Data Protocol")

zmq_dest_address = ProtoField.uint8("cspzmq.zmq_dest_addr",
                                    "ZMQ destination CSP address", base.DEC, NULL)

csp_priority_table = {
   [0] = "Critical",
   [1] = "High",
   [2] = "Normal",
   [3] = "Low"
}

csp_priority = ProtoField.uint32("csp.priority",
                                 "Priority", base.DEC, csp_priority_table, 0xC0000000)

csp_source = ProtoField.uint32("csp.source",
                               "Source", base.DEC, NULL, 0x3E000000)

csp_destination = ProtoField.uint32("csp.destination",
                                    "Destination", base.DEC, NULL, 0x01F00000)

csp_destination_port = ProtoField.uint32("csp.destination_port",
                                         "Destination port", base.DEC, NULL, 0x000FC000)

csp_source_port = ProtoField.uint32("csp.source_port",
                                    "Source port", base.DEC, NULL, 0x00003F00)

csp_reserved = ProtoField.uint32("csp.reserved",
                                 "CSP header reserved bits", base.BIN, NULL, 0x000000F0)

csp_hmac_flag = ProtoField.uint32("csp.hmac_flag",
                                  "HMAC flag", base.BIN, NULL, 0x00000008)

csp_xtea_flag = ProtoField.uint32("csp.xtea_flag",
                                  "XTEA flag", base.BIN, NULL, 0x00000004)

csp_rdp_flag = ProtoField.uint32("csp.rdp_flag",
                                 "RDP flag", base.BIN, NULL, 0x00000002)

csp_crc_flag = ProtoField.uint32("csp.crc_flag",
                                 "CRC flag", base.BIN, NULL, 0x00000001)

csp_crc = ProtoField.uint32("csp.crc", "CRC", base.HEX, NULL)

rdp_reserved = ProtoField.uint8("csp.rdp.reserved", "Reserved bits", base.BIN, NULL, 0xF0)

rdp_syn_flag = ProtoField.uint8("csp.rdp.syn_flag", "SYN flag", base.BIN, NULL, 0x8)

rdp_ack_flag = ProtoField.uint8("csp.rdp.ack_flag", "ACK flag", base.BIN, NULL, 0x4)

rdp_eak_flag = ProtoField.uint8("csp.rdp.eak_flag", "EAK flag", base.BIN, NULL, 0x2)

rdp_rst_flag = ProtoField.uint8("csp.rdp.rst_flag", "RST flag", base.BIN, NULL, 0x1)

rdp_seq = ProtoField.uint16("csp.rdp.seq", "Sequence number", base.DEC, NULL)

rdp_ack = ProtoField.uint16("csp.rdp.ack", "ACK number", base.DEC, NULL)

rdp_eak = ProtoField.uint16("csp.rdp.eak", "EAK number", base.DEC, NULL)

rdp_syn_window_size = ProtoField.uint32("csp.rdp.syn.window_size", "Window size", base.DEC, NULL)

rdp_syn_conn_timeout = ProtoField.uint32("csp.rdp.syn.conn_timeout", "Connection timeout", base.DEC, NULL)

rdp_syn_packet_timeout = ProtoField.uint32("csp.rdp.syn.packet_timeout", "Packet timeout", base.DEC, NULL)

rdp_syn_delayed_acks = ProtoField.uint32("csp.rdp.syn.delayed_acks", "Delayed ACKs", base.DEC, NULL)

rdp_syn_ack_timeout = ProtoField.uint32("csp.rdp.syn.ack_timeout", "ACK timeout", base.DEC, NULL)

rdp_syn_ack_delay_count = ProtoField.uint32("csp.rdp.syn.ack_delay_count", "ACK delay count", base.DEC, NULL)

rdp_analysis = ProtoField.none("csp.rdp.analysis", "RDP analysis")

cspzmq_proto.fields = { zmq_dest_address }

csp_proto.fields = {
   csp_priority, csp_source, csp_destination,
   csp_destination_port, csp_source_port, csp_reserved, csp_hmac_flag,
   csp_xtea_flag, csp_rdp_flag, csp_crc_flag, csp_crc
}

rdp_proto.fields = {
   rdp_reserved, rdp_syn_flag, rdp_ack_flag, rdp_eak_flag, rdp_rst_flag, rdp_seq, rdp_ack,
   rdp_eak, rdp_syn_window_size, rdp_syn_conn_timeout, rdp_syn_packet_timeout, rdp_syn_delayed_acks,
   rdp_syn_ack_timeout, rdp_syn_ack_delay_count, rdp_analysis
}

zmq_dest_address_field = Field.new("cspzmq.zmq_dest_addr")
priority_field = Field.new("csp.priority")
source_field = Field.new("csp.source")
destination_field = Field.new("csp.destination")
source_port_field = Field.new("csp.source_port")
destination_port_field = Field.new("csp.destination_port")
hmac_flag_field = Field.new("csp.hmac_flag")
xtea_flag_field = Field.new("csp.xtea_flag")
rdp_flag_field = Field.new("csp.rdp_flag")
crc_flag_field = Field.new("csp.crc_flag")
rdp_syn_flag_field = Field.new("csp.rdp.syn_flag")
rdp_ack_flag_field = Field.new("csp.rdp.ack_flag")
rdp_eak_flag_field = Field.new("csp.rdp.eak_flag")
rdp_rst_flag_field = Field.new("csp.rdp.rst_flag")
rdp_seq_field = Field.new("csp.rdp.seq")
rdp_ack_field = Field.new("csp.rdp.ack")
rdp_analysis_field = Field.new("csp.rdp.analysis")

rdp_expected_seq = {}
rdp_seq_analysis = {}

function cspzmq_proto.dissector(buffer, pinfo, tree)
  pinfo.cols.protocol = "CSP"

  local subtree = tree:add(cspzmq_proto, buffer())
  subtree:add(zmq_dest_address, buffer(0,1))
  subtree.text = string.format("%s, Dst: %d", subtree.text, zmq_dest_address_field()())
  local subtree = tree:add(csp_proto, buffer(1, buffer:len()-1))
  subtree:add_le(csp_priority, buffer(1,4))
  subtree:add_le(csp_source, buffer(1,4))
  subtree:add_le(csp_destination, buffer(1,4))
  subtree:add_le(csp_destination_port, buffer(1,4))
  subtree:add_le(csp_source_port, buffer(1,4))
  subtree:add_le(csp_reserved, buffer(1,4))
  subtree:add_le(csp_hmac_flag, buffer(1,4))
  subtree:add_le(csp_xtea_flag, buffer(1,4))
  subtree:add_le(csp_rdp_flag, buffer(1,4))
  subtree:add_le(csp_crc_flag, buffer(1,4))
  subtree.text = string.format("%s, Src: %d:%d, Dst: %d:%d",
                               subtree.text, source_field()(), source_port_field()(),
                               destination_field()(), destination_port_field()())

  local conv_id = string.format("%d:%d-%d:%d", source_field()(), source_port_field()(),
                                destination_field()(), destination_port_field()())

  local payload
  if crc_flag_field()() == 1 then
     payload = buffer:range(5, buffer:len()-9):tvb()
  else
     payload = buffer:range(5, buffer:len()-5):tvb()
  end

  local rdp
  local eak_numbers = {}
  if rdp_flag_field()() == 1 then
     payload_rdp = payload(0)
     rdp = payload(payload:len()-5,5)
     payload = payload:range(0, payload:len()-5):tvb()

     local subtree = tree:add(rdp_proto, payload_rdp)
     subtree:add(rdp_reserved, rdp(0,1))
     subtree:add(rdp_syn_flag, rdp(0,1))
     subtree:add(rdp_ack_flag, rdp(0,1))
     subtree:add(rdp_eak_flag, rdp(0,1))
     subtree:add(rdp_rst_flag, rdp(0,1))
     subtree:add(rdp_seq, rdp(1,2))
     subtree:add(rdp_ack, rdp(3,2))

     if rdp_eak_flag_field()() == 1 then
        if payload:len() > 0 then
           for offset=0,payload:len()-2,2 do
              subtree:add(rdp_eak, payload(offset,2))
              table.insert(eak_numbers, string.format("%d", payload(offset,2):uint64():tonumber()))
           end
           payload = payload:range(0,0):tvb()
        end
     end

     if pinfo.visited == false then
        if rdp_syn_flag_field()() == 1 then
           rdp_expected_seq[conv_id] = (rdp_seq_field()() + 1) % 65536
        else
           local expected_seq = rdp_expected_seq[conv_id]
           if rdp_seq_field()() == expected_seq then
              if payload:len() > 0 then
                 rdp_expected_seq[conv_id] = (expected_seq + 1) % 65536
              end
           elseif (expected_seq - rdp_seq_field()()) % 65536 < 32768 then
              rdp_seq_analysis[pinfo.number] = string.format("Retransmission: ACK %d expected %d", rdp_seq_field()(), expected_seq)
           else
              rdp_seq_analysis[pinfo.number] = string.format("Out of order: ACK %d expected %d", rdp_seq_field()(), expected_seq)
              rdp_expected_seq[conv_id] = (rdp_seq_field()() + 1) % 65536
           end
        end
     end

     if rdp_seq_analysis[pinfo.number] then
        local analysis = subtree:add(rdp_analysis)
        analysis:add_expert_info(PI_SEQUENCE, PI_NOTE, rdp_seq_analysis[pinfo.number])
     end

     if rdp_syn_flag_field()() == 1 and rdp_ack_flag_field()() == 0 and payload:len() == 24 then
        subtree:add(rdp_syn_window_size, payload(0,4))
        subtree:add(rdp_syn_conn_timeout, payload(4,4))
        subtree:add(rdp_syn_packet_timeout, payload(8,4))
        subtree:add(rdp_syn_delayed_acks, payload(12,4))
        subtree:add(rdp_syn_ack_timeout, payload(16,4))
        subtree:add(rdp_syn_ack_delay_count, payload(20,4))
        payload = payload:range(0,0):tvb()
     end

     subtree.text = string.format("%s, Seq: %d, Ack: %d, Len: %d", subtree.text,
                                  rdp_seq_field()(), rdp_ack_field()(), payload:len())
  end

  if crc_flag_field()() == 1 then
     subtree:add(csp_crc, buffer(buffer:len()-4,4))
  end

  pinfo.cols.src = string.format("%d", source_field()())
  pinfo.cols.dst = string.format("%d", destination_field()())
  local flags = ""
  if hmac_flag_field()() == 1 then
     flags = flags .. "H"
  end
  if xtea_flag_field()() == 1 then
     flags = flags .. "X"
  end
  if rdp_flag_field()() == 1 then
     flags = flags .. "R"
  end
  if crc_flag_field()() == 1 then
     flags = flags .. "C"
  end
  local info = string.format(
     "%d → %d [%s] Priority=%s Len=%d",
     source_port_field()(), destination_port_field()(), flags, priority_field()(),
     payload:len())
  if rdp_flag_field()() == 1 then
     pinfo.cols.protocol = "RDP"
     local flags = {}
     if rdp_syn_flag_field()() == 1 then
        table.insert(flags, "SYN")
     end
     if rdp_ack_flag_field()() == 1 then
        table.insert(flags, "ACK")
     end
     if rdp_eak_flag_field()() == 1 then
        table.insert(flags, "EAK")
     end
     if rdp_rst_flag_field()() == 1 then
        table.insert(flags, "RST")
     end
     flags = table.concat(flags, ", ")
     info = string.format("%d → %d [%s] Seq=%d Ack=%d Len=%d",
                          source_port_field()(), destination_port_field()(), flags,
                          rdp_seq_field()(), rdp_ack_field()(), payload:len())
     if rdp_eak_flag_field()() == 1 then
        info = string.format("%s Eak=%s",
                             info, table.concat(eak_numbers, ","))
     end
  end
  pinfo.cols.info = info

  if payload:len() > 0 then
     Dissector.get("data"):call(payload:range(0):tvb(), pinfo, tree)
  end
end

local ltype = DissectorTable.get("sll.ltype")
ltype:add(0, cspzmq_proto)
