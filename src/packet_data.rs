use pnet::{
    packet::{
        arp::{ArpHardwareType, ArpOperation, ArpPacket},
        ethernet::{EtherType, EthernetPacket},
        icmp::{IcmpCode, IcmpPacket, IcmpType},
        icmpv6::{Icmpv6Code, Icmpv6Packet, Icmpv6Type},
        ip::IpNextHeaderProtocol,
        ipv4::Ipv4Packet,
        ipv6::Ipv6Packet,
        tcp::{TcpOption, TcpPacket},
        udp::UdpPacket,
        Packet,
    },
    util::MacAddr,
};
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Clone)]
pub struct TcpPacketInfo {
    pub source: u16,
    pub destination: u16,
    pub sequence: u32,
    pub acknowledgement: u32,
    pub data_offset: u8,
    pub reserved: u8,
    pub flags: u8,
    pub window: u16,
    pub checksum: u16,
    pub urgent_ptr: u16,
    pub options: Vec<TcpOption>,
    pub length: usize,
}
impl<'a> From<&TcpPacket<'a>> for TcpPacketInfo {
    fn from(packet: &TcpPacket<'a>) -> Self {
        TcpPacketInfo {
            source: packet.get_source(),
            destination: packet.get_destination(),
            sequence: packet.get_sequence(),
            acknowledgement: packet.get_acknowledgement(),
            data_offset: packet.get_data_offset(),
            reserved: packet.get_reserved(),
            flags: packet.get_flags(),
            window: packet.get_window(),
            checksum: packet.get_checksum(),
            urgent_ptr: packet.get_urgent_ptr(),
            options: packet.get_options(),
            length: packet.payload().len(),
        }
    }
}

#[derive(Clone)]
pub struct UdpPacketInfo {
    pub source: u16,
    pub destination: u16,
    pub length: u16,
    pub checksum: u16,
}
impl<'a> From<&UdpPacket<'a>> for UdpPacketInfo {
    fn from(packet: &UdpPacket<'a>) -> Self {
        UdpPacketInfo {
            source: packet.get_source(),
            destination: packet.get_destination(),
            length: packet.get_length(),
            checksum: packet.get_checksum(),
        }
    }
}

#[derive(Clone)]
pub struct Icmpv6PacketInfo {
    pub icmpv6_type: Icmpv6Type,
    pub icmpv6_code: Icmpv6Code,
    pub checksum: u16,
    pub length: usize,
}
impl<'a> From<&Icmpv6Packet<'a>> for Icmpv6PacketInfo {
    fn from(packet: &Icmpv6Packet<'a>) -> Self {
        Icmpv6PacketInfo {
            icmpv6_type: packet.get_icmpv6_type(),
            icmpv6_code: packet.get_icmpv6_code(),
            checksum: packet.get_checksum(),
            length: packet.payload().len(),
        }
    }
}
#[derive(Clone)]
pub struct IcmpPacketInfo {
    pub icmp_type: IcmpType,
    pub icmp_code: IcmpCode,
    pub checksum: u16,
    pub length: usize,
}
impl<'a> From<&IcmpPacket<'a>> for IcmpPacketInfo {
    fn from(packet: &IcmpPacket<'a>) -> Self {
        IcmpPacketInfo {
            icmp_type: packet.get_icmp_type(),
            icmp_code: packet.get_icmp_code(),
            checksum: packet.get_checksum(),
            length: packet.payload().len(),
        }
    }
}

#[derive(Clone)]
pub struct EthernetPacketInfo {
    pub destination: MacAddr,
    pub source: MacAddr,
    pub ethertype: EtherType,
    pub payload: Vec<u8>,
}
impl<'p> From<&EthernetPacket<'p>> for EthernetPacketInfo {
    fn from(packet: &EthernetPacket) -> Self {
        EthernetPacketInfo {
            destination: packet.get_destination(),
            source: packet.get_source(),
            ethertype: packet.get_ethertype(),
            payload: packet.payload().to_vec(),
        }
    }
}

#[derive(Clone)]
pub struct ArpPacketInfo {
    pub hardware_type: ArpHardwareType,
    pub protocol_type: EtherType,
    pub hw_addr_len: u8,
    pub proto_addr_len: u8,
    pub operation: ArpOperation,
    pub sender_hw_addr: MacAddr,
    pub sender_proto_addr: Ipv4Addr,
    pub target_hw_addr: MacAddr,
    pub target_proto_addr: Ipv4Addr,
    pub length: usize,
}
impl<'p> From<&ArpPacket<'p>> for ArpPacketInfo {
    fn from(packet: &ArpPacket) -> Self {
        ArpPacketInfo {
            hardware_type: packet.get_hardware_type(),
            protocol_type: packet.get_protocol_type(),
            hw_addr_len: packet.get_hw_addr_len(),
            proto_addr_len: packet.get_proto_addr_len(),
            operation: packet.get_operation(),
            sender_hw_addr: packet.get_sender_hw_addr(),
            sender_proto_addr: packet.get_sender_proto_addr(),
            target_hw_addr: packet.get_target_hw_addr(),
            target_proto_addr: packet.get_target_proto_addr(),
            length: packet.payload().len(),
        }
    }
}
#[derive(Clone)]
pub struct Ipv6PacketInfo {
    pub version: u8,
    pub traffic_class: u8,
    pub flow_label: u32,
    pub payload_length: u16,
    pub next_header: IpNextHeaderProtocol,
    pub hop_limit: u8,
    pub source: Ipv6Addr,
    pub destination: Ipv6Addr,
    pub length: usize,
}
impl<'a> From<&Ipv6Packet<'a>> for Ipv6PacketInfo {
    fn from(packet: &Ipv6Packet<'a>) -> Self {
        Ipv6PacketInfo {
            version: packet.get_version(),
            traffic_class: packet.get_traffic_class(),
            flow_label: packet.get_flow_label(),
            payload_length: packet.get_payload_length(),
            next_header: packet.get_next_header(),
            hop_limit: packet.get_hop_limit(),
            source: packet.get_source(),
            destination: packet.get_destination(),
            length: packet.payload().len(),
        }
    }
}

#[derive(Clone)]
pub struct Ipv4PacketInfo {
    pub version: u8,
    pub header_length: u8,
    pub dscp: u8,
    pub ecn: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub next_level_protocol: IpNextHeaderProtocol,
    pub checksum: u16,
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub length: usize,
}
impl<'a> From<&Ipv4Packet<'a>> for Ipv4PacketInfo {
    fn from(packet: &Ipv4Packet<'a>) -> Self {
        Ipv4PacketInfo {
            version: packet.get_version(),
            header_length: packet.get_header_length(),
            dscp: packet.get_dscp(),
            ecn: packet.get_ecn(),
            total_length: packet.get_total_length(),
            identification: packet.get_identification(),
            flags: packet.get_flags(),
            fragment_offset: packet.get_fragment_offset(),
            ttl: packet.get_ttl(),
            next_level_protocol: packet.get_next_level_protocol(),
            checksum: packet.get_checksum(),
            source: packet.get_source(),
            destination: packet.get_destination(),
            length: packet.payload().len(),
        }
    }
}

#[derive(Clone)]
pub enum PacketsData {
    EthernetPacket(EthernetPacketInfo),
    ArpPacket(ArpPacketInfo),
    Ipv4Packet(Ipv4PacketInfo),
    Ipv6Packet(Ipv6PacketInfo),
    TcpPacket(TcpPacketInfo),
    UdpPacket(UdpPacketInfo),
    IcmpPacket(IcmpPacketInfo),
    Icmpv6Packet(Icmpv6PacketInfo),
}

#[derive(Clone)]
pub struct CompletePacket {
    pub id: usize,
    pub layer_1: Option<PacketsData>,
    pub layer_2: Option<PacketsData>,
    pub layer_3: Option<PacketsData>,
}

impl CompletePacket {
    pub fn new(id: usize) -> Self {
        CompletePacket {
            id,
            layer_1: None,
            layer_2: None,
            layer_3: None,
        }
    }
    pub fn set_layer1_packet(&mut self, packet: Option<PacketsData>) {
        self.layer_1 = packet;
    }
    pub fn set_layer2_packet(&mut self, packet: Option<PacketsData>) {
        self.layer_2 = packet;
    }
    pub fn set_layer3_packet(&mut self, packet: Option<PacketsData>) {
        self.layer_3 = packet;
    }
}
