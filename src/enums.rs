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
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Style, Stylize},
    text::Span,
    widgets::{Block, Borders, Padding, Paragraph, Row, Table},
    Frame,
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
impl TcpPacketInfo {
    pub fn render(self, block: Rect, frame: &mut Frame) {
        let (title_block, data_block) = {
            let chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Length(10), Constraint::Fill(1)])
                .margin(2)
                .split(block);
            (chunks[0], chunks[1])
        };
        let title = Paragraph::new("TCP")
            .bold()
            .block(Block::new().padding(Padding::top({
                if title_block.height % 2 == 0 {
                    (title_block.height / 2).saturating_sub(1)
                } else {
                    title_block.height / 2
                }
            })));
        let widths = [Constraint::Length(23), Constraint::Fill(1)];
        let infos = [
            Row::new(vec![
                Span::styled("Source Port", Style::new().bold()),
                Span::from(self.source.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Destination Port", Style::new().bold()),
                Span::from(self.destination.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Sequence Number", Style::new().bold()),
                Span::from(self.sequence.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Acknowledgement", Style::new().bold()),
                Span::from(self.acknowledgement.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Window Size", Style::new().bold()),
                Span::from(self.window.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Checksum", Style::new().bold()),
                Span::from(format!("0x{:04x}", self.checksum)),
            ]),
            Row::new(vec![
                Span::styled("Flags (raw)", Style::new().bold()),
                Span::from(self.flags.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Urgent Pointer", Style::new().bold()),
                Span::from(self.urgent_ptr.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Options", Style::new().bold()),
                Span::from(format!("{:?}", self.options)),
            ]),
            Row::new(vec![
                Span::styled("Payload Length", Style::new().bold()),
                Span::from(self.length.to_string()),
            ]),
        ];
        let table = Table::new(infos, widths).column_spacing(2).block(
            Block::default()
                .borders(Borders::LEFT)
                .border_style(Style::new().bold())
                .border_type(ratatui::widgets::BorderType::Thick)
                .style(Style::default()),
        );
        frame.render_widget(table, data_block);
        frame.render_widget(title, title_block);
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
impl UdpPacketInfo {
    pub fn render(self, block: Rect, frame: &mut Frame) {
        let (title_block, data_block) = {
            let chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Length(10), Constraint::Fill(1)])
                .margin(2)
                .split(block);
            (chunks[0], chunks[1])
        };
        let title = Paragraph::new("UDP")
            .bold()
            .block(Block::new().padding(Padding::top({
                if title_block.height % 2 == 0 {
                    (title_block.height / 2).saturating_sub(1)
                } else {
                    title_block.height / 2
                }
            })));
        let widths = [Constraint::Length(23), Constraint::Fill(1)];
        let infos = [
            Row::new(vec![
                Span::styled("Source Port", Style::new().bold()),
                Span::from(self.source.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Destination Port", Style::new().bold()),
                Span::from(self.destination.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Length", Style::new().bold()),
                Span::from(self.length.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Checksum", Style::new().bold()),
                Span::from(format!("0x{:04x}", self.checksum)),
            ]),
        ];
        let table = Table::new(infos, widths).column_spacing(2).block(
            Block::default()
                .borders(Borders::LEFT)
                .border_style(Style::new().bold().magenta())
                .border_type(ratatui::widgets::BorderType::Thick)
                .style(Style::default()),
        );
        frame.render_widget(table, data_block);
        frame.render_widget(title, title_block);
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
impl Icmpv6PacketInfo {
    pub fn render(self, block: Rect, frame: &mut Frame) {
        let (title_block, data_block) = {
            let chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Length(10), Constraint::Fill(1)])
                .margin(2)
                .split(block);
            (chunks[0], chunks[1])
        };
        let title = Paragraph::new("ICMPv6")
            .bold()
            .block(Block::new().padding(Padding::top({
                if title_block.height % 2 == 0 {
                    (title_block.height / 2).saturating_sub(1)
                } else {
                    title_block.height / 2
                }
            })));
        let widths = [Constraint::Length(23), Constraint::Fill(1)];
        let infos = [
            Row::new(vec![
                Span::styled("Type", Style::new().bold()),
                Span::from(format!("{:?}", self.icmpv6_type)),
            ]),
            Row::new(vec![
                Span::styled("Code", Style::new().bold()),
                Span::from(format!("{:?}", self.icmpv6_code)),
            ]),
            Row::new(vec![
                Span::styled("Checksum", Style::new().bold()),
                Span::from(format!("0x{:04x}", self.checksum)),
            ]),
            Row::new(vec![
                Span::styled("Payload Length", Style::new().bold()),
                Span::from(self.length.to_string()),
            ]),
        ];
        let table = Table::new(infos, widths).column_spacing(2).block(
            Block::default()
                .borders(Borders::LEFT)
                .border_style(Style::new().bold().magenta())
                .border_type(ratatui::widgets::BorderType::Thick)
                .style(Style::default()),
        );
        frame.render_widget(table, data_block);
        frame.render_widget(title, title_block);
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
impl IcmpPacketInfo {
    pub fn render(self, block: Rect, frame: &mut Frame) {
        let (title_block, data_block) = {
            let chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Length(10), Constraint::Fill(1)])
                .margin(2)
                .split(block);
            (chunks[0], chunks[1])
        };
        let title = Paragraph::new("ICMP")
            .bold()
            .block(Block::new().padding(Padding::top({
                if title_block.height % 2 == 0 {
                    (title_block.height / 2).saturating_sub(1)
                } else {
                    title_block.height / 2
                }
            })));
        let widths = [Constraint::Length(23), Constraint::Fill(1)];
        let infos = [
            Row::new(vec![
                Span::styled("Type", Style::new().bold()),
                Span::from(format!("{:?}", self.icmp_type)),
            ]),
            Row::new(vec![
                Span::styled("Code", Style::new().bold()),
                Span::from(format!("{:?}", self.icmp_code)),
            ]),
            Row::new(vec![
                Span::styled("Checksum", Style::new().bold()),
                Span::from(format!("0x{:04x}", self.checksum)),
            ]),
            Row::new(vec![
                Span::styled("Payload Length", Style::new().bold()),
                Span::from(self.length.to_string()),
            ]),
        ];
        let table = Table::new(infos, widths).column_spacing(2).block(
            Block::default()
                .borders(Borders::LEFT)
                .border_style(Style::new().bold())
                .border_type(ratatui::widgets::BorderType::Thick)
                .style(Style::default()),
        );
        frame.render_widget(table, data_block);
        frame.render_widget(title, title_block);
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
impl EthernetPacketInfo {
    pub fn render(self, block: Rect, frame: &mut Frame) {
        let (title_block, data_block) = {
            let chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Length(10), Constraint::Fill(1)])
                .margin(2)
                .split(block);
            (chunks[0], chunks[1])
        };
        let title = Paragraph::new("Ethernet")
            .bold()
            .block(Block::new().padding(Padding::top({
                if title_block.height % 2 == 0 {
                    (title_block.height / 2).saturating_sub(1)
                } else {
                    title_block.height / 2
                }
            })));
        let widths = [Constraint::Length(23), Constraint::Fill(1)];
        let infos = [
            Row::new(vec![
                Span::styled("Destination MAC", Style::new().bold()),
                Span::from(self.destination.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Source MAC", Style::new().bold()),
                Span::from(self.source.to_string()),
            ]),
            Row::new(vec![
                Span::styled("EtherType", Style::new().bold()),
                Span::from(format!("{:?}", self.ethertype)),
            ]),
            Row::new(vec![
                Span::styled("Payload Length", Style::new().bold()),
                Span::from(self.payload.len().to_string()),
            ]),
        ];
        let table = Table::new(infos, widths).column_spacing(2).block(
            Block::default()
                .borders(Borders::LEFT)
                .border_style(Style::new().bold())
                .border_type(ratatui::widgets::BorderType::Thick)
                .style(Style::default()),
        );
        frame.render_widget(table, data_block);
        frame.render_widget(title, title_block);
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
impl ArpPacketInfo {
    pub fn render(self, block: Rect, frame: &mut Frame) {
        let (title_block, data_block) = {
            let chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Length(10), Constraint::Fill(1)])
                .margin(2)
                .split(block);
            (chunks[0], chunks[1])
        };
        let title = Paragraph::new("ARP")
            .bold()
            .block(Block::new().padding(Padding::top({
                if title_block.height % 2 == 0 {
                    (title_block.height / 2).saturating_sub(1)
                } else {
                    title_block.height / 2
                }
            })));
        let widths = [Constraint::Length(23), Constraint::Fill(1)];
        let infos = [
            Row::new(vec![
                Span::styled("Operation", Style::new().bold()),
                Span::from(format!("{:?}", self.operation)),
            ]),
            Row::new(vec![
                Span::styled("Sender MAC", Style::new().bold()),
                Span::from(self.sender_hw_addr.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Sender IP", Style::new().bold()),
                Span::from(self.sender_proto_addr.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Target MAC", Style::new().bold()),
                Span::from(self.target_hw_addr.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Target IP", Style::new().bold()),
                Span::from(self.target_proto_addr.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Hardware Type", Style::new().bold()),
                Span::from(format!("{:?}", self.hardware_type)),
            ]),
            Row::new(vec![
                Span::styled("Protocol Type", Style::new().bold()),
                Span::from(format!("{:?}", self.protocol_type)),
            ]),
        ];
        let table = Table::new(infos, widths).column_spacing(2).block(
            Block::default()
                .borders(Borders::LEFT)
                .border_style(Style::new().bold())
                .border_type(ratatui::widgets::BorderType::Thick)
                .style(Style::default()),
        );
        frame.render_widget(table, data_block);
        frame.render_widget(title, title_block);
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
impl Ipv6PacketInfo {
    pub fn render(self, block: Rect, frame: &mut Frame) {
        let (title_block, data_block) = {
            let chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Length(10), Constraint::Fill(1)])
                .margin(2)
                .split(block);
            (chunks[0], chunks[1])
        };
        let title = Paragraph::new("IPv6")
            .bold()
            .block(Block::new().padding(Padding::top({
                if title_block.height % 2 == 0 {
                    (title_block.height / 2).saturating_sub(1)
                } else {
                    title_block.height / 2
                }
            })));
        let widths = [Constraint::Length(23), Constraint::Fill(1)];
        let infos = [
            Row::new(vec![
                Span::styled("Source IP", Style::new().bold()),
                Span::from(self.source.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Destination IP", Style::new().bold()),
                Span::from(self.destination.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Next Header", Style::new().bold()),
                Span::from(format!("{:?}", self.next_header)),
            ]),
            Row::new(vec![
                Span::styled("Traffic Class", Style::new().bold()),
                Span::from(self.traffic_class.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Flow Label", Style::new().bold()),
                Span::from(self.flow_label.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Payload Length", Style::new().bold()),
                Span::from(self.payload_length.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Hop Limit", Style::new().bold()),
                Span::from(self.hop_limit.to_string()),
            ]),
        ];
        let table = Table::new(infos, widths).column_spacing(2).block(
            Block::default()
                .borders(Borders::LEFT)
                .border_style(Style::new().bold())
                .border_type(ratatui::widgets::BorderType::Thick)
                .style(Style::default()),
        );
        frame.render_widget(table, data_block);
        frame.render_widget(title, title_block);
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
impl Ipv4PacketInfo {
    pub fn render(self, block: Rect, frame: &mut Frame) {
        let (title_block, data_block) = {
            let chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Length(10), Constraint::Fill(1)])
                .margin(2)
                .split(block);
            (chunks[0], chunks[1])
        };
        let title = Paragraph::new("IPv4")
            .bold()
            .block(Block::new().padding(Padding::top({
                if title_block.height % 2 == 0 {
                    (title_block.height / 2).saturating_sub(1)
                } else {
                    title_block.height / 2
                }
            })));
        let widths = [Constraint::Length(23), Constraint::Fill(1)];
        let infos = [
            Row::new(vec![
                Span::styled("Source IP", Style::new().bold()),
                Span::from(self.source.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Destination IP", Style::new().bold()),
                Span::from(self.destination.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Protocol", Style::new().bold()),
                Span::from(format!("{:?}", self.next_level_protocol)),
            ]),
            Row::new(vec![
                Span::styled("Time To Live (TTL)", Style::new().bold()),
                Span::from(self.ttl.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Total Length", Style::new().bold()),
                Span::from(self.total_length.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Checksum", Style::new().bold()),
                Span::from(format!("0x{:04x}", self.checksum)),
            ]),
            Row::new(vec![
                Span::styled("Identification", Style::new().bold()),
                Span::from(self.identification.to_string()),
            ]),
        ];
        let table = Table::new(infos, widths).column_spacing(2).block(
            Block::default()
                .borders(Borders::LEFT)
                .border_style(Style::new().bold())
                .border_type(ratatui::widgets::BorderType::Thick)
                .style(Style::default()),
        );
        frame.render_widget(table, data_block);
        frame.render_widget(title, title_block);
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
