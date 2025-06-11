use crate::packet_data::{CompletePacket, PacketsData};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Style, Stylize},
    text::Span,
    widgets::{Block, Borders, Clear, Padding, Paragraph, Row, Table},
    Frame,
};

pub struct PopupWidget<'a> {
    packet: &'a Option<CompletePacket>,
}

impl<'a> PopupWidget<'a> {
    pub fn new(packet: &'a Option<CompletePacket>) -> Self {
        Self { packet }
    }

    pub fn render(&self, frame: &mut Frame, area: Rect) {
        let popup_area = self.calculate_popup_area(area, 80, 80);

        frame.render_widget(Clear, popup_area);
        frame.render_widget(Block::bordered().title("Detalhes do Pacote"), popup_area);

        if let Some(packet) = self.packet {
            self.render_packet_layers(frame, popup_area, packet);
        }
    }

    fn calculate_popup_area(&self, area: Rect, percent_x: u16, percent_y: u16) -> Rect {
        use ratatui::layout::Flex;

        let vertical = Layout::vertical([ratatui::layout::Constraint::Percentage(percent_y)])
            .flex(Flex::Center);
        let horizontal = Layout::horizontal([ratatui::layout::Constraint::Percentage(percent_x)])
            .flex(Flex::Center);

        let [area] = vertical.areas(area);
        let [area] = horizontal.areas(area);
        area
    }

    fn render_packet_layers(&self, frame: &mut Frame, area: Rect, packet: &CompletePacket) {
        let layers_count = [&packet.layer_1, &packet.layer_2, &packet.layer_3]
            .iter()
            .filter(|layer| layer.is_some())
            .count();

        if layers_count == 0 {
            return;
        }

        let constraints: Vec<Constraint> = (0..layers_count)
            .map(|_| Constraint::Percentage(100 / layers_count as u16))
            .collect();

        let vertical_layout = Layout::vertical(constraints);
        let areas = vertical_layout.split(area);

        let mut area_index = 0;

        // Render layers in order (Layer 1 -> Layer 2 -> Layer 3)
        if packet.layer_1.is_some() {
            self.render_layer(frame, areas[area_index], &packet.layer_1);
            area_index += 1;
        }
        if packet.layer_2.is_some() {
            self.render_layer(frame, areas[area_index], &packet.layer_2);
            area_index += 1;
        }
        if packet.layer_3.is_some() {
            self.render_layer(frame, areas[area_index], &packet.layer_3);
        }
    }

    fn render_layer(&self, frame: &mut Frame, area: Rect, layer: &Option<PacketsData>) {
        if let Some(packet_data) = layer {
            match packet_data {
                PacketsData::EthernetPacket(packet) => {
                    self.render_ethernet_packet(frame, area, packet);
                }
                PacketsData::ArpPacket(packet) => {
                    self.render_arp_packet(frame, area, packet);
                }
                PacketsData::Ipv4Packet(packet) => {
                    self.render_ipv4_packet(frame, area, packet);
                }
                PacketsData::Ipv6Packet(packet) => {
                    self.render_ipv6_packet(frame, area, packet);
                }
                PacketsData::TcpPacket(packet) => {
                    self.render_tcp_packet(frame, area, packet);
                }
                PacketsData::UdpPacket(packet) => {
                    self.render_udp_packet(frame, area, packet);
                }
                PacketsData::IcmpPacket(packet) => {
                    self.render_icmp_packet(frame, area, packet);
                }
                PacketsData::Icmpv6Packet(packet) => {
                    self.render_icmpv6_packet(frame, area, packet);
                }
            }
        }
    }

    fn create_packet_layout(&self, area: Rect) -> (Rect, Rect) {
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Length(10), Constraint::Fill(1)])
            .margin(2)
            .split(area);
        (chunks[0], chunks[1])
    }

    fn create_title_widget<'p>(&self, title: String, title_area: Rect) -> Paragraph {
        Paragraph::new(title)
            .bold()
            .block(Block::new().padding(Padding::top({
                if title_area.height % 2 == 0 {
                    (title_area.height / 2).saturating_sub(1)
                } else {
                    title_area.height / 2
                }
            })))
    }

    fn render_ethernet_packet(&self, frame: &mut Frame, area: Rect, packet: &crate::packet_data::EthernetPacketInfo) {
        let (title_area, data_area) = self.create_packet_layout(area);
        let title = self.create_title_widget("Ethernet".to_string(), title_area);

        let widths = [Constraint::Length(23), Constraint::Fill(1)];
        let rows = [
            Row::new(vec![
                Span::styled("Destination MAC", Style::new().bold()),
                Span::from(packet.destination.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Source MAC", Style::new().bold()),
                Span::from(packet.source.to_string()),
            ]),
            Row::new(vec![
                Span::styled("EtherType", Style::new().bold()),
                Span::from(format!("{:?}", packet.ethertype)),
            ]),
            Row::new(vec![
                Span::styled("Payload Length", Style::new().bold()),
                Span::from(packet.payload.len().to_string()),
            ]),
        ];

        let table = Table::new(rows, widths)
            .column_spacing(2)
            .block(
                Block::default()
                    .borders(Borders::LEFT)
                    .border_style(Style::new().bold())
                    .border_type(ratatui::widgets::BorderType::Thick),
            );

        frame.render_widget(table, data_area);
        frame.render_widget(title, title_area);
    }

    fn render_arp_packet(&self, frame: &mut Frame, area: Rect, packet: &crate::packet_data::ArpPacketInfo) {
        let (title_area, data_area) = self.create_packet_layout(area);
        let title = self.create_title_widget("ARP".to_string(), title_area);

        let widths = [Constraint::Length(23), Constraint::Fill(1)];
        let rows = [
            Row::new(vec![
                Span::styled("Operation", Style::new().bold()),
                Span::from(format!("{:?}", packet.operation)),
            ]),
            Row::new(vec![
                Span::styled("Sender MAC", Style::new().bold()),
                Span::from(packet.sender_hw_addr.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Sender IP", Style::new().bold()),
                Span::from(packet.sender_proto_addr.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Target MAC", Style::new().bold()),
                Span::from(packet.target_hw_addr.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Target IP", Style::new().bold()),
                Span::from(packet.target_proto_addr.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Hardware Type", Style::new().bold()),
                Span::from(format!("{:?}", packet.hardware_type)),
            ]),
            Row::new(vec![
                Span::styled("Protocol Type", Style::new().bold()),
                Span::from(format!("{:?}", packet.protocol_type)),
            ]),
        ];

        let table = Table::new(rows, widths)
            .column_spacing(2)
            .block(
                Block::default()
                    .borders(Borders::LEFT)
                    .border_style(Style::new().bold())
                    .border_type(ratatui::widgets::BorderType::Thick),
            );

        frame.render_widget(table, data_area);
        frame.render_widget(title, title_area);
    }

    fn render_ipv4_packet(&self, frame: &mut Frame, area: Rect, packet: &crate::packet_data::Ipv4PacketInfo) {
        let (title_area, data_area) = self.create_packet_layout(area);
        let title = self.create_title_widget("IPv4".to_string(), title_area);

        let widths = [Constraint::Length(23), Constraint::Fill(1)];
        let rows = [
            Row::new(vec![
                Span::styled("Source IP", Style::new().bold()),
                Span::from(packet.source.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Destination IP", Style::new().bold()),
                Span::from(packet.destination.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Protocol", Style::new().bold()),
                Span::from(format!("{:?}", packet.next_level_protocol)),
            ]),
            Row::new(vec![
                Span::styled("Time To Live (TTL)", Style::new().bold()),
                Span::from(packet.ttl.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Total Length", Style::new().bold()),
                Span::from(packet.total_length.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Checksum", Style::new().bold()),
                Span::from(format!("0x{:04x}", packet.checksum)),
            ]),
            Row::new(vec![
                Span::styled("Identification", Style::new().bold()),
                Span::from(packet.identification.to_string()),
            ]),
        ];

        let table = Table::new(rows, widths)
            .column_spacing(2)
            .block(
                Block::default()
                    .borders(Borders::LEFT)
                    .border_style(Style::new().bold())
                    .border_type(ratatui::widgets::BorderType::Thick),
            );

        frame.render_widget(table, data_area);
        frame.render_widget(title, title_area);
    }

    fn render_ipv6_packet(&self, frame: &mut Frame, area: Rect, packet: &crate::packet_data::Ipv6PacketInfo) {
        let (title_area, data_area) = self.create_packet_layout(area);
        let title = self.create_title_widget("IPv6".to_string(), title_area);

        let widths = [Constraint::Length(23), Constraint::Fill(1)];
        let rows = [
            Row::new(vec![
                Span::styled("Source IP", Style::new().bold()),
                Span::from(packet.source.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Destination IP", Style::new().bold()),
                Span::from(packet.destination.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Next Header", Style::new().bold()),
                Span::from(format!("{:?}", packet.next_header)),
            ]),
            Row::new(vec![
                Span::styled("Traffic Class", Style::new().bold()),
                Span::from(packet.traffic_class.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Flow Label", Style::new().bold()),
                Span::from(packet.flow_label.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Payload Length", Style::new().bold()),
                Span::from(packet.payload_length.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Hop Limit", Style::new().bold()),
                Span::from(packet.hop_limit.to_string()),
            ]),
        ];

        let table = Table::new(rows, widths)
            .column_spacing(2)
            .block(
                Block::default()
                    .borders(Borders::LEFT)
                    .border_style(Style::new().bold())
                    .border_type(ratatui::widgets::BorderType::Thick),
            );

        frame.render_widget(table, data_area);
        frame.render_widget(title, title_area);
    }

    fn render_tcp_packet(&self, frame: &mut Frame, area: Rect, packet: &crate::packet_data::TcpPacketInfo) {
        let (title_area, data_area) = self.create_packet_layout(area);
        let title = self.create_title_widget("TCP".to_string(), title_area);

        let widths = [Constraint::Length(23), Constraint::Fill(1)];
        let rows = [
            Row::new(vec![
                Span::styled("Source Port", Style::new().bold()),
                Span::from(packet.source.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Destination Port", Style::new().bold()),
                Span::from(packet.destination.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Sequence Number", Style::new().bold()),
                Span::from(packet.sequence.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Acknowledgement", Style::new().bold()),
                Span::from(packet.acknowledgement.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Window Size", Style::new().bold()),
                Span::from(packet.window.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Checksum", Style::new().bold()),
                Span::from(format!("0x{:04x}", packet.checksum)),
            ]),
            Row::new(vec![
                Span::styled("Flags (raw)", Style::new().bold()),
                Span::from(packet.flags.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Urgent Pointer", Style::new().bold()),
                Span::from(packet.urgent_ptr.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Options", Style::new().bold()),
                Span::from(format!("{:?}", packet.options)),
            ]),
            Row::new(vec![
                Span::styled("Payload Length", Style::new().bold()),
                Span::from(packet.length.to_string()),
            ]),
        ];

        let table = Table::new(rows, widths)
            .column_spacing(2)
            .block(
                Block::default()
                    .borders(Borders::LEFT)
                    .border_style(Style::new().bold())
                    .border_type(ratatui::widgets::BorderType::Thick),
            );

        frame.render_widget(table, data_area);
        frame.render_widget(title, title_area);
    }

    fn render_udp_packet(&self, frame: &mut Frame, area: Rect, packet: &crate::packet_data::UdpPacketInfo) {
        let (title_area, data_area) = self.create_packet_layout(area);
        let title = self.create_title_widget("UDP".to_string(), title_area);

        let widths = [Constraint::Length(23), Constraint::Fill(1)];
        let rows = [
            Row::new(vec![
                Span::styled("Source Port", Style::new().bold()),
                Span::from(packet.source.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Destination Port", Style::new().bold()),
                Span::from(packet.destination.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Length", Style::new().bold()),
                Span::from(packet.length.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Checksum", Style::new().bold()),
                Span::from(format!("0x{:04x}", packet.checksum)),
            ]),
        ];

        let table = Table::new(rows, widths)
            .column_spacing(2)
            .block(
                Block::default()
                    .borders(Borders::LEFT)
                    .border_style(Style::new().bold())
                    .border_type(ratatui::widgets::BorderType::Thick),
            );

        frame.render_widget(table, data_area);
        frame.render_widget(title, title_area);
    }

    fn render_icmp_packet(&self, frame: &mut Frame, area: Rect, packet: &crate::packet_data::IcmpPacketInfo) {
        let (title_area, data_area) = self.create_packet_layout(area);
        let title = self.create_title_widget("ICMP".to_string(), title_area);

        let widths = [Constraint::Length(23), Constraint::Fill(1)];
        let rows = [
            Row::new(vec![
                Span::styled("Type", Style::new().bold()),
                Span::from(format!("{:?}", packet.icmp_type)),
            ]),
            Row::new(vec![
                Span::styled("Code", Style::new().bold()),
                Span::from(format!("{:?}", packet.icmp_code)),
            ]),
            Row::new(vec![
                Span::styled("Checksum", Style::new().bold()),
                Span::from(format!("0x{:04x}", packet.checksum)),
            ]),
            Row::new(vec![
                Span::styled("Payload Length", Style::new().bold()),
                Span::from(packet.length.to_string()),
            ]),
        ];

        let table = Table::new(rows, widths)
            .column_spacing(2)
            .block(
                Block::default()
                    .borders(Borders::LEFT)
                    .border_style(Style::new().bold())
                    .border_type(ratatui::widgets::BorderType::Thick),
            );

        frame.render_widget(table, data_area);
        frame.render_widget(title, title_area);
    }

    fn render_icmpv6_packet(&self, frame: &mut Frame, area: Rect, packet: &crate::packet_data::Icmpv6PacketInfo) {
        let (title_area, data_area) = self.create_packet_layout(area);
        let title = self.create_title_widget("ICMPv6".to_string(), title_area);

        let widths = [Constraint::Length(23), Constraint::Fill(1)];
        let rows = [
            Row::new(vec![
                Span::styled("Type", Style::new().bold()),
                Span::from(format!("{:?}", packet.icmpv6_type)),
            ]),
            Row::new(vec![
                Span::styled("Code", Style::new().bold()),
                Span::from(format!("{:?}", packet.icmpv6_code)),
            ]),
            Row::new(vec![
                Span::styled("Checksum", Style::new().bold()),
                Span::from(format!("0x{:04x}", packet.checksum)),
            ]),
            Row::new(vec![
                Span::styled("Payload Length", Style::new().bold()),
                Span::from(packet.length.to_string()),
            ]),
        ];

        let table = Table::new(rows, widths)
            .column_spacing(2)
            .block(
                Block::default()
                    .borders(Borders::LEFT)
                    .border_style(Style::new().bold())
                    .border_type(ratatui::widgets::BorderType::Thick),
            );

        frame.render_widget(table, data_area);
        frame.render_widget(title, title_area);
    }
}