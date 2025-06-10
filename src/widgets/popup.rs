use crate::enums::{CompletePacket, PacketsData};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    widgets::{Block, Clear},
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
        frame.render_widget(Block::bordered().title("Popup"), popup_area);

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
        let vertical_layout = Layout::vertical([
            Constraint::Percentage(33),
            Constraint::Percentage(33),
            Constraint::Percentage(33),
        ]);

        let [layer3_area, layer2_area, layer1_area] = vertical_layout.areas(area);

        self.render_layer1(frame, layer1_area, packet);
        self.render_layer2(frame, layer2_area, packet);
        self.render_layer3(frame, layer3_area, packet);
    }

    fn render_layer1(&self, frame: &mut Frame, area: Rect, packet: &CompletePacket) {
        if let Some(layer1) = &packet.layer_1 {
            match layer1 {
                PacketsData::EthernetPacket(ethernet_packet) => {
                    ethernet_packet.clone().render(area, frame);
                }
                _ => {}
            }
        }
    }

    fn render_layer2(&self, frame: &mut Frame, area: Rect, packet: &CompletePacket) {
        if let Some(layer2) = &packet.layer_2 {
            match layer2 {
                PacketsData::Ipv4Packet(ipv4_packet) => {
                    ipv4_packet.clone().render(area, frame);
                }
                PacketsData::Ipv6Packet(ipv6_packet) => {
                    ipv6_packet.clone().render(area, frame);
                }
                PacketsData::ArpPacket(arp_packet) => {
                    arp_packet.clone().render(area, frame);
                }
                _ => {}
            }
        }
    }

    fn render_layer3(&self, frame: &mut Frame, area: Rect, packet: &CompletePacket) {
        if let Some(layer3) = &packet.layer_3 {
            match layer3 {
                PacketsData::TcpPacket(tcp_packet) => {
                    tcp_packet.clone().render(area, frame);
                }
                PacketsData::UdpPacket(udp_packet) => {
                    udp_packet.clone().render(area, frame);
                }
                PacketsData::IcmpPacket(icmp_packet) => {
                    icmp_packet.clone().render(area, frame);
                }
                PacketsData::Icmpv6Packet(icmpv6_packet) => {
                    icmpv6_packet.clone().render(area, frame);
                }
                _ => {}
            }
        }
    }
}
