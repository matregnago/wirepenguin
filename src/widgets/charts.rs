use crate::enums::{CompletePacket, PacketsData};
use ratatui::{
    layout::Alignment,
    style::{Color, Modifier, Style},
    widgets::{BarChart, Block, Borders, Paragraph},
    Frame,
};
use std::collections::HashMap;

pub struct ChartWidget<'a> {
    packets: &'a [CompletePacket],
}

impl<'a> ChartWidget<'a> {
    pub fn new(packets: &'a [CompletePacket]) -> Self {
        Self { packets }
    }

    pub fn render(&self, frame: &mut Frame, area: ratatui::layout::Rect) {
        if self.packets.is_empty() {
            self.render_empty_chart(frame, area);
            return;
        }

        let protocol_counts = self.count_protocols();
        let chart_data = self.build_chart_data(protocol_counts);
        let barchart = self.build_barchart(chart_data);

        frame.render_widget(barchart, area);
    }

    fn render_empty_chart(&self, frame: &mut Frame, area: ratatui::layout::Rect) {
        let placeholder = Paragraph::new("Nenhum pacote capturado.")
            .block(
                Block::default()
                    .title("Pacotes Capturados")
                    .borders(Borders::ALL),
            )
            .alignment(Alignment::Center);
        frame.render_widget(placeholder, area);
    }

    fn count_protocols(&self) -> HashMap<&'static str, u32> {
        let mut protocol_counts = HashMap::new();

        for packet in self.packets {
            if let Some(protocol_name) = Self::get_protocol_name(packet) {
                *protocol_counts.entry(protocol_name).or_insert(0) += 1;
            }
        }

        protocol_counts
    }

    fn get_protocol_name(packet: &CompletePacket) -> Option<&'static str> {
        if let Some(layer3) = &packet.layer_3 {
            match layer3 {
                PacketsData::TcpPacket(_) => Some("TCP"),
                PacketsData::UdpPacket(_) => Some("UDP"),
                PacketsData::IcmpPacket(_) => Some("ICMP"),
                PacketsData::Icmpv6Packet(_) => Some("ICMPv6"),
                _ => None,
            }
        } else if let Some(layer2) = &packet.layer_2 {
            match layer2 {
                PacketsData::ArpPacket(_) => Some("ARP"),
                _ => None,
            }
        } else {
            None
        }
    }

    fn build_chart_data(
        &self,
        mut protocol_counts: HashMap<&'static str, u32>,
    ) -> Vec<(&'static str, u64)> {
        let mut sorted_protocols: Vec<&'static str> = protocol_counts.keys().cloned().collect();
        sorted_protocols.sort_unstable();

        sorted_protocols
            .into_iter()
            .map(|name| (name, protocol_counts.remove(name).unwrap_or(0) as u64))
            .collect()
    }

    fn build_barchart(&self, chart_data: Vec<(&'static str, u64)>) -> BarChart {
        let max_count = chart_data
            .iter()
            .map(|&(_, count)| count)
            .max()
            .unwrap_or(0);

        BarChart::default()
            .block(
                Block::default()
                    .title("Pacotes Capturados")
                    .borders(Borders::ALL),
            )
            .data(&chart_data)
            .bar_width(5)
            .bar_style(Style::default().fg(Color::LightCyan))
            .value_style(
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::LightCyan)
                    .add_modifier(Modifier::BOLD),
            )
            .label_style(Style::default().fg(Color::White))
            .max(max_count)
    }
}
