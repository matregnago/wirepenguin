use ratatui::{
    layout::{Constraint, Margin, Rect},
    text::Text,
    widgets::{
        Block, Borders, Cell, Row, Scrollbar, ScrollbarOrientation, ScrollbarState, StatefulWidget,
        Table, TableState
    },
};

use crate::packet_data::{CompletePacket, PacketsData};

pub struct PacketTableState {
    pub table_state: TableState,
    pub scroll_state: ScrollbarState,
}

impl PacketTableState {
    pub fn new() -> Self {
        Self {
            table_state: TableState::default().with_selected(0),
            scroll_state: ScrollbarState::new(0),
        }
    }

    pub fn next_row(&mut self, packets_len: usize) {
        let i = match self.table_state.selected() {
            Some(i) => {
                if packets_len == 0 || i >= packets_len - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.table_state.select(Some(i));
        self.scroll_state = self.scroll_state.position(i);
    }

    pub fn previous_row(&mut self, packets_len: usize) {
        let i = match self.table_state.selected() {
            Some(i) => {
                if i == 0 {
                    if packets_len > 0 {
                        packets_len - 1
                    } else {
                        0
                    }
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.table_state.select(Some(i));
        self.scroll_state = self.scroll_state.position(i);
    }

    pub fn selected(&self) -> Option<usize> {
        self.table_state.selected()
    }
}
pub struct PacketTable<'a> {
    packets: &'a [CompletePacket],
    block: Option<Block<'a>>,
}

impl<'a> PacketTable<'a> {
    pub fn new(packets: &'a [CompletePacket]) -> Self {
        Self {
            packets,
            block: None,
        }
    }

    pub fn block(mut self, block: Block<'a>) -> Self {
        self.block = Some(block);
        self
    }

    fn generate_ref_array(&self, complete_packet: &CompletePacket) -> Option<[String; 5]> {
        if let Some(layer2) = &complete_packet.layer_2 {
            let (src_ip, dst_ip) = match layer2 {
                PacketsData::ArpPacket(arp_packet) => {
                    return Some([
                        complete_packet.id.to_string(),
                        "ARP".to_string(),
                        format!(
                            "{}",
                             arp_packet.sender_hw_addr
                        ),
                        format!(
                            "{}",
                            arp_packet.target_hw_addr
                        ),
                        arp_packet.length.to_string(),
                    ]);
                }
                PacketsData::Ipv4Packet(ipv4) => {
                    (ipv4.source.to_string(), ipv4.destination.to_string())
                }
                PacketsData::Ipv6Packet(ipv6) => {
                    (ipv6.source.to_string(), ipv6.destination.to_string())
                }
                _ => ("".to_string(), "".to_string()),
            };

            if let Some(layer3) = &complete_packet.layer_3 {
                match layer3 {
                    PacketsData::TcpPacket(tcp) => {
                        return Some([
                            complete_packet.id.to_string(),
                            "TCP".to_string(),
                            format!("{}:{}", src_ip, tcp.source),
                            format!("{}:{}", dst_ip, tcp.destination),
                            tcp.length.to_string(),
                        ]);
                    }
                    PacketsData::UdpPacket(udp) => {
                        return Some([
                            complete_packet.id.to_string(),
                            "UDP".to_string(),
                            format!("{}:{}", src_ip, udp.source),
                            format!("{}:{}", dst_ip, udp.destination),
                            udp.length.to_string(),
                        ]);
                    }
                    PacketsData::IcmpPacket(icmp) => {
                        return Some([
                            complete_packet.id.to_string(),
                            "ICMP".to_string(),
                            src_ip,
                            dst_ip,
                            icmp.length.to_string(),
                        ]);
                    }
                    PacketsData::Icmpv6Packet(icmpv6) => {
                        return Some([
                            complete_packet.id.to_string(),
                            "ICMPv6".to_string(),
                            src_ip,
                            dst_ip,
                            icmpv6.length.to_string(),
                        ]);
                    }
                    _ => {}
                }
            }
        }
        None
    }
}

impl<'a> StatefulWidget for PacketTable<'a> {
    type State = PacketTableState;

    fn render(self, area: Rect, buf: &mut ratatui::buffer::Buffer, state: &mut Self::State) {
        let header = ["ID", "Protocolo", "Origem", "Destino", "Length"]
            .into_iter()
            .map(Cell::from)
            .collect::<Row>();

        let rows: Vec<Row> = self
            .packets
            .iter()
            .filter_map(|data| {
                self.generate_ref_array(data).map(|item| {
                    item.into_iter()
                        .map(|content| Cell::from(Text::from(format!("\n{content}\n"))))
                        .collect::<Row>()
                        .height(2)
                })
            })
            .collect();

        let widths = [
            Constraint::Length(8),
            Constraint::Length(10),
            Constraint::Length(25),
            Constraint::Length(25),
            Constraint::Length(8),
        ];

        let bar = " > ";
        let mut table = Table::new(rows, widths)
            .header(header)
            .highlight_symbol(Text::from(vec![
                "".into(),
                bar.into(),
                bar.into(),
                "".into(),
            ]));

        if let Some(block) = self.block {
            table = table.block(block);
        } else {
            table = table.block(Block::new().borders(Borders::ALL).title("Lista de pacotes"));
        }

        StatefulWidget::render(table, area, buf, &mut state.table_state.clone());
        state.scroll_state = state.scroll_state.content_length(self.packets.len());

        let scrollbar = Scrollbar::default()
            .orientation(ScrollbarOrientation::VerticalRight)
            .begin_symbol(None)
            .end_symbol(None);

        let scrollbar_area = area.inner(Margin {
            vertical: 1,
            horizontal: 0,
        });

        StatefulWidget::render(scrollbar, scrollbar_area, buf, &mut state.scroll_state);
    }
}