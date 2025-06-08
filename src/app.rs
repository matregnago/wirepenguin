use crate::{
    enums::{CompletePacket, PacketsData},
    packet_sniffer::sniffer,
};
use crossterm::event::{KeyCode, KeyEventKind};
use pnet::datalink::NetworkInterface;
use ratatui::{
    layout::{Constraint, Layout, Margin, Rect},
    text::Text,
    widgets::{
        Block, Borders, Cell, Paragraph, Row, Scrollbar, ScrollbarOrientation, ScrollbarState,
        Table, TableState,
    },
    DefaultTerminal, Frame,
};
use std::{
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

pub enum Event {
    Input(crossterm::event::KeyEvent),
    PacketCaptured(CompletePacket),
    Render,
}

pub struct App {
    exit: bool,
    table_state: TableState,
    scroll_state: ScrollbarState,
    packets: Vec<CompletePacket>,
    pub action_tx: mpsc::Sender<Event>,
    pub action_rx: mpsc::Receiver<Event>,
    interface: NetworkInterface,
}

pub fn handle_input_events(tx: mpsc::Sender<Event>) {
    loop {
        match crossterm::event::read().unwrap() {
            crossterm::event::Event::Key(key_event) => {
                tx.send(Event::Input(key_event)).unwrap();
            }
            _ => {}
        }
    }
}

impl App {
    pub fn new(network_interface: NetworkInterface) -> Self {
        let (action_tx, action_rx) = mpsc::channel();
        App {
            exit: false,
            table_state: TableState::default().with_selected(0),
            scroll_state: ScrollbarState::new(0),
            packets: Vec::new(),
            action_tx,
            action_rx,
            interface: network_interface,
        }
    }

    fn handle_key_event(
        &mut self,
        key_event: crossterm::event::KeyEvent,
    ) -> color_eyre::Result<()> {
        if key_event.kind == KeyEventKind::Press {
            match key_event.code {
                KeyCode::Char('q') => self.exit = true,
                KeyCode::Char('j') | KeyCode::Down => self.next_row(),
                KeyCode::Char('k') | KeyCode::Up => self.previous_row(),
                // KeyCode::Char('i') => self.exit = true,
                // KeyCode::Enter => self.exit = true,
                // KeyCode::Up => self.exit = true,
                // KeyCode::Down => self.exit = true,
                _ => {}
            }
        }
        Ok(())
    }

    pub fn run(&mut self, terminal: &mut DefaultTerminal) -> color_eyre::Result<()> {
        let tx_to_sniffer = self.action_tx.clone();
        let tx_to_key_event_handler = self.action_tx.clone();
        let tx_to_draw_handler = self.action_tx.clone();
        let interface_to_sniffer = self.interface.clone();
        let tick_rate = Duration::from_secs_f64(1.0 / 22.0); // 60 FPS

        thread::spawn(move || sniffer(interface_to_sniffer, tx_to_sniffer));
        thread::spawn(move || handle_input_events(tx_to_key_event_handler));
        thread::spawn(move || {
            let mut last_tick = Instant::now();
            loop {
                let now = Instant::now();
                let elapsed = now.duration_since(last_tick);

                if elapsed >= tick_rate {
                    if tx_to_draw_handler.send(Event::Render).is_err() {
                        break; // Canal fechado, sai do loop
                    }
                    last_tick = now;
                } else {
                    // Pequena pausa para não consumir 100% da CPU
                    thread::sleep(Duration::from_millis(1));
                }
            }
        });

        while !self.exit {
            match self.action_rx.recv().unwrap() {
                Event::PacketCaptured(packet) => self.packets.insert(0, packet),
                Event::Input(key_event) => self.handle_key_event(key_event).unwrap(),
                Event::Render => {
                    terminal.draw(|frame| self.draw(frame))?;
                }
            }
        }
        Ok(())
    }

    fn draw(&mut self, frame: &mut Frame) {
        let vertical_layout =
            Layout::vertical([Constraint::Percentage(35), Constraint::Percentage(65)]);
        let [top_area, packets_area] = vertical_layout.areas(frame.area());
        let horizontal_area =
            Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]);
        let [chart_area, interfaces_area] = horizontal_area.areas(top_area);
        self.render_table(frame, packets_area);
        self.render_scrollbar(frame, packets_area);
        self.render_chart(frame, chart_area);
        self.render_interfaces(frame, interfaces_area);
    }

    fn render_scrollbar(&mut self, frame: &mut Frame, area: Rect) {
        frame.render_stateful_widget(
            Scrollbar::default()
                .orientation(ScrollbarOrientation::VerticalRight)
                .begin_symbol(None)
                .end_symbol(None),
            area.inner(Margin {
                vertical: 1,
                horizontal: 1,
            }),
            &mut self.scroll_state,
        );
    }
    pub fn next_row(&mut self) {
        let i = match self.table_state.selected() {
            Some(i) => {
                if self.packets.is_empty() || i >= self.packets.len() - 1 {
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

    pub fn previous_row(&mut self) {
        let i = match self.table_state.selected() {
            Some(i) => {
                if i == 0 {
                    if self.packets.len() > 0 {
                        self.packets.len() - 1
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

    fn generate_ref_array(&self, complete_packet: &CompletePacket) -> Option<[String; 5]> {
        if let Some(layer2) = &complete_packet.layer_2 {
            let (src_ip, dst_ip) = match layer2 {
                PacketsData::ArpPacket(arp_packet) => {
                    return Some([
                        complete_packet.id.to_string(),
                        "ARP".to_string(),
                        format!(
                            "{} ({})",
                            arp_packet.sender_proto_addr, arp_packet.sender_hw_addr
                        ),
                        format!(
                            "{} ({})",
                            arp_packet.target_proto_addr, arp_packet.target_hw_addr
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

    fn render_table(&mut self, frame: &mut Frame, area: Rect) {
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
        let table = Table::new(rows, widths)
            .header(header)
            .block(Block::new().borders(Borders::ALL))
            .highlight_symbol(Text::from(vec![
                "".into(),
                bar.into(),
                bar.into(),
                "".into(),
            ]));

        frame.render_stateful_widget(table, area, &mut self.table_state.clone());
    }

    fn render_chart(&mut self, frame: &mut Frame, area: Rect) {
        frame.render_widget(
            Paragraph::new("Gráfico").block(Block::new().borders(Borders::ALL)),
            area,
        );
    }

    fn render_interfaces(&mut self, frame: &mut Frame, area: Rect) {
        frame.render_widget(
            Paragraph::new("Interfaces").block(Block::new().borders(Borders::ALL)),
            area,
        );
    }
}
