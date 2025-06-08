use crate::{
    enums::{CompletePacket, PacketsData},
    packet_sniffer::sniffer,
};
use crossterm::event::{KeyCode, KeyEventKind};
use pnet::{
    datalink::{self, NetworkInterface},
    util::MacAddr,
};
use ratatui::{
    layout::{Alignment, Constraint, Flex, Layout, Margin, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{
        BarChart, Block, Borders, Cell, Clear, Padding, Paragraph, Row, Scrollbar,
        ScrollbarOrientation, ScrollbarState, Table, TableState,
    },
    DefaultTerminal, Frame,
};
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    thread::{self, JoinHandle},
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
    interfaces_table_state: TableState,
    interfaces_scroll_state: ScrollbarState,
    packets: Vec<CompletePacket>,
    pub action_tx: mpsc::Sender<Event>,
    pub action_rx: mpsc::Receiver<Event>,
    pub interface: Option<NetworkInterface>,
    pub interfaces: Vec<NetworkInterface>,
    show_popup: bool,
    sniffer_paused: bool,
    selected_popup_packet: Option<CompletePacket>,
    sniffer_handle: Option<JoinHandle<()>>,
    sniffer_stop_signal: Arc<AtomicBool>,
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
    pub fn new() -> Self {
        let (action_tx, action_rx) = mpsc::channel();
        App {
            exit: false,
            sniffer_paused: false,
            table_state: TableState::default().with_selected(0),
            scroll_state: ScrollbarState::new(0),
            interfaces_table_state: TableState::default().with_selected(0),
            interfaces_scroll_state: ScrollbarState::new(0),
            packets: Vec::new(),
            action_tx,
            action_rx,
            interface: None,
            interfaces: Vec::new(),
            show_popup: false,
            selected_popup_packet: None,
            sniffer_handle: None,
            sniffer_stop_signal: Arc::new(AtomicBool::new(false)),
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
                KeyCode::Char('i') => self.next_active_interface(),
                KeyCode::Char('p') => {
                    if !self.sniffer_paused {
                        self.stop_sniffer();
                    } else {
                        self.start_sniffer();
                    }
                }
                KeyCode::Enter => {
                    self.show_popup = !self.show_popup;
                    if let Some(selected_idx) = self.table_state.selected() {
                        self.selected_popup_packet = self.packets.get(selected_idx).cloned();
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    pub fn stop_sniffer(&mut self) {
        self.sniffer_stop_signal.store(true, Ordering::Relaxed);

        if let Some(handle) = self.sniffer_handle.take() {
            let _ = handle.join();
        }
        self.sniffer_paused = true;
    }

    fn start_sniffer(&mut self) {
        let tx_to_sniffer = self.action_tx.clone();
        let interface = self.interface.clone().unwrap();
        let stop_signal = Arc::new(AtomicBool::new(false));
        self.sniffer_stop_signal = stop_signal.clone();
        let handle = thread::spawn(move || {
            sniffer(interface, tx_to_sniffer, stop_signal);
        });

        self.sniffer_handle = Some(handle);
        self.sniffer_paused = false;
    }

    pub fn run(&mut self, terminal: &mut DefaultTerminal) -> color_eyre::Result<()> {
        let tx_to_key_event_handler = self.action_tx.clone();
        let tx_to_draw_handler = self.action_tx.clone();
        let tick_rate = Duration::from_secs_f64(1.0 / 22.0);

        let interfaces = datalink::interfaces();
        if interfaces.len() == 0 {
            self.exit = true;
        }
        for intf in &interfaces {
            if intf.is_up() && !intf.ips.is_empty() {
                for ip in &intf.ips {
                    if let IpAddr::V4(ipv4) = ip.ip() {
                        if ipv4.is_private() && !ipv4.is_loopback() && !ipv4.is_unspecified() {
                            self.interfaces.push(intf.clone());
                            break;
                        }
                    }
                }
            }
        }
        self.interface = self.interfaces.get(0).cloned();
        self.start_sniffer();
        thread::spawn(move || handle_input_events(tx_to_key_event_handler));
        thread::spawn(move || {
            let mut last_tick = Instant::now();
            loop {
                let now = Instant::now();
                let elapsed = now.duration_since(last_tick);

                if elapsed >= tick_rate {
                    if tx_to_draw_handler.send(Event::Render).is_err() {
                        break;
                    }
                    last_tick = now;
                } else {
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

    pub fn popup_area(&mut self, area: Rect, percent_x: u16, percent_y: u16) -> Rect {
        let vertical = Layout::vertical([Constraint::Percentage(percent_y)]).flex(Flex::Center);
        let horizontal = Layout::horizontal([Constraint::Percentage(percent_x)]).flex(Flex::Center);
        let [area] = vertical.areas(area);
        let [area] = horizontal.areas(area);
        area
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
        self.render_interfaces_scrollbar(frame, interfaces_area);
        if self.show_popup {
            let block = Block::bordered().title("Popup");
            let area = self.popup_area(frame.area(), 80, 80);
            let vertical_popup_area = Layout::vertical([
                Constraint::Percentage(33),
                Constraint::Percentage(33),
                Constraint::Percentage(33),
            ]);
            let [layer3_info_area, layer2_info_area, layer1_info_area] =
                vertical_popup_area.areas(area);
            frame.render_widget(Clear, area);
            frame.render_widget(block, area);
            let popup_packet = &self.selected_popup_packet;
            if let Some(packet) = popup_packet {
                if let Some(layer1) = &packet.layer_1 {
                    match layer1 {
                        PacketsData::EthernetPacket(ethernet_packet) => {
                            ethernet_packet.clone().render(layer1_info_area, frame)
                        }
                        _ => {}
                    }
                }

                if let Some(layer2) = &packet.layer_2 {
                    match layer2 {
                        PacketsData::Ipv4Packet(ipv4_packet) => {
                            ipv4_packet.clone().render(layer2_info_area, frame)
                        }
                        PacketsData::Ipv6Packet(ipv6_packet) => {
                            ipv6_packet.clone().render(layer2_info_area, frame)
                        }
                        PacketsData::ArpPacket(arp_packet) => {
                            arp_packet.clone().render(layer2_info_area, frame)
                        }
                        _ => {}
                    }
                }

                if let Some(layer3) = &packet.layer_3 {
                    match layer3 {
                        PacketsData::TcpPacket(tcp_packet) => {
                            tcp_packet.clone().render(layer3_info_area, frame)
                        }
                        PacketsData::UdpPacket(udp_packet) => {
                            udp_packet.clone().render(layer3_info_area, frame)
                        }
                        PacketsData::IcmpPacket(icmp_packet) => {
                            icmp_packet.clone().render(layer3_info_area, frame)
                        }
                        PacketsData::Icmpv6Packet(icmpv6_packet) => {
                            icmpv6_packet.clone().render(layer3_info_area, frame)
                        }
                        _ => {}
                    }
                }
            }
        }
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
    fn render_interfaces_scrollbar(&mut self, frame: &mut Frame, area: Rect) {
        frame.render_stateful_widget(
            Scrollbar::default()
                .orientation(ScrollbarOrientation::VerticalRight)
                .begin_symbol(None)
                .end_symbol(None),
            area.inner(Margin {
                vertical: 1,
                horizontal: 1,
            }),
            &mut self.interfaces_scroll_state,
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

    fn render_interfaces(&mut self, frame: &mut Frame, area: Rect) {
        let table = self.make_table();
        frame.render_widget(table, area);
    }

    fn make_table(&mut self) -> Table {
        let header = Row::new(vec!["", "Nome", "MAC", "Ipv4", "Ipv6"])
            .style(Style::default().fg(Color::Yellow))
            .height(1);
        let mut rows = Vec::new();
        for w in &self.interfaces {
            let mut active = String::from("");
            if self.interface.is_some() && self.interface.clone().unwrap() == *w {
                active = String::from("*");
            }
            let name = if cfg!(windows) {
                w.description.clone()
            } else {
                w.name.clone()
            };
            let mac = w.mac.unwrap_or(MacAddr::default()).to_string();
            let ipv4: Vec<Line> = w
                .ips
                .iter()
                .filter(|f| f.is_ipv4())
                .cloned()
                .map(|ip| {
                    let ip_str = ip.ip().to_string();
                    Line::from(vec![Span::styled(
                        format!("{ip_str:<2}"),
                        Style::default().fg(Color::Blue),
                    )])
                })
                .collect();
            let ipv6: Vec<Span> = w
                .ips
                .iter()
                .filter(|f| f.is_ipv6())
                .cloned()
                .map(|ip| Span::from(ip.ip().to_string()))
                .collect();

            let mut row_height = 1;
            if ipv4.len() > 1 {
                row_height = ipv4.clone().len() as u16;
            }
            rows.push(
                Row::new(vec![
                    Cell::from(Span::styled(
                        format!("{active:<1}"),
                        Style::default().fg(Color::Red),
                    )),
                    Cell::from(Span::styled(
                        format!("{name:<2}"),
                        Style::default().fg(Color::Green),
                    )),
                    Cell::from(mac),
                    Cell::from(ipv4.clone()),
                    Cell::from(vec![Line::from(ipv6)]),
                ])
                .height(row_height),
            );
        }

        let table = Table::new(
            rows,
            [
                Constraint::Length(1),
                Constraint::Length(8),
                Constraint::Length(18),
                Constraint::Length(14),
                Constraint::Length(25),
            ],
        )
        .header(header)
        .block(
            Block::default()
                .title(Line::from(vec![
                    Span::styled("|Inter", Style::default().fg(Color::Yellow)),
                    Span::styled("f", Style::default().fg(Color::Red)),
                    Span::styled("aces|", Style::default().fg(Color::Yellow)),
                ]))
                .border_style(Style::default().fg(Color::Rgb(100, 100, 100)))
                .title_style(Style::default().fg(Color::Yellow))
                .title_alignment(Alignment::Right)
                .borders(Borders::ALL)
                .padding(Padding::new(0, 0, 1, 0)),
        )
        .column_spacing(1);
        table
    }

    fn next_active_interface(&mut self) {
        self.stop_sniffer();

        if self.interfaces.is_empty() {
            self.interface = None;
            self.interfaces_table_state.select(None);
            return;
        }

        let current_selected_idx = self.interfaces_table_state.selected().unwrap_or(0);
        let new_idx = (current_selected_idx + 1) % self.interfaces.len();

        self.interfaces_table_state.select(Some(new_idx));
        self.interface = self.interfaces.get(new_idx).cloned();

        if self.interface.is_some() {
            self.start_sniffer();
        }
    }
    fn get_last_layer_protocol_name(packet: &CompletePacket) -> Option<&'static str> {
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

    fn render_chart(&mut self, frame: &mut Frame, area: Rect) {
        let mut protocol_counts: HashMap<&'static str, u32> = HashMap::new();

        for packet in &self.packets {
            if let Some(protocol_name) = Self::get_last_layer_protocol_name(packet) {
                *protocol_counts.entry(protocol_name).or_insert(0) += 1;
            }
        }

        if protocol_counts.is_empty() {
            let placeholder = Paragraph::new("Nenhum pacote capturado.")
                .block(
                    Block::default()
                        .title("Pacotes Capturados")
                        .borders(Borders::ALL),
                )
                .alignment(Alignment::Center);
            frame.render_widget(placeholder, area);
            return;
        }

        let mut sorted_protocols: Vec<&&str> = protocol_counts.keys().collect();
        sorted_protocols.sort_unstable();

        let chart_data: Vec<(&str, u64)> = sorted_protocols
            .into_iter()
            .map(|name| (*name, protocol_counts[name] as u64))
            .collect();

        let max_count = chart_data
            .iter()
            .map(|&(_, count)| count)
            .max()
            .unwrap_or(0);

        let barchart = BarChart::default()
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
            .max(max_count);

        frame.render_widget(barchart, area);
    }
}
