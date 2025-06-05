use std::{sync::mpsc, thread};

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

use crate::{
    enums::{CompletePacket, PacketsData},
    packet_sniffer::sniffer,
};

pub enum Event {
    Input(crossterm::event::KeyEvent),
    PacketCaptured(CompletePacket),
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
            scroll_state: ScrollbarState::default(),
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
                KeyCode::Char('i') => self.exit = true,
                KeyCode::Enter => self.exit = true,
                KeyCode::Up => self.exit = true,
                KeyCode::Down => self.exit = true,
                _ => {}
            }
        }
        Ok(())
    }

    pub fn run(&mut self, terminal: &mut DefaultTerminal) -> color_eyre::Result<()> {
        let tx_to_sniffer = self.action_tx.clone();
        let tx_to_key_event_handler = self.action_tx.clone();
        let interface_to_sniffer = self.interface.clone();

        thread::spawn(move || sniffer(interface_to_sniffer, tx_to_sniffer));
        thread::spawn(move || handle_input_events(tx_to_key_event_handler));
        while !self.exit {
            terminal.draw(|frame| self.draw(frame))?;
            match self.action_rx.recv().unwrap() {
                Event::PacketCaptured(packet) => self.packets.push(packet),
                Event::Input(key_event) => self.handle_key_event(key_event).unwrap(),
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
    fn render_table(&mut self, frame: &mut Frame, area: Rect) {
        let header = ["Tempo", "Pacote"]
            .into_iter()
            .map(Cell::from)
            .collect::<Row>()
            .height(1);
        let rows: Vec<Row> = self
            .packets
            .iter()
            .enumerate()
            .map(|(_, data)| {
                if let Some(layer_3) = &data.layer_3 {
                    let packet = match layer_3 {
                        PacketsData::IcmpPacket(icmp_packet) => {
                            format!("{} - {}", data.id, icmp_packet.length)
                        }
                        _ => String::new(),
                    };
                    Row::new(vec![Cell::from(packet)])
                } else {
                    Row::new(vec![Cell::from("")])
                }
            })
            .collect();
        let widths = [Constraint::Length(5), Constraint::Length(5)];
        let bar = " █ ";
        let table = Table::new(rows, widths)
            .header(header)
            .block(Block::new().borders(Borders::ALL))
            .highlight_symbol(Text::from(vec![
                "".into(),
                bar.into(),
                bar.into(),
                "".into(),
            ]));
        frame.render_stateful_widget(table, area, &mut self.table_state);
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
