use crate::{
   sniffer::Sniffer,
    packet_data::CompletePacket,
    event::Event,
    widgets::{
        charts::ChartWidget, interfaces::InterfacesWidget, layout_helper::LayoutHelper,
        popup::PopupWidget,
    },
};
use crossterm::event::{KeyCode, KeyEventKind};
use pnet::{
    datalink::{self, NetworkInterface},
};
use ratatui::{
    widgets::{ScrollbarState, TableState},
    DefaultTerminal, Frame,
};
use std::{
    net::IpAddr,
    sync::mpsc,
    thread::{self},
    time::{Duration, Instant},
};

pub struct App {
    exit: bool,
    interfaces_table_state: TableState,
    interfaces_scroll_state: ScrollbarState,
    packets: Vec<CompletePacket>,
    pub action_tx: mpsc::Sender<Event>,
    pub action_rx: mpsc::Receiver<Event>,
    pub interface: Option<NetworkInterface>,
    pub interfaces: Vec<NetworkInterface>,
    show_popup: bool,
    selected_popup_packet: Option<CompletePacket>,
    sniffer: Sniffer,
}

impl App {
    pub fn new() -> Self {
        let (action_tx, action_rx) = mpsc::channel();
        App {
            exit: false,
            interfaces_table_state: TableState::default().with_selected(0),
            interfaces_scroll_state: ScrollbarState::new(0),
            packets: Vec::new(),
            action_tx,
            action_rx,
            interface: None,
            interfaces: Vec::new(),
            show_popup: false,
            selected_popup_packet: None,
            sniffer: Sniffer::new(),
        }
    }

    fn handle_key_event(
        &mut self,
        key_event: crossterm::event::KeyEvent,
    ) -> color_eyre::Result<()> {
        if key_event.kind == KeyEventKind::Press {
            match key_event.code {
                KeyCode::Char('q') => self.exit = true,
                KeyCode::Char('j') | KeyCode::Down => self.sniffer.next_row(),
                KeyCode::Char('k') | KeyCode::Up => self.sniffer.previous_row(),
                KeyCode::Char('i') => self.next_active_interface(),
                KeyCode::Char('p') => self.toggle_sniffer(),
                KeyCode::Enter => self.toggle_popup(),
                _ => {}
            }
        }
        Ok(())
    }

    fn toggle_sniffer(&mut self) {
        if !self.sniffer.sniffer_paused {
            self.sniffer.stop();
        } else {
            self.sniffer.start();
        }
    }

    fn toggle_popup(&mut self) {
        self.show_popup = !self.show_popup;
        if let Some(selected_idx) = self.sniffer.selected_packet_index() {
            self.selected_popup_packet = self.packets.get(selected_idx).cloned();
        }
    }

    pub fn run(&mut self, terminal: &mut DefaultTerminal) -> color_eyre::Result<()> {
        self.setup_interfaces()?;
        self.start_background_threads();

        while !self.exit {
            match self.action_rx.recv().unwrap() {
                Event::PacketCaptured(packet) => self.handle_packet_captured(packet),
                Event::Input(key_event) => self.handle_key_event(key_event)?,
                Event::Render => {
                    terminal.draw(|frame| self.draw(frame))?;
                }
            }
        }
        Ok(())
    }

    fn setup_interfaces(&mut self) -> color_eyre::Result<()> {
        let interfaces = datalink::interfaces();
        if interfaces.is_empty() {
            self.exit = true;
            return Ok(());
        }

        self.interfaces = self.filter_valid_interfaces(&interfaces);
        self.interface = self.interfaces.get(0).cloned();

        let tx_to_sniffer = self.action_tx.clone();
        self.sniffer.network_interface = self.interfaces.get(0).cloned();
        self.sniffer.register_event_handler(tx_to_sniffer);
        self.sniffer.start();

        Ok(())
    }

    fn filter_valid_interfaces(&self, interfaces: &[NetworkInterface]) -> Vec<NetworkInterface> {
        interfaces
            .iter()
            .filter(|intf| self.is_valid_interface(intf))
            .cloned()
            .collect()
    }

    fn is_valid_interface(&self, intf: &NetworkInterface) -> bool {
        intf.is_up() && !intf.ips.is_empty() && self.has_private_ipv4(intf)
    }

    fn has_private_ipv4(&self, intf: &NetworkInterface) -> bool {
        intf.ips.iter().any(|ip| {
            if let IpAddr::V4(ipv4) = ip.ip() {
                ipv4.is_private() && !ipv4.is_loopback() && !ipv4.is_unspecified()
            } else {
                false
            }
        })
    }

    fn start_background_threads(&self) {
        let tx_key_events = self.action_tx.clone();
        let tx_render = self.action_tx.clone();

        thread::spawn(move || handle_input_events(tx_key_events));

        thread::spawn(move || {
            let tick_rate = Duration::from_secs_f64(1.0 / 22.0);
            let mut last_tick = Instant::now();

            loop {
                let now = Instant::now();
                if now.duration_since(last_tick) >= tick_rate {
                    if tx_render.send(Event::Render).is_err() {
                        break;
                    }
                    last_tick = now;
                } else {
                    thread::sleep(Duration::from_millis(1));
                }
            }
        });
    }

    fn handle_packet_captured(&mut self, packet: CompletePacket) {
        self.packets.insert(0, packet.clone());
        self.sniffer.packets.insert(0, packet);
    }

    fn draw(&mut self, frame: &mut Frame) {
        let (top_area, packets_area) = LayoutHelper::create_main_layout(frame.area());
        let (chart_area, interfaces_area) = LayoutHelper::create_top_layout(top_area);

        self.render_sniffer(frame, packets_area);
        self.render_chart(frame, chart_area);
        self.render_interfaces(frame, interfaces_area);

        if self.show_popup {
            self.render_popup(frame);
        }
    }

    fn render_sniffer(&mut self, frame: &mut Frame, area: ratatui::layout::Rect) {
        self.sniffer.draw(frame, area);
    }

    fn render_chart(&self, frame: &mut Frame, area: ratatui::layout::Rect) {
        let chart_widget = ChartWidget::new(&self.packets);
        chart_widget.render(frame, area);
    }

    fn render_interfaces(&mut self, frame: &mut Frame, area: ratatui::layout::Rect) {
        let interfaces_widget = InterfacesWidget::new(&self.interfaces, &self.interface);
        interfaces_widget.render(
            frame,
            area,
            &mut self.interfaces_table_state,
            &mut self.interfaces_scroll_state,
        );
    }

    fn render_popup(&self, frame: &mut Frame) {
        let popup_widget = PopupWidget::new(&self.selected_popup_packet);
        popup_widget.render(frame, frame.area());
    }

    fn next_active_interface(&mut self) {
        self.sniffer.stop();

        if self.interfaces.is_empty() {
            self.interface = None;
            self.interfaces_table_state.select(None);
            return;
        }

        let current_idx = self.interfaces_table_state.selected().unwrap_or(0);
        let new_idx = (current_idx + 1) % self.interfaces.len();

        self.interfaces_table_state.select(Some(new_idx));
        self.interface = self.interfaces.get(new_idx).cloned();
        self.sniffer.network_interface = self.interfaces.get(new_idx).cloned();

        if self.interface.is_some() {
            self.sniffer.start();
        }
    }
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
