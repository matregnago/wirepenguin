use pnet::{datalink::NetworkInterface, util::MacAddr};
use ratatui::{
    layout::{Alignment, Constraint, Margin},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{
        Block, Borders, Cell, Padding, Row, Scrollbar, ScrollbarOrientation, ScrollbarState, Table,
        TableState,
    },
    Frame,
};

pub struct InterfacesWidget<'a> {
    interfaces: &'a [NetworkInterface],
    current_interface: &'a Option<NetworkInterface>,
}

impl<'a> InterfacesWidget<'a> {
    pub fn new(
        interfaces: &'a [NetworkInterface],
        current_interface: &'a Option<NetworkInterface>,
    ) -> Self {
        Self {
            interfaces,
            current_interface,
        }
    }

    pub fn render(
        &self,
        frame: &mut Frame,
        area: ratatui::layout::Rect,
        _table_state: &mut TableState,
        scroll_state: &mut ScrollbarState,
    ) {
        let table = self.build_table();
        frame.render_widget(table, area);

        frame.render_stateful_widget(
            Scrollbar::default()
                .orientation(ScrollbarOrientation::VerticalRight)
                .begin_symbol(None)
                .end_symbol(None),
            area.inner(Margin {
                vertical: 1,
                horizontal: 1,
            }),
            scroll_state,
        );
    }

    fn build_table(&self) -> Table {
        let header = Row::new(vec!["", "Nome", "MAC", "Ipv4", "Ipv6"])
            .style(Style::default().fg(Color::Yellow))
            .height(1);

        let rows = self.build_interface_rows();

        Table::new(
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
        .block(self.build_block())
        .column_spacing(1)
    }

    fn build_interface_rows(&self) -> Vec<Row> {
        self.interfaces
            .iter()
            .map(|interface| self.build_interface_row(interface))
            .collect()
    }

    fn build_interface_row(&self, interface: &NetworkInterface) -> Row {
        let active = if self.is_current_interface(interface) {
            "*"
        } else {
            ""
        };

        let name = if cfg!(windows) {
            interface.description.clone()
        } else {
            interface.name.clone()
        };

        let mac = interface.mac.unwrap_or(MacAddr::default()).to_string();

        let (ipv4_lines, ipv6_spans) = self.extract_ip_info(interface);
        let row_height = std::cmp::max(1, ipv4_lines.len() as u16);

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
            Cell::from(ipv4_lines),
            Cell::from(vec![Line::from(ipv6_spans)]),
        ])
        .height(row_height)
    }

    fn is_current_interface(&self, interface: &NetworkInterface) -> bool {
        self.current_interface
            .as_ref()
            .map_or(false, |current| current == interface)
    }

    fn extract_ip_info(&self, interface: &NetworkInterface) -> (Vec<Line>, Vec<Span>) {
        let ipv4_lines: Vec<Line> = interface
            .ips
            .iter()
            .filter(|ip| ip.is_ipv4())
            .map(|ip| {
                Line::from(vec![Span::styled(
                    format!("{:<2}", ip.ip()),
                    Style::default().fg(Color::Blue),
                )])
            })
            .collect();

        let ipv6_spans: Vec<Span> = interface
            .ips
            .iter()
            .filter(|ip| ip.is_ipv6())
            .map(|ip| Span::from(ip.ip().to_string()))
            .collect();

        (ipv4_lines, ipv6_spans)
    }

    fn build_block(&self) -> Block {
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
            .padding(Padding::new(0, 0, 1, 0))
    }
}
