use ratatui::{
    layout::Alignment, text::{Line, Span}, widgets::Paragraph, Frame
};
pub struct Footer;

impl Footer {
    pub fn new() -> Self {
        Self {  }
    }

    pub fn render(&self, frame: &mut Frame, area: ratatui::layout::Rect) {

    let footer_text = Paragraph::new(Line::from(vec![
        Span::raw("q: sair  "),
        Span::raw("j/k ou ↓/↑: navegar  "),
        Span::raw("i: interface  "),
        Span::raw("p: play/pause  "),
        Span::raw("enter: detalhes"),
    ]))
    .alignment(Alignment::Center);

    frame.render_widget(footer_text, area);
}
}
