use ratatui::layout::{Constraint, Layout, Rect};

pub struct LayoutHelper;

impl LayoutHelper {
    pub fn create_main_layout(area: Rect) -> (Rect, Rect) {
        let vertical_layout =
            Layout::vertical([Constraint::Percentage(35), Constraint::Percentage(65)]);
        let [top_area, packets_area] = vertical_layout.areas(area);
        (top_area, packets_area)
    }

    pub fn create_top_layout(area: Rect) -> (Rect, Rect) {
        let horizontal_layout =
            Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]);
        let [chart_area, interfaces_area] = horizontal_layout.areas(area);
        (chart_area, interfaces_area)
    }
}
