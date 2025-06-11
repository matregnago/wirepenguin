use app::App;
mod app;
mod event;
mod packet_data;
mod sniffer;
mod widgets;
fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;
    let mut terminal = ratatui::init();

    let mut app = App::new();
    let app_result = app.run(&mut terminal);
    ratatui::restore();
    app_result
}
