use app::App;
mod app;
mod sniffer;
mod event;
mod widgets;
mod packet_data;
fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;
    let mut terminal = ratatui::init();

    let mut app = App::new();
    let app_result = app.run(&mut terminal);
    ratatui::restore();
    app_result
}
