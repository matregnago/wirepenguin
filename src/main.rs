use app::App;
use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use std::env;

mod app;
mod enums;
mod packet_sniffer;

fn main() -> color_eyre::Result<()> {
    let interface_name = env::args().nth(1).unwrap();

    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .filter(|network_interface| network_interface.name == interface_name)
        .next()
        .unwrap();

    color_eyre::install()?;
    let mut terminal = ratatui::init();

    let mut app = App::new(interface);
    let app_result = app.run(&mut terminal);
    ratatui::restore();
    app_result
}
