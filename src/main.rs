use packet_sniffer::sniffer;
use pnet::datalink;
use std::env;

mod enums;
mod packet_sniffer;
fn main() {
    let interface_name = env::args().nth(1).unwrap();

    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .filter(|network_interface| network_interface.name == interface_name)
        .next()
        .unwrap();
    sniffer(interface);
}
