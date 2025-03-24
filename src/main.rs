use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet;
use std::env;

fn main() {
    let interface_name = env::args().nth(1).unwrap();

    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .filter(|network_interface| network_interface.name == interface_name)
        .next()
        .unwrap();

    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Tipo de canal incompatível. "),
        Err(e) => panic!("Erro ao criar um canal de datalink: {}", e),
    };

    loop {
        match rx.next() {
            Ok(packet) => {
                let packet = EthernetPacket::new(packet).unwrap();
                if packet.get_ethertype() == EtherTypes::Ipv4 {
                    let ipv4packet = Ipv4Packet::new(packet.payload()).unwrap();
                    println!(
                        "IPv4 packet: source {} destination {} => {} {}",
                        ipv4packet.get_source(),
                        ipv4packet.get_destination(),
                        ipv4packet.get_next_level_protocol(),
                        ipv4packet.get_total_length(),
                    );
                }
            }

            Err(e) => panic!("Erro ao coletar pacote: {}", e),
        }
    }
}
