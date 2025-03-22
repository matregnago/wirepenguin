use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use pnet::packet::ethernet::EthernetPacket;
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
                println!("{:?}", packet);
            }
            Err(e) => panic!("Erro ao coletar pacote: {}", e),
        }
    }
}
