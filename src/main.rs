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
                match packet.get_ethertype() {
                    EtherTypes::Ipv4 => {
                        let ipv4packet = Ipv4Packet::new(packet.payload()).unwrap();
                        match ipv4packet.get_next_level_protocol() {
                            IpNextHeaderProtocols::Udp => {
                                let udppacket = UdpPacket::new(packet.payload()).unwrap();
                                println!(
                                    "UDP Packet: {} -> {} length: {}",
                                    udppacket.get_source(),
                                    udppacket.get_destination(),
                                    udppacket.get_length()
                                )
                            }
                            IpNextHeaderProtocols::Tcp => {
                                let tcppacket = TcpPacket::new(packet.payload()).unwrap();
                                println!(
                                    "TCP Packet: {} -> {}",
                                    tcppacket.get_source(),
                                    tcppacket.get_destination()
                                )
                            }
                            _ => continue,
                        }
                    }
                    EtherTypes::Ipv6 => {
                        let ipv6packet = Ipv6Packet::new(packet.payload()).unwrap();
                        println!(
                            "IPv6 packet: source {} destination {} => {}",
                            ipv6packet.get_source(),
                            ipv6packet.get_destination(),
                            ipv6packet.get_next_header()
                        );
                    }
                    EtherTypes::Arp => {
                        let arppacket = ArpPacket::new(packet.payload()).unwrap();
                        println!("ARP packet: {:?}", arppacket);
                    }
                    _ => {
                        println!(
                            "Unknown packet: {} > {}; ethertype: {:?} length: {}",
                            packet.get_source(),
                            packet.get_destination(),
                            packet.get_ethertype(),
                            packet.packet().len()
                        );
                    }
                }
            }

            Err(e) => panic!("Erro ao coletar pacote: {}", e),
        }
    }
}
