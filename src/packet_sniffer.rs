use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    time::Duration,
};

use pnet::{
    datalink::{Channel, ChannelType, NetworkInterface},
    packet::{
        arp::ArpPacket,
        ethernet::{EtherTypes, EthernetPacket},
        icmp::IcmpPacket,
        icmpv6::Icmpv6Packet,
        ip::{IpNextHeaderProtocol, IpNextHeaderProtocols},
        ipv4::Ipv4Packet,
        ipv6::Ipv6Packet,
        tcp::TcpPacket,
        udp::UdpPacket,
        Packet,
    },
};

use crate::{
    app::Event,
    enums::{
        ArpPacketInfo, CompletePacket, EthernetPacketInfo, IcmpPacketInfo, Icmpv6PacketInfo,
        Ipv4PacketInfo, Ipv6PacketInfo, PacketsData, TcpPacketInfo, UdpPacketInfo,
    },
};

fn handle_icmp_packet(icmp_packet: &IcmpPacket, complete_packet: &mut CompletePacket) {
    complete_packet.set_layer3_packet(Some(PacketsData::IcmpPacket(IcmpPacketInfo::from(
        icmp_packet,
    ))));
}
fn handle_icmpv6_packet(icmpv6_packet: &Icmpv6Packet, complete_packet: &mut CompletePacket) {
    complete_packet.set_layer3_packet(Some(PacketsData::Icmpv6Packet(Icmpv6PacketInfo::from(
        icmpv6_packet,
    ))));
}
fn handle_tcp_packet(tcp_packet: &TcpPacket, complete_packet: &mut CompletePacket) {
    complete_packet.set_layer3_packet(Some(PacketsData::TcpPacket(TcpPacketInfo::from(
        tcp_packet,
    ))));
}
fn handle_udp_packet(udp_packet: &UdpPacket, complete_packet: &mut CompletePacket) {
    complete_packet.set_layer3_packet(Some(PacketsData::UdpPacket(UdpPacketInfo::from(
        udp_packet,
    ))));
}
fn handle_ip_next_header_protocols(
    packet: &[u8],
    protocol: IpNextHeaderProtocol,
    complete_packet: &mut CompletePacket,
) {
    match protocol {
        IpNextHeaderProtocols::Icmp => {
            let icmp_packet = IcmpPacket::new(packet);
            if let Some(icmp_packet) = icmp_packet {
                handle_icmp_packet(&icmp_packet, complete_packet);
            }
        }
        IpNextHeaderProtocols::Icmpv6 => {
            let icmpv6_packet = Icmpv6Packet::new(packet);
            if let Some(icmpv6_packet) = icmpv6_packet {
                handle_icmpv6_packet(&icmpv6_packet, complete_packet);
            }
        }
        IpNextHeaderProtocols::Tcp => {
            let tcp_packet = TcpPacket::new(packet);
            if let Some(tcp_packet) = tcp_packet {
                handle_tcp_packet(&tcp_packet, complete_packet);
            }
        }
        IpNextHeaderProtocols::Udp => {
            let udp_packet = UdpPacket::new(packet);
            if let Some(udp_packet) = udp_packet {
                handle_udp_packet(&udp_packet, complete_packet);
            }
        }
        _ => {}
    }
}
fn handle_ipv6_packet(ipv6_packet: &Ipv6Packet, complete_packet: &mut CompletePacket) {
    complete_packet.set_layer2_packet(Some(PacketsData::Ipv6Packet(Ipv6PacketInfo::from(
        ipv6_packet,
    ))));
    handle_ip_next_header_protocols(
        ipv6_packet.payload(),
        ipv6_packet.get_next_header(),
        complete_packet,
    );
}
fn handle_ipv4_packet(ipv4_packet: &Ipv4Packet, complete_packet: &mut CompletePacket) {
    complete_packet.set_layer2_packet(Some(PacketsData::Ipv4Packet(Ipv4PacketInfo::from(
        ipv4_packet,
    ))));
    handle_ip_next_header_protocols(
        ipv4_packet.payload(),
        ipv4_packet.get_next_level_protocol(),
        complete_packet,
    );
}
fn handle_arp_packet(arp_packet: &ArpPacket, complete_packet: &mut CompletePacket) {
    complete_packet.set_layer2_packet(Some(PacketsData::ArpPacket(ArpPacketInfo::from(
        arp_packet,
    ))));
}

fn handle_ethernet_packet(ethernet_packet: &EthernetPacket, complete_packet: &mut CompletePacket) {
    complete_packet.set_layer1_packet(Some(PacketsData::EthernetPacket(EthernetPacketInfo::from(
        ethernet_packet,
    ))));
    match ethernet_packet.get_ethertype() {
        EtherTypes::Arp => {
            let arp_packet = ArpPacket::new(ethernet_packet.payload());
            if let Some(arp_packet) = arp_packet {
                handle_arp_packet(&arp_packet, complete_packet);
            }
        }
        EtherTypes::Ipv4 => {
            let ipv4_packet = Ipv4Packet::new(ethernet_packet.payload());
            if let Some(ipv4_packet) = ipv4_packet {
                handle_ipv4_packet(&ipv4_packet, complete_packet);
            }
        }
        EtherTypes::Ipv6 => {
            let ipv6_packet = Ipv6Packet::new(ethernet_packet.payload());
            if let Some(ipv6_packet) = ipv6_packet {
                handle_ipv6_packet(&ipv6_packet, complete_packet);
            }
        }
        _ => {}
    }
}

pub fn sniffer(
    network_interface: NetworkInterface,
    tx: mpsc::Sender<Event>,
    stop_signal: Arc<AtomicBool>,
) {
    let (_, mut receiver) = match pnet::datalink::channel(
        &network_interface,
        pnet::datalink::Config {
            write_buffer_size: 4096,
            read_buffer_size: 4096,
            read_timeout: Some(Duration::new(1, 0)),
            write_timeout: None,
            channel_type: ChannelType::Layer2,
            bpf_fd_attempts: 1000,
            linux_fanout: None,
            promiscuous: true,
            socket_fd: None,
        },
    ) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => {
            eprintln!(
                "Datalink channel for {} is an unknown type. Sniffer thread exiting.",
                network_interface.name
            );
            return;
        }
        Err(e) => {
            eprintln!(
                "Error creating datalink channel for {}: {}. Sniffer thread exiting.",
                network_interface.name, e
            );
            return;
        }
    };

    let mut packet_id = 0;

    loop {
        if stop_signal.load(Ordering::Relaxed) {
            break;
        }

        match receiver.next() {
            Ok(packet) => {
                packet_id += 1;
                let mut complete_packet = CompletePacket::new(packet_id);
                let ethernet_packet = EthernetPacket::new(packet);
                if let Some(ethernet_packet) = ethernet_packet {
                    handle_ethernet_packet(&ethernet_packet, &mut complete_packet);
                };
                tx.send(Event::PacketCaptured(complete_packet)).unwrap()
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::TimedOut {
                    continue;
                }
            }
        }
    }
}
