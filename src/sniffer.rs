use std::{
    sync::mpsc::Sender,
    thread::{self, JoinHandle},
};

use crate::{
    event::Event,
    widgets::packet_table::{PacketTable, PacketTableState},
};
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
use ratatui::{
    layout::Rect,
    widgets::{Block, Borders},
    Frame,
};

use crate::packet_data::{
    ArpPacketInfo, CompletePacket, EthernetPacketInfo, IcmpPacketInfo, Icmpv6PacketInfo,
    Ipv4PacketInfo, Ipv6PacketInfo, PacketsData, TcpPacketInfo, UdpPacketInfo,
};

pub struct Sniffer {
    pub network_interface: Option<NetworkInterface>,
    pub tx: Option<mpsc::Sender<Event>>,
    pub stop_signal: Arc<AtomicBool>,
    pub sniffer_paused: bool,
    pub sniffer_handle: Option<JoinHandle<()>>,
    pub packet_table_state: PacketTableState,
    pub packets: Vec<CompletePacket>,
}

impl Sniffer {
    pub fn new() -> Self {
        Sniffer {
            network_interface: None,
            tx: None,
            stop_signal: Arc::new(AtomicBool::new(false)),
            sniffer_paused: true,
            sniffer_handle: None,
            packet_table_state: PacketTableState::new(),
            packets: Vec::new(),
        }
    }

    pub fn stop(&mut self) {
        self.stop_signal.store(true, Ordering::Relaxed);

        if let Some(handle) = self.sniffer_handle.take() {
            let _ = handle.join();
        }
        self.sniffer_paused = true;
    }

    pub fn start(&mut self) {
        let tx_to_sniffer = self.tx.clone();
        if let Some(tx_to_sniffer) = tx_to_sniffer {
            let interface = self.network_interface.clone();
            if let Some(interface) = interface {
                let stop_signal = Arc::new(AtomicBool::new(false));
                self.stop_signal = stop_signal.clone();
                let handle = thread::spawn(move || {
                    Self::run(interface, tx_to_sniffer, stop_signal);
                });

                self.sniffer_handle = Some(handle);
                self.sniffer_paused = false;
            }
        }
    }

    pub fn next_row(&mut self) {
        self.packet_table_state.next_row(self.packets.len());
    }

    pub fn previous_row(&mut self) {
        self.packet_table_state.previous_row(self.packets.len());
    }

    pub fn selected_packet_index(&self) -> Option<usize> {
        self.packet_table_state.selected()
    }

    fn run(
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
                println!("Tipo desconhecido de datalink channel",);
                return;
            }
            Err(_) => {
                println!("Erro ao criar datalink channel");
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
                        Self::handle_ethernet_packet(&ethernet_packet, &mut complete_packet);
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
                    Self::handle_icmp_packet(&icmp_packet, complete_packet);
                }
            }
            IpNextHeaderProtocols::Icmpv6 => {
                let icmpv6_packet = Icmpv6Packet::new(packet);
                if let Some(icmpv6_packet) = icmpv6_packet {
                    Self::handle_icmpv6_packet(&icmpv6_packet, complete_packet);
                }
            }
            IpNextHeaderProtocols::Tcp => {
                let tcp_packet = TcpPacket::new(packet);
                if let Some(tcp_packet) = tcp_packet {
                    Self::handle_tcp_packet(&tcp_packet, complete_packet);
                }
            }
            IpNextHeaderProtocols::Udp => {
                let udp_packet = UdpPacket::new(packet);
                if let Some(udp_packet) = udp_packet {
                    Self::handle_udp_packet(&udp_packet, complete_packet);
                }
            }
            _ => {}
        }
    }

    fn handle_ipv6_packet(ipv6_packet: &Ipv6Packet, complete_packet: &mut CompletePacket) {
        complete_packet.set_layer2_packet(Some(PacketsData::Ipv6Packet(Ipv6PacketInfo::from(
            ipv6_packet,
        ))));
        Self::handle_ip_next_header_protocols(
            ipv6_packet.payload(),
            ipv6_packet.get_next_header(),
            complete_packet,
        );
    }

    fn handle_ipv4_packet(ipv4_packet: &Ipv4Packet, complete_packet: &mut CompletePacket) {
        complete_packet.set_layer2_packet(Some(PacketsData::Ipv4Packet(Ipv4PacketInfo::from(
            ipv4_packet,
        ))));
        Self::handle_ip_next_header_protocols(
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

    fn handle_ethernet_packet(
        ethernet_packet: &EthernetPacket,
        complete_packet: &mut CompletePacket,
    ) {
        complete_packet.set_layer1_packet(Some(PacketsData::EthernetPacket(
            EthernetPacketInfo::from(ethernet_packet),
        )));
        match ethernet_packet.get_ethertype() {
            EtherTypes::Arp => {
                let arp_packet = ArpPacket::new(ethernet_packet.payload());
                if let Some(arp_packet) = arp_packet {
                    Self::handle_arp_packet(&arp_packet, complete_packet);
                }
            }
            EtherTypes::Ipv4 => {
                let ipv4_packet = Ipv4Packet::new(ethernet_packet.payload());
                if let Some(ipv4_packet) = ipv4_packet {
                    Self::handle_ipv4_packet(&ipv4_packet, complete_packet);
                }
            }
            EtherTypes::Ipv6 => {
                let ipv6_packet = Ipv6Packet::new(ethernet_packet.payload());
                if let Some(ipv6_packet) = ipv6_packet {
                    Self::handle_ipv6_packet(&ipv6_packet, complete_packet);
                }
            }
            _ => {}
        }
    }

    pub fn register_event_handler(&mut self, tx: Sender<Event>) {
        self.tx = Some(tx);
    }

    pub fn draw(&mut self, frame: &mut Frame<'_>, area: Rect) {
        let widget = PacketTable::new(&self.packets).block(Block::default().borders(Borders::ALL).title("Lista de pacotes"));

        frame.render_stateful_widget(widget, area, &mut self.packet_table_state);
    }
}
