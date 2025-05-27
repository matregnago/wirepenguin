use packet_sniffer::sniffer;
use pnet::datalink;
use std::env;
use std::process; // Importa para sair do processo

mod enums;
mod packet_sniffer;

fn main() { // main agora não retorna Result
    // 1. Obtenção do nome da interface:
    let args: Vec<String> = env::args().collect();

    let interface_name = match args.get(1) {
        Some(name) => name.clone(),
        None => {
            eprintln!("Faltou o uso da interface:");
            eprintln!("Exemplo: wirepenguin eth0");
            process::exit(1); // Sai com código de erro 1
        }
    };

    // 2. Localização da interface de rede:
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .filter(|network_interface| network_interface.name == interface_name)
        .next()
        .expect(&format!("Interface de rede '{}' não encontrada.", interface_name)); 

    sniffer(interface);

}