# WirePenguin 🐧

<p align="center">
  <img src="logo.png" alt="WirePenguin Logo" width="200"/>

WirePenguin é um sniffer de pacotes de rede desenvolvido em Rust com interface gráfica no terminal (TUI). O projeto foi criado como trabalho acadêmico por Matheus Tregnago e Ricardo Bregalda.

## 📋 Características

- **Captura em tempo real** de pacotes de rede
- **Interface gráfica no terminal** intuitiva e interativa
- **Análise detalhada** das camadas de enlace, rede e transporte
- **Visualização de cabeçalhos** de protocolos
- **Gráficos dinâmicos** mostrando estatísticas de captura
- **Múltiplas interfaces** de rede suportadas

## 🚀 Protocolos Suportados

### Camada de Enlace
- Ethernet

### Camada de Rede
- IPv4
- IPv6
- ARP
- ICMP
- ICMPv6

### Camada de Transporte
- TCP
- UDP

## 🛠️ Tecnologias Utilizadas

- **Linguagem:** Rust
- **Bibliotecas principais:**
  - [`pnet`](https://github.com/libpnet/libpnet) - Captura e tratamento de pacotes
  - [`ratatui`](https://ratatui.rs/) - Interface gráfica no terminal
  - [`tokio`](https://tokio.rs/) - Runtime assíncrono
  - [`crossterm`](https://github.com/crossterm-rs/crossterm) - Manipulação do terminal

## 📦 Instalação

### Pré-requisitos

- Rust 1.70+ instalado
- Cargo (gerenciador de pacotes do Rust)
- Permissões de administrador/root (necessário para captura de pacotes)

### Compilação

```bash
# Clone o repositório
git clone https://github.com/matregnago/wirepenguin
cd wirepenguin

# Compile o projeto
cargo build --release
```

## 🎮 Uso

Execute o programa com privilégios de administrador:

### Linux/macOS
```bash
sudo ./target/release/wirepenguin
```

### Windows
```powershell
# Execute como Administrador
.\target\release\wirepenguin.exe
```

## ⌨️ Controles

| Tecla | Ação |
|-------|------|
| `q` | Sair do programa |
| `j` ou `↓` | Navegar para baixo na lista |
| `k` ou `↑` | Navegar para cima na lista |
| `i` | Alternar interface de rede |
| `p` | Pausar/Continuar captura |
| `Enter` | Ver detalhes do pacote selecionado |

## 🖼️ Interface

O WirePenguin apresenta uma interface dividida em seções:

1. **Gráfico de Pacotes**: Exibe estatísticas dos protocolos capturados
2. **Lista de Interfaces**: Mostra as interfaces de rede disponíveis
3. **Tabela de Pacotes**: Lista todos os pacotes capturados com informações básicas
4. **Rodapé**: Exibe os atalhos de teclado disponíveis

## 🏗️ Arquitetura

O software utiliza um sistema baseado em eventos com threads separadas para:

- **Thread Principal**: Gerencia a interface e processa eventos
- **Thread de Captura**: Realiza o sniffing de pacotes
- **Thread de Renderização**: Controla a atualização da tela (22 FPS)
- **Thread de Input**: Captura entradas do teclado

### Comunicação entre Threads

Utiliza canais MPSC (Multi-producer, single-consumer) para comunicação entre threads, com três tipos de eventos:
- `Render`: Atualização da interface
- `PacketCaptured`: Novo pacote capturado
- `Input`: Entrada do usuário

## 📝 Estrutura do Projeto

```
wirepenguin/
├── src/
│   ├── main.rs           # Ponto de entrada
│   ├── app.rs            # Lógica principal da aplicação
│   ├── event.rs          # Definição de eventos
│   ├── packet_data.rs    # Estruturas de dados dos pacotes
│   ├── sniffer.rs        # Lógica de captura de pacotes
│   └── widgets/          # Componentes da interface
│       ├── charts.rs     # Gráfico de estatísticas
│       ├── footer.rs     # Rodapé com atalhos
│       ├── interfaces.rs # Lista de interfaces
│       ├── packet_table.rs # Tabela de pacotes
│       └── popup.rs      # Detalhes do pacote
├── Cargo.toml            # Configuração do projeto
└── README.md             # Este arquivo
```

## 👥 Autores

- **Matheus Tregnago** - [GitHub](https://github.com/matregnago)
- **Ricardo Bregalda** - [GitHub](https://github.com/RicardoMBregalda)

## 📚 Referências

- [Ratatui Documentation](https://ratatui.rs/)
- [libpnet Documentation](https://github.com/libpnet/libpnet)
- [Wirefish](https://github.com/WirefishInc/wirefish)
- [Netscanner](https://github.com/Chleba/netscanner)
- [Oryx](https://github.com/pythops/oryx)

## 📄 Licença

Este projeto foi desenvolvido como trabalho acadêmico. Para informações sobre licenciamento, entre em contato com os autores.
