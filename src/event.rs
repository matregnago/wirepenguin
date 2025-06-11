use crate::packet_data::CompletePacket;

pub enum Event {
    Input(crossterm::event::KeyEvent),
    PacketCaptured(CompletePacket),
    Render,
}
