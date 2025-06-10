use crate::enums::CompletePacket;

pub enum Event {
    Input(crossterm::event::KeyEvent),
    PacketCaptured(CompletePacket),
    Render,
}
