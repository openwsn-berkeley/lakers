pub const MAX_PDU: usize = 258;
pub const FREQ: u32 = 2408;
pub const ADV_ADDRESS: u32 = 0x12345678;
pub const ADV_CRC_INIT: u32 = 0xffff;
pub const CRC_POLY: u32 = 0x00065b;

#[derive(Debug)]
pub enum PacketError {
    SliceTooLong,
    SliceTooShort,
    ParsingError,
}
pub struct Packet {
    pub len: usize,
    pub pdu: [u8; MAX_PDU],
}

impl Default for Packet {
    fn default() -> Self {
        Packet {
            len: 0,
            pdu: [0u8; MAX_PDU],
        }
    }
}

impl Packet {
    pub fn new() -> Self {
        Packet {
            len: 0,
            pdu: [0u8; MAX_PDU],
        }
    }

    pub fn new_from_slice(slice: &[u8]) -> Result<Self, PacketError> {
        let mut buffer = Self::new();
        if buffer.fill_with_slice(slice).is_ok() {
            Ok(buffer)
        } else {
            Err(PacketError::SliceTooLong)
        }
    }

    pub fn fill_with_slice(&mut self, slice: &[u8]) -> Result<(), PacketError> {
        if slice.len() <= self.pdu.len() {
            self.len = slice.len();
            self.pdu[..self.len].copy_from_slice(slice);
            Ok(())
        } else {
            Err(PacketError::SliceTooLong)
        }
    }

    pub fn as_bytes(&mut self) -> &[u8] {
        self.pdu.copy_within(..self.len, 2);
        self.pdu[0] = 0x00;
        self.pdu[1] = self.len as u8;

        &self.pdu[..self.len]
    }
}

impl TryInto<Packet> for &[u8] {
    type Error = ();

    fn try_into(self) -> Result<Packet, Self::Error> {
        let mut packet: Packet = Default::default();

        if self.len() > 1 {
            packet.len = self[1] as usize;
            packet.pdu[..packet.len].copy_from_slice(&self[2..2 + packet.len]);
            Ok(packet)
        } else {
            Err(())
        }
    }
}
