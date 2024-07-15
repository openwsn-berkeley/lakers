use embassy_nrf::radio::ble::Radio;
use embassy_nrf::saadc::Time;
use embassy_nrf::{peripherals, radio};
use embassy_time::Duration;
use embassy_time::TimeoutError;
use embassy_time::WithTimeout;

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
    TimeoutError,
    RadioError,
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

impl From<TimeoutError> for PacketError {
    fn from(error: TimeoutError) -> Self {
        PacketError::TimeoutError
    }
}

impl From<embassy_nrf::radio::Error> for PacketError {
    fn from(error: embassy_nrf::radio::Error) -> Self {
        match error {
            _ => PacketError::RadioError,
        }
    }
}

pub async fn transmit_and_wait_response(
    radio: &mut Radio<'static, embassy_nrf::peripherals::RADIO>,
    mut packet: Packet,
    timeout: Duration,
) -> Result<Packet, PacketError> {
    let mut rcvd_packet: Packet = Default::default();
    let mut buffer: [u8; MAX_PDU] = [0x00u8; MAX_PDU];

    radio.transmit(packet.as_bytes()).await?;
    radio.receive(&mut buffer).with_timeout(timeout).await?;

    Ok(buffer[..].try_into().unwrap())
}

pub async fn transmit_without_response(
    radio: &mut Radio<'static, embassy_nrf::peripherals::RADIO>,
    mut packet: Packet,
) -> Result<(), PacketError> {
    radio.transmit(packet.as_bytes()).await?;
    Ok(())
}
