#![no_std]
#![no_main]

use defmt::info;
use defmt::unwrap;
use embassy_executor::Spawner;
use embassy_nrf::gpio::{Level, Output, OutputDrive};
use embassy_nrf::radio::ble::Mode;
use embassy_nrf::radio::ble::Radio;
use embassy_nrf::radio::TxPower;
use embassy_nrf::{bind_interrupts, peripherals, radio};
use embassy_time::{Duration, Timer};
use radio_common::{Packet, PacketError, ADV_ADDRESS, ADV_CRC_INIT, CRC_POLY, FREQ, MAX_PDU};
use {defmt_rtt as _, panic_probe as _};

mod radio_common;

bind_interrupts!(struct Irqs {
    RADIO => radio::InterruptHandler<peripherals::RADIO>;
});

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let mut config = embassy_nrf::config::Config::default();
    config.hfclk_source = embassy_nrf::config::HfclkSource::ExternalXtal;
    let p = embassy_nrf::init(config);

    info!("Starting BLE radio");
    let mut radio = Radio::new(p.RADIO, Irqs);

    let mut led = Output::new(p.P0_13, Level::Low, OutputDrive::Standard);
    led.set_high();

    radio.set_mode(Mode::BLE_1MBIT);
    radio.set_tx_power(TxPower::_0D_BM);
    radio.set_frequency(FREQ);

    radio.set_access_address(ADV_ADDRESS);
    radio.set_header_expansion(false);
    radio.set_crc_init(ADV_CRC_INIT);
    radio.set_crc_poly(CRC_POLY);

    unwrap!(spawner.spawn(receive_and_blink(radio, led)));
}

#[embassy_executor::task]
async fn receive_and_blink(
    mut radio: Radio<'static, embassy_nrf::peripherals::RADIO>,
    mut led: Output<'static>,
) {
    info!("Hello from receive_and_blink");

    loop {
        let mut buffer: [u8; MAX_PDU] = [0x00u8; MAX_PDU];
        let res = radio.receive(&mut buffer).await.unwrap();
        let packet: Packet = buffer[..].try_into().unwrap();

        info!("Packet received: {:X}", packet.pdu[..packet.len]);

        // blink the LED
        led.set_low();
        Timer::after(Duration::from_millis(50)).await;
        led.set_high();
    }
}
