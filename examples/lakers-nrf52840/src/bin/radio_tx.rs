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
use embassy_time::WithTimeout;
use embassy_time::{Duration, Timer};
use {defmt_rtt as _, panic_probe as _};

mod radio_common;

bind_interrupts!(struct Irqs {
    RADIO => radio::InterruptHandler<peripherals::RADIO>;
});

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    info!("Hello world!");
    let mut config = embassy_nrf::config::Config::default();
    config.hfclk_source = embassy_nrf::config::HfclkSource::ExternalXtal;
    let p = embassy_nrf::init(config);

    info!("Starting BLE radio");
    let mut radio: Radio<'_, _> = Radio::new(p.RADIO, Irqs).into();

    let mut led = Output::new(p.P0_13, Level::Low, OutputDrive::Standard);
    led.set_high();

    radio.set_mode(Mode::BLE_1MBIT);
    radio.set_tx_power(TxPower::_0D_BM);
    radio.set_frequency(radio_common::FREQ);

    radio.set_access_address(radio_common::ADV_ADDRESS);
    radio.set_header_expansion(false);
    radio.set_crc_init(radio_common::ADV_CRC_INIT);
    radio.set_crc_poly(radio_common::CRC_POLY);

    unwrap!(spawner.spawn(transmit_and_blink(radio, led, Duration::from_millis(100))));
}

#[embassy_executor::task]
async fn transmit_and_blink(
    mut radio: Radio<'static, embassy_nrf::peripherals::RADIO>,
    mut led: Output<'static>,
    period: Duration,
) {
    loop {
        let mut packet_to_transmit =
            radio_common::Packet::new_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]).unwrap();

        let rcvd = radio_common::transmit_and_wait_response(
            &mut radio,
            packet_to_transmit,
            Duration::from_secs(1),
        )
        .await;

        match rcvd {
            Ok(packet) => info!("Packet received: {:X}", packet.pdu[..packet.len]),
            Err(radio_common::PacketError::TimeoutError) => info!("Timeout!"),
            _ => info!("Unhandled error!"),
        }

        // wait for period before continuing
        Timer::after(period).await;
    }
}
