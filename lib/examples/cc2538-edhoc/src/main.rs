#![no_main]
#![no_std]
#![allow(unused)]

use panic_rtt_target as _;
use rtt_target::{rprintln, rtt_init_print};

use cortex_m::asm;
use cortex_m_rt as rt;
use rt::entry;

use cc2538_hal::crypto::aes_engine::ccm::AesCcmInfo;
use cc2538_hal::crypto::aes_engine::keys::{AesKey, AesKeySize, AesKeys};

use cc2538_hal::{crypto::*, sys_ctrl::*};
use cc2538_pac as pac;

use cc2538_edhoc::Cc2538Accelerator;

mod consts;
use consts::*;

use edhoc::consts::*;
use edhoc::*;

#[entry]
fn main() -> ! {
    rtt_init_print!();

    match inner_main() {
        Ok(()) => cortex_m::peripheral::SCB::sys_reset(),
        Err(e) => panic!("{}", e),
    }
}

fn inner_main() -> Result<(), &'static str> {
    let mut periph = pac::Peripherals::take().ok_or("unable to get peripherals")?;

    let mut core_periph = cortex_m::Peripherals::take().unwrap();
    core_periph.DCB.enable_trace();
    core_periph.DWT.enable_cycle_counter();

    // Setup the clock
    let mut sys_ctrl = periph.SYS_CTRL.constrain();
    sys_ctrl.set_sys_div(ClockDiv::Clock32Mhz);
    sys_ctrl.set_io_div(ClockDiv::Clock32Mhz);
    sys_ctrl.enable_radio_in_active_mode();
    sys_ctrl.enable_gpt0_in_active_mode();
    sys_ctrl.enable_aes_in_active_mode();
    sys_ctrl.enable_pka_in_active_mode();

    let mut sys_ctrl = sys_ctrl.freeze();

    sys_ctrl.reset_aes();
    sys_ctrl.clear_reset_aes();

    sys_ctrl.reset_pka();
    sys_ctrl.clear_reset_pka();

    let crypto = Crypto::new(&mut periph.AES, &mut periph.PKA);
    let mut acc = Cc2538Accelerator::new(crypto);

    test_sha256_digest(&mut acc);
    rprintln!("SHA256 test is ok");

    test_p256_ecdh(&mut acc);
    rprintln!("ECDH over P256 test is ok");

    test_aes_ccm(&mut acc);
    rprintln!("AES-CCM test is ok");

    loop {
        cortex_m::asm::nop();
    }
    Ok(())
}

fn test_sha256_digest<A: Accelerator>(acc: &mut A) {
    let mut digest = [0x00_u8; SHA256_DIGEST_LEN];

    acc.sha256_digest(&MESSAGE_1_TV, &mut digest);
    assert_eq!(digest, H_MESSAGE_1_TV);
}

fn test_p256_ecdh<A: Accelerator>(acc: &mut A) {
    let mut secret = [0x00 as u8; P256_ELEM_LEN];
    acc.p256_ecdh(&X_TV, &G_Y_TV, &mut secret);
    assert_eq!(G_XY_TV, secret);
}

fn test_aes_ccm<A: Accelerator>(acc: &mut A) {
    let mut ciphertext: [u8; CIPHERTEXT_3_LEN] = [0x00; CIPHERTEXT_3_LEN];

    acc.aes_ccm_encrypt(K_3_TV, IV_3_TV, AES_CCM_TAG_LEN, &A_3_TV, &P_3_TV, &mut ciphertext);
    assert_eq!(ciphertext, CIPHERTEXT_3_TV);
}
