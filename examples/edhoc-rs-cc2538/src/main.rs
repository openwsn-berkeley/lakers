#![no_main]
#![no_std]
#![allow(unused)]
#![feature(default_alloc_error_handler)]

use static_alloc::Bump;

#[global_allocator]
static A: Bump<[u8; 1 << 11]> = Bump::uninit();

use panic_rtt_target as _;
use rtt_target::{rprintln, rtt_init_print};

use cortex_m::asm;
use cortex_m_rt as rt;
use rt::entry;

use cc2538_hal::crypto::aes_engine::ccm::AesCcmInfo;
use cc2538_hal::crypto::aes_engine::keys::{AesKey, AesKeySize, AesKeys};

use cc2538_hal::{crypto::*, sys_ctrl::*};
use cc2538_pac as pac;

use edhoc_rs::{EDHOCError, EdhocInitiator, EdhocResponder, EdhocState};
use hexlit::hex;

#[entry]
fn main() -> ! {
    rtt_init_print!();

    match inner_main() {
        Ok(()) => cortex_m::peripheral::SCB::sys_reset(),
        Err(e) => panic!("{}", e),
    }
}

fn inner_main() -> Result<(), &'static str> {
    const ID_CRED_I: &str = "a104412b";
    const ID_CRED_R: &str = "a104410a";
    const CRED_I: &str = "A2027734322D35302D33312D46462D45462D33372D33322D333908A101A5010202412B2001215820AC75E9ECE3E50BFC8ED60399889522405C47BF16DF96660A41298CB4307F7EB62258206E5DE611388A4B8A8211334AC7D37ECB52A387D257E6DB3C2A93DF21FF3AFFC8";
    const I: &str = "fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b";
    const R: &str = "72cc4761dbd4c78f758931aa589d348d1ef874a7e303ede2f140dcf3e6aa4aac";
    const G_I: &str = "ac75e9ece3e50bfc8ed60399889522405c47bf16df96660a41298cb4307f7eb6"; // used
    const _G_I_Y_COORD: &str = "6e5de611388a4b8a8211334ac7d37ecb52a387d257e6db3c2a93df21ff3affc8"; // not used
    const CRED_R: &str = "A2026008A101A5010202410A2001215820BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F02258204519E257236B2A0CE2023F0931F1F386CA7AFDA64FCDE0108C224C51EABF6072";
    const G_R: &str = "bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f0";
    const C_R_TV: [u8; 1] = hex!("27");

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

    rprintln!("Hello from CC2538");

    test_handshake();

    fn test_handshake() {
        let state_initiator: EdhocState = Default::default();
        let mut initiator = EdhocInitiator::new(
            state_initiator,
            I,
            G_R,
            ID_CRED_I,
            CRED_I,
            ID_CRED_R,
            CRED_R,
        );
        let state_responder: EdhocState = Default::default();
        let mut responder = EdhocResponder::new(
            state_responder,
            R,
            G_I,
            ID_CRED_I,
            CRED_I,
            ID_CRED_R,
            CRED_R,
        );

        let (error, message_1) = initiator.prepare_message_1(); // to update the state
        assert!(error == EDHOCError::Success);

        let error = responder.process_message_1(&message_1);
        assert!(error == EDHOCError::Success);

        let (error, message_2, c_r) = responder.prepare_message_2();
        assert!(error == EDHOCError::Success);
        assert!(c_r != 0xff);
        let (error, _c_r) = initiator.process_message_2(&message_2);
        assert!(error == EDHOCError::Success);

        let (error, message_3, i_prk_out) = initiator.prepare_message_3();
        assert!(error == EDHOCError::Success);
        let (error, r_prk_out) = responder.process_message_3(&message_3);
        assert!(error == EDHOCError::Success);

        // check that prk_out is equal at initiator and responder side
        assert_eq!(i_prk_out, r_prk_out);

        // derive OSCORE secret and salt at both sides and compare
        let (error, i_oscore_secret) = initiator.edhoc_exporter(0u8, &[], 16); // label is 0
        assert!(error == EDHOCError::Success);
        let (error, i_oscore_salt) = initiator.edhoc_exporter(1u8, &[], 8); // label is 1
        assert!(error == EDHOCError::Success);

        let (error, r_oscore_secret) = responder.edhoc_exporter(0u8, &[], 16); // label is 0
        assert!(error == EDHOCError::Success);
        let (error, r_oscore_salt) = responder.edhoc_exporter(1u8, &[], 8); // label is 1
        assert!(error == EDHOCError::Success);

        assert_eq!(i_oscore_secret, r_oscore_secret);
        assert_eq!(i_oscore_salt, r_oscore_salt);
    }

    loop {
        cortex_m::asm::nop();
    }
    Ok(())
}
