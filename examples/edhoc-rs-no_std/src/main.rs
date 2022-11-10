#![no_std]
#![no_main]
#![feature(default_alloc_error_handler)]

use static_alloc::Bump;

#[global_allocator]
static A: Bump<[u8; 1 << 10]> = Bump::uninit();

use cortex_m_rt::entry;
use cortex_m_semihosting::{
    debug::{self, EXIT_SUCCESS},
    hprintln as println,
};

use panic_semihosting as _;

use edhoc_rs::{EDHOCError, EdhocInitiator, EdhocState};

#[entry]
fn main() -> ! {
    // testing output
    println!("Hello, hacspec!");

    // testing asserts
    assert!(1 == 1);

    // edhoc-rs test code
    use hexlit::hex;

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

    const MESSAGE_1_TV: [u8; 37] =
        hex!("030258208af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b637");

    fn test_new_initiator() {
        let state: EdhocState = Default::default();
        let _initiator = EdhocInitiator::new(state, I, G_R, ID_CRED_I, CRED_I, ID_CRED_R, CRED_R);
    }

    test_new_initiator();

    fn test_prepare_message_1() {
        let state: EdhocState = Default::default();
        let mut initiator =
            EdhocInitiator::new(state, I, G_R, ID_CRED_I, CRED_I, ID_CRED_R, CRED_R);

        let (error, message_1) = initiator.prepare_message_1();
        assert!(error == EDHOCError::Success);
        assert_eq!(message_1, MESSAGE_1_TV);
    }

    test_prepare_message_1();

    // exit via semihosting call
    debug::exit(EXIT_SUCCESS);

    // the cortex_m_rt `entry` macro requires `main()` to never return
    loop {}
}
