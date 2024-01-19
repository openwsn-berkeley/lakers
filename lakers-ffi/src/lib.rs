#![no_std]
/// to compile this module for the nRF52840:
/// cargo build --target='thumbv7em-none-eabihf' --no-default-features --features="crypto-cryptocell310"
use edhoc_rs::{EADItem, EdhocMessageBuffer};
use lakers_crypto::{default_crypto, CryptoTrait};

pub mod initiator;

// Panic handler for cortex-m targets
#[cfg(any(feature = "crypto-cryptocell310", feature = "crypto-psa-baremetal"))]
use panic_semihosting as _;

// This function is useful to test the FFI
#[no_mangle]
pub extern "C" fn p256_generate_key_pair_from_c(out_private_key: *mut u8, out_public_key: *mut u8) {
    let (private_key, public_key) = default_crypto().p256_generate_key_pair();

    unsafe {
        // copy the arrays to the pointers received from C
        // this makes sure that data is not dropped when the function returns
        core::ptr::copy_nonoverlapping(
            private_key.as_ptr(),
            out_private_key,
            edhoc_rs::P256_ELEM_LEN,
        );
        core::ptr::copy_nonoverlapping(
            public_key.as_ptr(),
            out_public_key,
            edhoc_rs::P256_ELEM_LEN,
        );
    }
}

#[derive(Clone, Debug)]
#[repr(C)]
pub struct EADItemC {
    pub label: u8,
    pub is_critical: bool,
    pub value: *mut EdhocMessageBuffer,
}

impl EADItemC {
    pub fn to_rust(&self) -> EADItem {
        let value = if self.value.is_null() {
            None
        } else {
            Some(unsafe { *self.value })
        };

        EADItem {
            label: self.label,
            is_critical: self.is_critical,
            value,
        }
    }

    pub unsafe fn from_rust_to_c(mut ead: EADItem, ead_c: *mut EADItemC) {
        (*ead_c).label = ead.label;
        (*ead_c).is_critical = ead.is_critical;
        (*ead_c).value = ead
            .value
            .as_mut()
            .map_or(core::ptr::null_mut(), |v| v as *mut EdhocMessageBuffer)
    }
}
