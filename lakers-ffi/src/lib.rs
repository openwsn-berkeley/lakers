#![no_std]
/// to compile this module for the nRF52840:
/// cargo build --target='thumbv7em-none-eabihf' --no-default-features --features="crypto-cryptocell310"
use edhoc_rs::*;
use lakers_crypto::{default_crypto, CryptoTrait};

pub mod ead_authz;
pub mod initiator;

// crate type staticlib requires a panic handler and an allocator
use embedded_alloc::Heap;
use panic_semihosting as _;
#[global_allocator]
static HEAP: Heap = Heap::empty();

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

    pub unsafe fn copy_into_c(mut ead: EADItem, ead_c: *mut EADItemC) {
        (*ead_c).label = ead.label;
        (*ead_c).is_critical = ead.is_critical;
        (*ead_c).value = ead
            .value
            .as_mut()
            .map_or(core::ptr::null_mut(), |v| v as *mut EdhocMessageBuffer)
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct ProcessingM2C {
    pub mac_2: BytesMac2,
    pub prk_2e: BytesHashLen,
    pub th_2: BytesHashLen,
    pub x: BytesP256ElemLen,
    pub g_y: BytesP256ElemLen,
    pub plaintext_2: EdhocMessageBuffer,
    pub ead_2: *mut EADItemC,
}

impl ProcessingM2C {
    pub fn to_rust(&self) -> ProcessingM2 {
        ProcessingM2 {
            mac_2: self.mac_2,
            prk_2e: self.prk_2e,
            th_2: self.th_2,
            x: self.x,
            g_y: self.g_y,
            plaintext_2: self.plaintext_2,
            ead_2: if self.ead_2.is_null() {
                None
            } else {
                Some(unsafe { (*self.ead_2).to_rust() })
            },
        }
    }

    pub unsafe fn copy_into_c(
        mut processing_m2: ProcessingM2,
        processing_m2_c: *mut ProcessingM2C,
    ) {
        (*processing_m2_c).mac_2 = processing_m2.mac_2;
        (*processing_m2_c).prk_2e = processing_m2.prk_2e;
        (*processing_m2_c).th_2 = processing_m2.th_2;
        (*processing_m2_c).x = processing_m2.x;
        (*processing_m2_c).g_y = processing_m2.g_y;
        (*processing_m2_c).plaintext_2 = processing_m2.plaintext_2;
        if processing_m2.ead_2.is_some() {
            EADItemC::copy_into_c(processing_m2.ead_2.unwrap(), (*processing_m2_c).ead_2);
        }
    }
}
