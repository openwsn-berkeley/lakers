#![no_std]
/// This module contains the FFI bindings for the lakers-c library.
/// Normally the structs can be derived from the Rust structs, except in cases
/// where we need to hide fields that are not compatible with C, such as `Option<..>`.
/// Specifically in the case of `Option<..>` we use a pointer instead, where `NULL` indicates `None`.
///
/// Example command to compile this module for the nRF52840:
/// cargo build --target='thumbv7em-none-eabihf' --no-default-features --features="crypto-cryptocell310"
use lakers::*;
use lakers_crypto::{default_crypto, CryptoTrait};

pub mod ead_authz;
pub mod initiator;

// crate type staticlib requires a panic handler and an allocator
use embedded_alloc::Heap;
use panic_semihosting as _;
#[global_allocator]
static HEAP: Heap = Heap::empty();

/// Note that while the Rust version supports optional value to indicate an empty value,
/// in the C version we use an empty buffer for that case.
#[derive(Clone, Debug)]
#[repr(C)]
pub struct EADItemC {
    pub label: u8,
    pub is_critical: bool,
    pub value: EdhocMessageBuffer,
}

impl EADItemC {
    pub fn to_rust(&self) -> EADItem {
        let value = Some(self.value);

        EADItem {
            label: self.label,
            is_critical: self.is_critical,
            value,
        }
    }

    pub unsafe fn copy_into_c(ead: EADItem, ead_c: *mut EADItemC) {
        (*ead_c).label = ead.label;
        (*ead_c).is_critical = ead.is_critical;
        if let Some(value) = ead.value {
            (*ead_c).value = value;
        }
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
    pub c_r: u8,
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
            c_r: self.c_r,
            ead_2: if self.ead_2.is_null() {
                None
            } else {
                Some(unsafe { (*self.ead_2).to_rust() })
            },
        }
    }

    /// note that it is a shallow copy (ead_2 is handled separately by the caller)
    pub unsafe fn copy_into_c(processing_m2: ProcessingM2, processing_m2_c: *mut ProcessingM2C) {
        (*processing_m2_c).mac_2 = processing_m2.mac_2;
        (*processing_m2_c).prk_2e = processing_m2.prk_2e;
        (*processing_m2_c).th_2 = processing_m2.th_2;
        (*processing_m2_c).x = processing_m2.x;
        (*processing_m2_c).g_y = processing_m2.g_y;
        (*processing_m2_c).plaintext_2 = processing_m2.plaintext_2;
        (*processing_m2_c).c_r = processing_m2.c_r;
    }
}

#[no_mangle]
pub unsafe extern "C" fn credential_rpk_new(
    value: *const u8,
    value_len: usize,
    cred: *mut CredentialRPK,
) -> i8 {
    let value = core::slice::from_raw_parts(value, value_len);
    match CredentialRPK::new(EdhocMessageBuffer::new_from_slice(value).unwrap()) {
        Ok(cred_rpk) => {
            *cred = cred_rpk;
            0
        }
        Err(_) => -1,
    }
}

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
            lakers::P256_ELEM_LEN,
        );
        core::ptr::copy_nonoverlapping(public_key.as_ptr(), out_public_key, lakers::P256_ELEM_LEN);
    }
}
