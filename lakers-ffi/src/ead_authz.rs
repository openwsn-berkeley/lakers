use crate::*;
use edhoc_rs::*;
use lakers_crypto::default_crypto;

#[no_mangle]
pub unsafe extern "C" fn authz_device_new(
    id_u: EdhocMessageBuffer,
    g_w: *const BytesP256ElemLen,
    loc_w: EdhocMessageBuffer,
) -> ZeroTouchDevice {
    ZeroTouchDevice::new(id_u, *g_w, loc_w)
}

#[no_mangle]
pub unsafe extern "C" fn authz_device_prepare_ead_1(
    // input parans
    device_c: ZeroTouchDevice,
    secret: *const BytesP256ElemLen,
    ss: u8,
    // output parans
    device_c_out: *mut ZeroTouchDeviceWaitEAD2,
    ead_1_c_out: *mut EADItemC,
) -> i8 {
    let (device, ead_1) = device_c.prepare_ead_1(&mut default_crypto(), *secret, ss);
    *device_c_out = device;
    EADItemC::from_rust_to_c(ead_1, ead_1_c_out);

    0
}

#[no_mangle]
pub unsafe extern "C" fn authz_device_process_ead_2(
    // input parans
    device: ZeroTouchDeviceWaitEAD2,
    ead_2_c: *const EADItemC,
    cred_v: CredentialRPK,
    // output parans
    device_c_out: *mut ZeroTouchDeviceDone,
) -> i8 {
    match device.process_ead_2(
        &mut default_crypto(),
        (*ead_2_c).to_rust(),
        cred_v.value.as_slice(),
    ) {
        Ok(device) => {
            *device_c_out = device;
            0
        }
        Err(_) => -1,
    }
}
