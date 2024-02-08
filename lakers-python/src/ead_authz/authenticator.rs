use lakers::*;
use pyo3::prelude::*;

#[pyclass(name = "AuthzAutenticator")]
pub struct PyAuthzAutenticator {
    authenticator: ZeroTouchAuthenticator,
    authenticator_wait: ZeroTouchAuthenticatorWaitVoucherResp,
}

#[pymethods]
impl PyAuthzAutenticator {
    #[new]
    fn new() -> Self {
        Self {
            authenticator: ZeroTouchAuthenticator::default(),
            authenticator_wait: ZeroTouchAuthenticatorWaitVoucherResp::default(),
        }
    }

    pub fn process_ead_1(
        &mut self,
        ead_1: EADItem,
        message_1: Vec<u8>,
    ) -> PyResult<(Vec<u8>, Vec<u8>)> {
        let message_1 = EdhocMessageBuffer::new_from_slice(message_1.as_slice()).unwrap(); // FIXME: avoid unwrap
        let (state, loc_w, voucher_request) =
            self.authenticator.process_ead_1(&ead_1, &message_1)?;
        self.authenticator_wait = state;
        Ok((
            Vec::from(loc_w.as_slice()),
            Vec::from(voucher_request.as_slice()),
        ))
    }

    pub fn prepare_ead_2(&self, voucher_response: Vec<u8>) -> PyResult<EADItem> {
        let voucher_response =
            EdhocMessageBuffer::new_from_slice(voucher_response.as_slice()).unwrap(); // FIXME: avoid unwrap
        Ok(self.authenticator_wait.prepare_ead_2(&voucher_response)?)
    }
}
