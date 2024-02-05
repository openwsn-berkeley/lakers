use lakers::*;
use lakers_crypto::{default_crypto, CryptoTrait};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

#[pyclass(name = "EdhocResponder")]
pub struct PyEdhocResponder {
    r: Vec<u8>,
    cred_r: CredentialRPK,
    start: ResponderStart,
    processing_m1: ProcessingM1,
    wait_m3: WaitM3,
}

#[pymethods]
impl PyEdhocResponder {
    #[new]
    fn new(r: Vec<u8>, cred_r: Vec<u8>) -> Self {
        let (y, g_y) = default_crypto().p256_generate_key_pair();

        Self {
            r,
            cred_r: CredentialRPK::new(
                EdhocMessageBuffer::new_from_slice(&cred_r.as_slice()).unwrap(),
            )
            .unwrap(),
            start: ResponderStart { y, g_y },
            processing_m1: ProcessingM1::default(),
            wait_m3: WaitM3::default(),
        }
    }

    fn process_message_1(&mut self, message_1: Vec<u8>) -> PyResult<Option<EADItem>> {
        let message_1 = EdhocMessageBuffer::new_from_slice(message_1.as_slice()).unwrap(); // FIXME
        let (state, ead_1) = r_process_message_1(&self.start, &mut default_crypto(), &message_1)?;
        self.processing_m1 = state;

        Ok(ead_1)
    }

    fn prepare_message_2(
        &mut self,
        cred_transfer: CredentialTransfer,
        c_r: Option<u8>,
        ead_2: Option<EADItem>,
    ) -> PyResult<Vec<u8>> {
        let c_r = match c_r {
            Some(c_r) => c_r,
            None => generate_connection_identifier_cbor(&mut default_crypto()),
        };
        let mut r = BytesP256ElemLen::default();
        r.copy_from_slice(self.r.as_slice());

        match r_prepare_message_2(
            &self.processing_m1,
            &mut default_crypto(),
            self.cred_r,
            &r,
            c_r,
            cred_transfer,
            &ead_2,
        ) {
            Ok((state, message_2)) => {
                self.wait_m3 = state;
                Ok(Vec::from(message_2.as_slice()))
            }
            Err(error) => Err(PyValueError::new_err(error as i8)),
        }
    }
}
