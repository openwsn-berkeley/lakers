use lakers::*;
use lakers_crypto::{default_crypto, CryptoTrait};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

#[pyclass(name = "EdhocInitiator")]
pub struct PyEdhocInitiator {
    start: InitiatorStart,
    wait_m2: WaitM2,
}

#[pymethods]
impl PyEdhocInitiator {
    #[new]
    fn new() -> Self {
        // we only support a single cipher suite which is already CBOR-encoded
        let mut suites_i: BytesSuites = [0x0; SUITES_LEN];
        let suites_i_len = EDHOC_SUPPORTED_SUITES.len();
        suites_i[0..suites_i_len].copy_from_slice(&EDHOC_SUPPORTED_SUITES[..]);
        let (x, g_x) = default_crypto().p256_generate_key_pair();

        Self {
            start: InitiatorStart {
                x,
                g_x,
                suites_i,
                suites_i_len,
            },
            wait_m2: WaitM2::default(),
        }
    }

    // fn prepare_message_1(&mut self, c_i: Option<u8>, ead_1: &Option<EADItem>) -> PyResult<Vec<u8>> {
    fn prepare_message_1(&mut self, c_i: Option<u8>) -> PyResult<Vec<u8>> {
        let c_i = match c_i {
            Some(c_i) => c_i,
            None => generate_connection_identifier_cbor(&mut default_crypto()),
        };

        // match i_prepare_message_1(&self.start, &mut default_crypto(), c_i, ead_1) {
        match i_prepare_message_1(&self.start, &mut default_crypto(), c_i, &None) {
            Ok((state, message_1)) => {
                self.wait_m2 = state;
                Ok(Vec::from(message_1.as_slice()))
            }
            Err(error) => Err(PyValueError::new_err(error as i8)),
        }
    }
}
