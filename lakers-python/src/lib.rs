use lakers::{EdhocInitiator as EdhocInitiatorRust, *};
use lakers_crypto::{default_crypto, CryptoTrait};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::wrap_pyfunction;

// #[derive(Clone, Copy)]
#[pyclass]
struct EdhocInitiator {
    state_start: InitiatorStart,
}

#[pymethods]
impl EdhocInitiator {
    #[new]
    fn new() -> Self {
        // we only support a single cipher suite which is already CBOR-encoded
        let mut suites_i: BytesSuites = [0x0; SUITES_LEN];
        let suites_i_len = EDHOC_SUPPORTED_SUITES.len();
        suites_i[0..suites_i_len].copy_from_slice(&EDHOC_SUPPORTED_SUITES[..]);
        let (x, g_x) = default_crypto().p256_generate_key_pair();

        Self {
            state_start: InitiatorStart {
                x,
                g_x,
                suites_i,
                suites_i_len,
            },
        }
    }

    // fn prepare_message_1(&mut self, c_i: Option<u8>, ead_1: &Option<EADItem>) -> PyResult<Vec<u8>> {
    fn prepare_message_1(&mut self, c_i: Option<u8>) -> PyResult<Vec<u8>> {
        let c_i = match c_i {
            Some(c_i) => c_i,
            None => generate_connection_identifier_cbor(&mut default_crypto()),
        };

        // match i_prepare_message_1(&self.state_start, &mut default_crypto(), c_i, ead_1) {
        match i_prepare_message_1(&self.state_start, &mut default_crypto(), c_i, &None) {
            Ok((state, message_1)) => {
                // self.state_start = state;
                Ok(Vec::from(message_1.as_slice()))
            }
            Err(error) => Err(PyValueError::new_err(error as i8)),
        }
    }
}

/// This function is useful to test the python bindings
#[pyfunction]
fn p256_generate_key_pair() -> PyResult<(BytesP256ElemLen, BytesP256ElemLen)> {
    Ok(default_crypto().p256_generate_key_pair())
}

#[pymodule]
fn lakers(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(p256_generate_key_pair, m)?)?;
    m.add_class::<EdhocInitiator>()?;
    // Add more functions here
    Ok(())
}
