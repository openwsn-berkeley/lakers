use lakers::{EdhocResponder as EdhocResponderRust, *};
use lakers_crypto::{default_crypto, CryptoTrait};
use pyo3::prelude::*;

#[pyclass]
pub struct EdhocResponder {
    start: ResponderStart,
    processing_m1: ProcessingM1,
}

#[pymethods]
impl EdhocResponder {
    #[new]
    fn new() -> Self {
        let (y, g_y) = default_crypto().p256_generate_key_pair();

        Self {
            start: ResponderStart { y, g_y },
            processing_m1: ProcessingM1::default(),
        }
    }

    fn process_message_1(&mut self, message_1: Vec<u8>) -> PyResult<Option<EADItem>> {
        let message_1 = EdhocMessageBuffer::new_from_slice(message_1.as_slice()).unwrap(); // FIXME
        let (state, ead_1) = r_process_message_1(&self.start, &mut default_crypto(), &message_1)?;
        self.processing_m1 = state;

        Ok(ead_1)
    }
}
