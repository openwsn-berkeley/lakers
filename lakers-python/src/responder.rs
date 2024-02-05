use lakers::{EdhocResponder as EdhocResponderRust, *};
use lakers_crypto::{default_crypto, CryptoTrait};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

#[pyclass]
pub struct EdhocResponder {
    state_start: ResponderStart,
}

#[pymethods]
impl EdhocResponder {
    #[new]
    fn new() -> Self {
        let (y, g_y) = default_crypto().p256_generate_key_pair();

        Self {
            state_start: ResponderStart { y, g_y },
        }
    }
}
