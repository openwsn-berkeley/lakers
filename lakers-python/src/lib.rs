use lakers::*;
use lakers_crypto::{default_crypto, CryptoTrait};
use pyo3::prelude::*;
use pyo3::wrap_pyfunction;

/// This function is useful to test the python bindings
#[pyfunction]
fn p256_generate_key_pair() -> PyResult<(BytesP256ElemLen, BytesP256ElemLen)> {
    Ok(default_crypto().p256_generate_key_pair())
}

#[pymodule]
fn lakers(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(p256_generate_key_pair, m)?)?;
    // Add more functions here
    Ok(())
}
