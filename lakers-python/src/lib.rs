use lakers::BytesP256ElemLen;
use lakers_crypto::{default_crypto, CryptoTrait};
use pyo3::prelude::*;
use pyo3::wrap_pyfunction;

mod initiator;
mod responder;

/// this function is useful to test the python bindings
#[pyfunction]
fn p256_generate_key_pair() -> PyResult<(BytesP256ElemLen, BytesP256ElemLen)> {
    Ok(default_crypto().p256_generate_key_pair())
}

// this name must match `lib.name` in `Cargo.toml`
#[pymodule]
#[pyo3(name = "lakers")]
fn lakers_python(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(p256_generate_key_pair, m)?)?;
    m.add_class::<initiator::PyEdhocInitiator>()?;
    m.add_class::<responder::PyEdhocResponder>()?;
    m.add_class::<lakers::CredentialTransfer>()?;
    // Add more functions here
    Ok(())
}
