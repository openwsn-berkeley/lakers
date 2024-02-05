use lakers::BytesP256ElemLen;
use lakers::*;
use lakers_crypto::{default_crypto, CryptoTrait};
use pyo3::prelude::*;
use pyo3::wrap_pyfunction;

mod initiator;
use initiator::*;

mod responder;
use responder::*;

/// this function is useful to test the python bindings
#[pyfunction]
fn p256_generate_key_pair() -> PyResult<(BytesP256ElemLen, BytesP256ElemLen)> {
    Ok(default_crypto().p256_generate_key_pair())
}

#[pyfunction(name = "credential_check_or_fetch")]
// FIXME: using inverted parameters from rust version (credential_check_or_fetch)
// since, in Python, by convention, parameters that can be None come later
pub fn py_credential_check_or_fetch(
    id_cred_received: Vec<u8>,
    cred_expected: Option<Vec<u8>>,
) -> PyResult<Vec<u8>> {
    let cred_expected = if let Some(cred_expected) = cred_expected {
        Some(CredentialRPK::new(
            EdhocMessageBuffer::new_from_slice(cred_expected.as_slice()).unwrap(),
        )?)
    } else {
        None
    };
    let valid_cred = if id_cred_received.len() == 1 {
        credential_check_or_fetch(cred_expected, IdCredOwned::CompactKid(id_cred_received[0]))?
    } else {
        credential_check_or_fetch(
            cred_expected,
            IdCredOwned::FullCredential(
                EdhocMessageBuffer::new_from_slice(id_cred_received.as_slice()).unwrap(),
            ),
        )?
    };
    Ok(Vec::from(valid_cred.value.as_slice()))
}

// this name must match `lib.name` in `Cargo.toml`
#[pymodule]
#[pyo3(name = "lakers")]
fn lakers_python(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(p256_generate_key_pair, m)?)?;
    m.add_function(wrap_pyfunction!(py_credential_check_or_fetch, m)?)?;
    m.add_class::<initiator::PyEdhocInitiator>()?;
    m.add_class::<responder::PyEdhocResponder>()?;
    m.add_class::<lakers::CredentialTransfer>()?;
    // Add more functions here
    Ok(())
}
