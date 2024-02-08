/// This file implements the python bindings for the lakers library.
/// Note that this module is not restricted by no_std.
use lakers::*;
use lakers_crypto::{default_crypto, CryptoTrait};
use pyo3::wrap_pyfunction;
use pyo3::{prelude::*, types::PyBytes};

mod ead_authz;
mod initiator;
mod responder;

// NOTE: throughout this implementation, we use Vec<u8> for incoming byte lists and PyBytes for outgoing byte lists.
// This is because the incoming lists of bytes are automatically converted to `Vec<u8>` by pyo3,
// but the outgoing ones must be explicitly converted to `PyBytes`.

#[pyfunction(name = "credential_check_or_fetch")]
// FIXME: using inverted parameters from rust version (credential_check_or_fetch)
// since, in Python, by convention, parameters that can be None come later
pub fn py_credential_check_or_fetch<'a>(
    py: Python<'a>,
    id_cred_received: Vec<u8>,
    cred_expected: Option<Vec<u8>>,
) -> PyResult<&'a PyBytes> {
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
    Ok(PyBytes::new(py, valid_cred.value.as_slice()))
}

/// this function is useful to test the python bindings
#[pyfunction]
fn p256_generate_key_pair<'a>(py: Python<'a>) -> PyResult<(&'a PyBytes, &'a PyBytes)> {
    let (x, g_x) = default_crypto().p256_generate_key_pair();
    Ok((
        PyBytes::new(py, x.as_slice()),
        PyBytes::new(py, g_x.as_slice()),
    ))
}

// this name must match `lib.name` in `Cargo.toml`
#[pymodule]
#[pyo3(name = "lakers")]
fn lakers_python(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(p256_generate_key_pair, m)?)?;
    m.add_function(wrap_pyfunction!(py_credential_check_or_fetch, m)?)?;
    // edhoc items
    m.add_class::<initiator::PyEdhocInitiator>()?;
    m.add_class::<responder::PyEdhocResponder>()?;
    m.add_class::<lakers::CredentialTransfer>()?;
    m.add_class::<lakers::EADItem>()?;
    // ead-authz items
    m.add_class::<ead_authz::PyAuthzAutenticator>()?;
    m.add_class::<ead_authz::PyAuthzEnrollmentServer>()?;
    Ok(())
}
