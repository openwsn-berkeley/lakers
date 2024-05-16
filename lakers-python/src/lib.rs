/// This file implements the python bindings for the lakers library.
/// Note that this module is not restricted by no_std.
use lakers::*;
// use lakers_ead_authz::consts::*;
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
    cred_expected: Option<AutoCredentialRPK>,
) -> PyResult<&'a PyBytes> {
    let cred_expected = cred_expected.map(|c| c.to_credential()).transpose()?;

    let valid_cred = if id_cred_received.len() == 1 {
        credential_check_or_fetch(
            cred_expected,
            CredentialRPK {
                kid: id_cred_received[0],
                value: Default::default(),
                public_key: Default::default(),
            },
        )?
    } else {
        credential_check_or_fetch(
            cred_expected,
            CredentialRPK::new(
                EdhocMessageBuffer::new_from_slice(id_cred_received.as_slice()).unwrap(),
            )?,
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

/// Helper for PyO3 converted functions that behave like passing an argument through a
/// `CredentialRPK` constructor; use this in an argument and then call [self.to_credential()].
/// The resulting function will accept both a bytes-ish object (and pass it through
/// [CredentialRPK::new()] or a preexisting [CredentialRPK].
#[derive(FromPyObject)]
enum AutoCredentialRPK {
    #[pyo3(transparent, annotation = "bytes")]
    Parse(Vec<u8>),
    #[pyo3(transparent, annotation = "CredentialRPK")]
    Existing(lakers_shared::CredentialRPK),
}

impl AutoCredentialRPK {
    fn to_credential(self) -> PyResult<CredentialRPK> {
        use AutoCredentialRPK::*;
        Ok(match self {
            Existing(e) => e,
            Parse(v) => CredentialRPK::new(EdhocMessageBuffer::new_from_slice(&v)?)?,
        })
    }
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
    m.add_class::<lakers::CredentialRPK>()?;
    // ead-authz items
    m.add_class::<ead_authz::PyAuthzDevice>()?;
    m.add_class::<ead_authz::PyAuthzAutenticator>()?;
    m.add_class::<ead_authz::PyAuthzEnrollmentServer>()?;
    m.add_class::<ead_authz::PyAuthzServerUserAcl>()?;

    let submodule = PyModule::new(_py, "consts")?;
    submodule.add("EAD_AUTHZ_LABEL", lakers_ead_authz::consts::EAD_AUTHZ_LABEL)?;
    m.add_submodule(submodule)?;
    Ok(())
}
