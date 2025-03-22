/// This file implements the python bindings for the lakers library.
/// Note that this module is not restricted by no_std.
use lakers::*;
// use lakers_ead_authz::consts::*;
use lakers_crypto::{default_crypto, CryptoTrait};
use log::trace;
use pyo3::wrap_pyfunction;
use pyo3::{prelude::*, types::PyBytes};

mod ead_authz;
mod initiator;
mod responder;

/// Error raised when operations on a Python object did not happen in the sequence in which they
/// were intended.
///
/// This currently has no more detailed response because for every situation this can occur in,
/// there are different possible explainations that we can't get across easily in a single message.
/// For example, if `responder.processing_m1` is absent, that can be either because no message 1
/// was processed into it yet, or because message 2 was already generated.
#[derive(Debug)]
pub(crate) struct StateMismatch;

trait ErrExt {
    type T;
    fn with_cause(self, py: Python<'_>, cause: &str) -> Result<Self::T, PyErr>;
}

impl<T> ErrExt for Option<T> {
    type T = T;
    fn with_cause(self, py: Python<'_>, cause: &str) -> Result<T, PyErr> {
        self.ok_or_else(|| pyo3::exceptions::PyValueError::new_err(format!("{}", cause)))
    }
}

impl<T, E: core::fmt::Display> ErrExt for Result<T, E> {
    type T = T;
    fn with_cause(self, py: Python<'_>, cause: &str) -> Result<T, PyErr> {
        self.map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{} ({})", cause, e)))
    }
}

impl std::error::Error for StateMismatch {}
impl std::fmt::Display for StateMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Type state mismatch")
    }
}
impl From<StateMismatch> for PyErr {
    #[track_caller]
    fn from(err: StateMismatch) -> PyErr {
        let location = std::panic::Location::caller();
        // It would be nice to inject something more idiomatic on the Python side, eg. setting a
        // cause with a Rust file and line number, but to create such an object we'd need the GIL,
        // and that'd required doing a lot of things custom, eg. by creating a custom class where
        // we pass that extra info in extra arguments, or re-implementing PyErr's lazy state (which
        // we can't hook into because that's private) -- having the location in the text is the
        // second best option.
        pyo3::exceptions::PyRuntimeError::new_err(format!("{} (internally {})", err, location))
    }
}

// NOTE: throughout this implementation, we use Vec<u8> for incoming byte lists and PyBytes for outgoing byte lists.
// This is because the incoming lists of bytes are automatically converted to `Vec<u8>` by pyo3,
// but the outgoing ones must be explicitly converted to `PyBytes`.

// NOTE: using inverted parameters from rust version (credential_check_or_fetch)
// since, in Python, parameters that can be None come later
#[pyfunction(name = "credential_check_or_fetch")]
#[pyo3(signature = (id_cred_received, cred_expected=None))]
pub fn py_credential_check_or_fetch<'a>(
    py: Python<'a>,
    id_cred_received: Vec<u8>,
    cred_expected: Option<AutoCredential>,
) -> PyResult<Bound<'a, PyBytes>> {
    let valid_cred = credential_check_or_fetch(
        cred_expected.map(|c| c.to_credential()).transpose()?,
        IdCred::from_full_value(id_cred_received.as_slice())?,
    )?;

    Ok(PyBytes::new_bound(py, valid_cred.bytes.as_slice()))
}

/// this function is useful to test the python bindings
#[pyfunction]
fn p256_generate_key_pair<'a>(
    py: Python<'a>,
) -> PyResult<(Bound<'a, PyBytes>, Bound<'a, PyBytes>)> {
    let (x, g_x) = default_crypto().p256_generate_key_pair();
    Ok((
        PyBytes::new_bound(py, x.as_slice()),
        PyBytes::new_bound(py, g_x.as_slice()),
    ))
}

/// Helper for PyO3 converted functions that behave like passing an argument through a
/// `Credential` constructor; use this in an argument and then call [self.to_credential()].
/// The resulting function will accept both a bytes-ish object (and pass it through
/// [Credential::new()] or a preexisting [Credential].
#[derive(FromPyObject)]
pub enum AutoCredential {
    #[pyo3(transparent, annotation = "bytes")]
    Parse(Vec<u8>),
    #[pyo3(transparent, annotation = "Credential")]
    Existing(lakers_shared::Credential),
}

impl AutoCredential {
    pub fn to_credential(self) -> Result<Credential, EDHOCError> {
        use AutoCredential::*;
        Ok(match self {
            Existing(e) => e,
            Parse(v) => Credential::parse_ccs(v.as_slice())?,
        })
    }
}

/// Lakers implementation of EDHOC.
///
/// The `EdhocInitiator` and `EdhocResponder` are entry points to this module.
///
/// Operations in this module produce logging entries on the `lakers.initiator` and
/// `lakers.responder` logger names. Due to implementation details of `pyo3_log`, Python's log
/// levels are cached in the Rust implementation. It is recommended that the full logging
/// is configured before creating Lakers objects. A setup with `logging.basicConfig(loglevel=5)`
/// will also show Lakers' trace level log messages, which have no equivalent Python level.
#[pymodule]
// this name must match `lib.name` in `Cargo.toml`
#[pyo3(name = "lakers")]
fn lakers_python(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    // initialize the logger once when the module is imported
    if let Err(e) = pyo3_log::Logger::new(py, pyo3_log::Caching::LoggersAndLevels)?
        .filter(log::LevelFilter::Trace)
        .install()
    {
        // Not logging anything in the successful case (see module level docs)
        log::error!("lakers-python failed to set up: {e}");
    }

    m.add_function(wrap_pyfunction!(p256_generate_key_pair, m)?)?;
    m.add_function(wrap_pyfunction!(py_credential_check_or_fetch, m)?)?;
    // edhoc items
    m.add_class::<initiator::PyEdhocInitiator>()?;
    m.add_class::<responder::PyEdhocResponder>()?;
    m.add_class::<lakers::CredentialTransfer>()?;
    m.add_class::<lakers::EADItem>()?;
    m.add_class::<lakers::Credential>()?;
    // ead-authz items
    m.add_class::<ead_authz::PyAuthzDevice>()?;
    m.add_class::<ead_authz::PyAuthzAutenticator>()?;
    m.add_class::<ead_authz::PyAuthzEnrollmentServer>()?;
    m.add_class::<ead_authz::PyAuthzServerUserAcl>()?;

    let submodule = PyModule::new_bound(py, "consts")?;
    submodule.add("EAD_AUTHZ_LABEL", lakers_ead_authz::consts::EAD_AUTHZ_LABEL)?;
    m.add_submodule(&submodule)?;
    Ok(())
}
