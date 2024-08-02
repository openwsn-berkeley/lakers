/// This file contains the python bindings for some types (added only when needed).
/// These are defined here instead of in the `lakers-python` crate so that the types
/// can be extended, e.g, by adding new traits and methods.
/// Note that this module is not restricted by no_std.
use super::*;
use core::fmt;
use pyo3::{
    exceptions::{PyTypeError, PyValueError},
    types::PyBytes,
    PyErr,
};

impl fmt::Display for EDHOCError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EDHOCError::{:?}", self)
    }
}

impl From<EDHOCError> for PyErr {
    fn from(error: EDHOCError) -> Self {
        PyValueError::new_err(error.to_string())
    }
}

impl fmt::Display for MessageBufferError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MessageBufferError::{:?}", self)
    }
}

impl From<MessageBufferError> for PyErr {
    fn from(error: MessageBufferError) -> Self {
        PyValueError::new_err(error.to_string())
    }
}

impl fmt::Display for EdhocBufferError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EdhocBufferError::{:?}", self)
    }
}

impl From<EdhocBufferError> for PyErr {
    fn from(error: EdhocBufferError) -> Self {
        PyValueError::new_err(error.to_string())
    }
}

#[pymethods]
impl EADItem {
    #[new]
    fn new_py(label: u8, is_critical: bool, value: Vec<u8>) -> Self {
        Self {
            label,
            is_critical,
            value: Some(EdhocMessageBuffer::new_from_slice(value.as_slice()).unwrap()),
        }
    }

    fn value<'a>(&self, py: Python<'a>) -> Option<Bound<'a, PyBytes>> {
        self.value
            .as_ref()
            .map(|v| PyBytes::new_bound(py, v.as_slice()))
    }

    fn label(&self) -> u8 {
        self.label
    }

    fn is_critical(&self) -> bool {
        self.is_critical
    }
}

// FIXME: adjust for new Credential struct
#[pymethods]
impl Credential {
    /// Construct a new Credential
    ///
    /// This has two variations:
    /// * Pass only the value. Lakers will try to parse the value as a CCS, and populate all fields
    ///   (value, public_key, kid) from that.
    /// * Pass all components. Lakers will not attempt to parse the value. This is primarily
    ///   useful when the credential is not a CCS but eg. a CBOR Web Token (CWT) which the
    ///   application can decrypt based on its association with an ACE Authorization Server (AS),
    ///   or of which it knows the corresponding details from when it requested that token.
    ///
    /// Note that other forms of a Credential can be around (eg. only carrying a kid). Those can
    /// not directly be constructed, but may be produced by Lakers when parsing a message that
    /// contains a credential by reference.
    #[new]
    #[pyo3(signature = (value, *, kid = None, public_key = None))]
    fn new_py(value: Vec<u8>, kid: Option<Vec<u8>>, public_key: Option<Vec<u8>>) -> PyResult<Self> {
        match (kid, public_key) {
            (None, None) => Ok(Self::parse_ccs(&value)?),
            (Some(kid), Some(public_key)) => {
                let public_key = public_key
                    .try_into()
                    .map_err(|_| PyTypeError::new_err("Public key length mismatch"))?;
                Ok(
                    Self::new_ccs(BufferCred::new_from_slice(&value)?, public_key)
                        .with_kid(BufferKid::new_from_slice(&kid)?),
                )
            }
            _ => Err(PyTypeError::new_err(
                "To bypass credential parsing, all optional arguments must be given.",
            )),
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "Credential(bytes.fromhex('{}'), public_key=bytes.fromhex('{}'), kid={:?})",
            hex::encode(self.bytes.as_slice()),
            hex::encode(self.public_key().unwrap().as_slice()),
            self.kid.as_ref().unwrap(),
        )
    }

    fn value<'a>(&self, py: Python<'a>) -> Bound<'a, PyBytes> {
        PyBytes::new_bound(py, self.bytes.as_slice())
    }

    #[pyo3(name = "public_key")]
    fn py_public_key<'a>(&self, py: Python<'a>) -> Bound<'a, PyBytes> {
        PyBytes::new_bound(py, &self.public_key().unwrap())
    }

    fn kid<'a>(&self, py: Python<'a>) -> Bound<'a, PyBytes> {
        PyBytes::new_bound(py, self.kid.as_ref().unwrap().as_slice())
    }
}
