use super::*;
use core::fmt;
use pyo3::{exceptions::PyValueError, PyErr};

impl fmt::Display for EDHOCError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EDHOCError: {:?}", self)
    }
}

impl From<EDHOCError> for PyErr {
    fn from(error: EDHOCError) -> Self {
        PyValueError::new_err(error.to_string())
    }
}
