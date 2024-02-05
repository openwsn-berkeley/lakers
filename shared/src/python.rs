use super::*;
use pyo3::{exceptions::PyValueError, PyErr};

impl From<EDHOCError> for PyErr {
    fn from(error: EDHOCError) -> Self {
        PyValueError::new_err(error as i8)
    }
}
