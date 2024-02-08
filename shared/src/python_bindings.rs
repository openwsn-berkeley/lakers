/// This file contains the python bindings for some types (added only when needed).
/// These are defined here instead of in the `lakers-python` crate so that the types
/// can be extended, e.g, by adding new traits and methods.
/// Note that this module is not restricted by no_std.
use super::*;
use core::fmt;
use pyo3::{exceptions::PyValueError, types::PyBytes, PyErr};

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

    fn value<'a>(&self, py: Python<'a>) -> Option<&'a PyBytes> {
        self.value.as_ref().map(|v| PyBytes::new(py, v.as_slice()))
    }

    fn label(&self) -> u8 {
        self.label
    }

    fn is_critical(&self) -> bool {
        self.is_critical
    }
}
