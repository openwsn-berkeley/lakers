use lakers::*;
use lakers_crypto::default_crypto;
use pyo3::prelude::*;

#[pyclass(name = "AuthzEnrollmentServer")]
pub struct PyAuthzEnrollmentServer {
    server: ZeroTouchServer,
}

#[pymethods]
impl PyAuthzEnrollmentServer {
    #[new]
    pub fn new(w: Vec<u8>, cred_v: Vec<u8>, acl: Option<Vec<u8>>) -> Self {
        let mut w_arr = BytesP256ElemLen::default();
        w_arr.copy_from_slice(&w.as_slice());
        let acl = if let Some(acl) = acl {
            Some(EdhocMessageBuffer::new_from_slice(acl.as_slice()).unwrap())
        } else {
            None
        };

        Self {
            server: ZeroTouchServer::new(w_arr, cred_v.as_slice(), acl),
        }
    }

    fn handle_voucher_request(&self, vreq: Vec<u8>) -> PyResult<Vec<u8>> {
        let vreq = EdhocMessageBuffer::new_from_slice(vreq.as_slice()).unwrap();
        match self
            .server
            .handle_voucher_request(&mut default_crypto(), &vreq)
        {
            Ok(voucher_response) => Ok(Vec::from(voucher_response.as_slice())),
            Err(error) => Err(error.into()),
        }
    }
}
