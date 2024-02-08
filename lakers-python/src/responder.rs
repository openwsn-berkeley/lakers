use lakers::*;
use lakers_crypto::{default_crypto, CryptoTrait};
use pyo3::{prelude::*, types::PyBytes};

#[pyclass(name = "EdhocResponder")]
pub struct PyEdhocResponder {
    r: Vec<u8>,
    cred_r: CredentialRPK,
    start: ResponderStart,
    processing_m1: ProcessingM1,
    wait_m3: WaitM3,
    processing_m3: ProcessingM3,
    completed: Completed,
}

#[pymethods]
impl PyEdhocResponder {
    #[new]
    fn new(r: Vec<u8>, cred_r: Vec<u8>) -> Self {
        let (y, g_y) = default_crypto().p256_generate_key_pair();

        Self {
            r,
            cred_r: CredentialRPK::new(
                EdhocMessageBuffer::new_from_slice(&cred_r.as_slice()).unwrap(),
            )
            .unwrap(),
            start: ResponderStart { y, g_y },
            processing_m1: ProcessingM1::default(),
            wait_m3: WaitM3::default(),
            processing_m3: ProcessingM3::default(),
            completed: Completed::default(),
        }
    }

    fn process_message_1(&mut self, message_1: Vec<u8>) -> PyResult<Option<EADItem>> {
        let message_1 = EdhocMessageBuffer::new_from_slice(message_1.as_slice()).unwrap(); // FIXME: avoid unwrap call
        let (state, ead_1) = r_process_message_1(&self.start, &mut default_crypto(), &message_1)?;
        self.processing_m1 = state;

        Ok(ead_1)
    }

    fn prepare_message_2<'a>(
        &mut self,
        py: Python<'a>,
        cred_transfer: CredentialTransfer,
        c_r: Option<u8>,
        ead_2: Option<EADItem>,
    ) -> PyResult<&'a PyBytes> {
        let c_r = match c_r {
            Some(c_r) => c_r,
            None => generate_connection_identifier_cbor(&mut default_crypto()),
        };
        let mut r = BytesP256ElemLen::default();
        r.copy_from_slice(self.r.as_slice());

        match r_prepare_message_2(
            &self.processing_m1,
            &mut default_crypto(),
            self.cred_r,
            &r,
            c_r,
            cred_transfer,
            &ead_2,
        ) {
            Ok((state, message_2)) => {
                self.wait_m3 = state;
                Ok(PyBytes::new(py, message_2.as_slice()))
            }
            Err(error) => Err(error.into()),
        }
    }

    pub fn parse_message_3(&mut self, message_3: Vec<u8>) -> PyResult<(Vec<u8>, Option<EADItem>)> {
        let message_3 = EdhocMessageBuffer::new_from_slice(message_3.as_slice()).unwrap(); // FIXME: avoid unwrap call
        match r_parse_message_3(&mut self.wait_m3, &mut default_crypto(), &message_3) {
            Ok((state, id_cred_i, ead_3)) => {
                self.processing_m3 = state;
                let id_cred_i = match id_cred_i {
                    IdCredOwned::CompactKid(kid) => Vec::from([kid]),
                    IdCredOwned::FullCredential(cred) => Vec::from(cred.as_slice()),
                };
                Ok((id_cred_i, ead_3))
            }
            Err(error) => Err(error.into()),
        }
    }

    pub fn verify_message_3(&mut self, valid_cred_i: Vec<u8>) -> PyResult<[u8; SHA256_DIGEST_LEN]> {
        let valid_cred_i = CredentialRPK::new(
            EdhocMessageBuffer::new_from_slice(&valid_cred_i.as_slice()).unwrap(),
        )?;
        match r_verify_message_3(&mut self.processing_m3, &mut default_crypto(), valid_cred_i) {
            Ok((state, prk_out)) => {
                self.completed = state;
                Ok(prk_out)
            }
            Err(error) => Err(error.into()),
        }
    }

    pub fn edhoc_exporter<'a>(
        &mut self,
        py: Python<'a>,
        label: u8,
        context: Vec<u8>,
        length: usize,
    ) -> PyResult<&'a PyBytes> {
        let mut context_buf: BytesMaxContextBuffer = [0x00u8; MAX_KDF_CONTEXT_LEN];
        context_buf[..context.len()].copy_from_slice(context.as_slice());

        let res = edhoc_exporter(
            &self.completed,
            &mut default_crypto(),
            label,
            &context_buf,
            context.len(),
            length,
        );
        Ok(PyBytes::new(py, &res[..length]))
    }

    pub fn edhoc_key_update<'a>(
        &mut self,
        py: Python<'a>,
        context: Vec<u8>,
    ) -> PyResult<&'a PyBytes> {
        let mut context_buf = [0x00u8; MAX_KDF_CONTEXT_LEN];
        context_buf[..context.len()].copy_from_slice(context.as_slice());

        let res = edhoc_key_update(
            &mut self.completed,
            &mut default_crypto(),
            &context_buf,
            context.len(),
        );
        Ok(PyBytes::new(py, &res[..SHA256_DIGEST_LEN]))
    }
}
