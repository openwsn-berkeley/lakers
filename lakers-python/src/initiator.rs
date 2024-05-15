use lakers::*;
use lakers_crypto::{default_crypto, CryptoTrait};
use pyo3::{prelude::*, types::PyBytes};

#[pyclass(name = "EdhocInitiator")]
pub struct PyEdhocInitiator {
    cred_i: Option<CredentialRPK>,
    start: InitiatorStart,
    wait_m2: WaitM2,
    processing_m2: ProcessingM2,
    processed_m2: ProcessedM2,
    completed: Completed,
}

#[pymethods]
impl PyEdhocInitiator {
    #[new]
    fn new() -> Self {
        // we only support a single cipher suite which is already CBOR-encoded
        let mut suites_i: BytesSuites = [0x0; SUITES_LEN];
        let suites_i_len = EDHOC_SUPPORTED_SUITES.len();
        suites_i[0..suites_i_len].copy_from_slice(&EDHOC_SUPPORTED_SUITES[..]);
        let (x, g_x) = default_crypto().p256_generate_key_pair();

        Self {
            cred_i: None,
            start: InitiatorStart {
                x,
                g_x,
                suites_i,
                suites_i_len,
            },
            wait_m2: WaitM2::default(),
            processing_m2: ProcessingM2::default(),
            processed_m2: ProcessedM2::default(),
            completed: Completed::default(),
        }
    }

    fn prepare_message_1<'a>(
        &mut self,
        py: Python<'a>,
        c_i: Option<Vec<u8>>,
        ead_1: Option<EADItem>,
    ) -> PyResult<&'a PyBytes> {
        let c_i = match c_i {
            Some(c_i) => ConnId::from_slice(c_i.as_slice()).ok_or(
                pyo3::exceptions::PyValueError::new_err("Connection identifier out of range"),
            )?,
            None => generate_connection_identifier_cbor(&mut default_crypto()),
        };

        match i_prepare_message_1(&self.start, &mut default_crypto(), c_i, &ead_1) {
            Ok((state, message_1)) => {
                self.wait_m2 = state;
                Ok(PyBytes::new(py, message_1.as_slice()))
            }
            Err(error) => Err(error.into()),
        }
    }

    pub fn parse_message_2<'a>(
        &mut self,
        py: Python<'a>,
        message_2: Vec<u8>,
    ) -> PyResult<(&'a PyBytes, &'a PyBytes, Option<EADItem>)> {
        let message_2 = EdhocMessageBuffer::new_from_slice(message_2.as_slice())?;

        match i_parse_message_2(&self.wait_m2, &mut default_crypto(), &message_2) {
            Ok((state, c_r, id_cred_r, ead_2)) => {
                self.processing_m2 = state;
                let id_cred_r = if id_cred_r.reference_only() {
                    PyBytes::new(py, &[id_cred_r.kid])
                } else {
                    PyBytes::new(py, id_cred_r.value.as_slice())
                };
                let c_r = PyBytes::new(py, c_r.as_slice());
                Ok((c_r, id_cred_r, ead_2))
            }
            Err(error) => Err(error.into()),
        }
    }

    pub fn verify_message_2(
        &mut self,
        i: Vec<u8>,
        cred_i: super::AutoCredentialRPK,
        valid_cred_r: super::AutoCredentialRPK,
    ) -> PyResult<()> {
        let cred_i = cred_i.to_credential()?;
        let valid_cred_r = valid_cred_r.to_credential()?;

        match i_verify_message_2(
            &self.processing_m2,
            &mut default_crypto(),
            valid_cred_r,
            i.as_slice()
                .try_into()
                .expect("Wrong length of initiator private key"),
        ) {
            Ok(state) => {
                self.processed_m2 = state;
                self.cred_i = Some(cred_i);
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    }

    pub fn prepare_message_3<'a>(
        &mut self,
        py: Python<'a>,
        cred_transfer: CredentialTransfer,
        ead_3: Option<EADItem>,
    ) -> PyResult<(&'a PyBytes, &'a PyBytes)> {
        match i_prepare_message_3(
            &mut self.processed_m2,
            &mut default_crypto(),
            self.cred_i.unwrap(),
            cred_transfer,
            &ead_3,
        ) {
            Ok((state, message_3, prk_out)) => {
                self.completed = state;
                Ok((
                    PyBytes::new(py, message_3.as_slice()),
                    PyBytes::new(py, prk_out.as_slice()),
                ))
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

    pub fn get_h_message_1<'a>(&self, py: Python<'a>) -> PyResult<&'a PyBytes> {
        Ok(PyBytes::new(py, &self.wait_m2.h_message_1[..]))
    }

    pub fn compute_ephemeral_secret<'a>(
        &self,
        py: Python<'a>,
        g_a: Vec<u8>,
    ) -> PyResult<&'a PyBytes> {
        let mut g_a_arr = BytesP256ElemLen::default();
        g_a_arr.copy_from_slice(&g_a[..]);
        let secret = default_crypto().p256_ecdh(&self.start.x, &g_a_arr);
        Ok(PyBytes::new(py, &secret[..]))
    }

    pub fn selected_cipher_suite(&self) -> PyResult<u8> {
        Ok(self.start.suites_i[self.start.suites_i_len - 1])
    }
}
