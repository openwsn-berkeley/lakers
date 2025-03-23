use lakers::*;
use lakers_crypto::{default_crypto, CryptoTrait};
use log::trace;
use pyo3::{prelude::*, types::PyBytes};

use super::StateMismatch;

/// An implementation of the EDHOC protocol for the initiator side.
#[pyclass(name = "EdhocInitiator")]
pub struct PyEdhocInitiator {
    cred_i: Option<Credential>,
    // FIXME: This does *not* get taken out, so some data stays available for longer than it needs
    // to be -- but that is apparently needed in selected_cipher_suite and
    // compute_ephemeral_secret.
    start: InitiatorStart,
    wait_m2: Option<WaitM2>,
    processing_m2: Option<ProcessingM2>,
    processed_m2: Option<ProcessedM2>,
    wait_m4: Option<WaitM4>,
    completed: Option<Completed>,
}

#[pymethods]
impl PyEdhocInitiator {
    #[new]
    fn new() -> Self {
        trace!("Initializing EdhocInitiator");
        let mut crypto = default_crypto();
        let suites_i =
            prepare_suites_i(&crypto.supported_suites(), EDHOCSuite::CipherSuite2.into()).unwrap();
        let (x, g_x) = crypto.p256_generate_key_pair();

        Self {
            cred_i: None,
            start: InitiatorStart {
                x,
                g_x,
                method: EDHOCMethod::StatStat.into(),
                suites_i,
            },
            wait_m2: None,
            processing_m2: None,
            processed_m2: None,
            wait_m4: None,
            completed: None,
        }
    }

    /// Generates message 1.
    ///
    /// At this point, a ``C_I`` (connection identifier) may be provided, as well as additonal EAD
    /// data.
    #[pyo3(signature = (c_i=None, ead_1=None))]
    fn prepare_message_1<'a>(
        &mut self,
        py: Python<'a>,
        c_i: Option<Vec<u8>>,
        ead_1: Option<EADItem>,
    ) -> PyResult<Bound<'a, PyBytes>> {
        let c_i = match c_i {
            Some(c_i) => ConnId::from_slice(c_i.as_slice()).ok_or(
                pyo3::exceptions::PyValueError::new_err("Connection identifier out of range"),
            )?,
            None => generate_connection_identifier_cbor(&mut default_crypto()),
        };

        match i_prepare_message_1(&self.start, &mut default_crypto(), c_i, &ead_1) {
            Ok((state, message_1)) => {
                self.wait_m2 = Some(state);
                Ok(PyBytes::new_bound(py, message_1.as_slice()))
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Process message 2.
    ///
    /// This produces both the ``C_R`` and the ``ID_CRED_R``, and maybe additional EAD data sent by
    /// the responder, but does not verify them yet: They are only verified when the application
    /// provides the expanded credential ``CRED_R`` (typically based on the information in
    /// ``ID_CRED_R``) in :meth:`.verify_message_2()`.
    pub fn parse_message_2<'a>(
        &mut self,
        py: Python<'a>,
        message_2: Vec<u8>,
    ) -> PyResult<(Bound<'a, PyBytes>, Bound<'a, PyBytes>, Option<EADItem>)> {
        let message_2 = EdhocMessageBuffer::new_from_slice(message_2.as_slice())?;

        match i_parse_message_2(
            &self.wait_m2.take().ok_or(StateMismatch)?,
            &mut default_crypto(),
            &message_2,
        ) {
            Ok((state, c_r, id_cred_r, ead_2)) => {
                self.processing_m2 = Some(state);
                Ok((
                    PyBytes::new_bound(py, c_r.as_slice()),
                    PyBytes::new_bound(py, id_cred_r.bytes.as_slice()),
                    ead_2,
                ))
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Verifies the previously inserted message 2.
    ///
    /// At this point, the initiator's private key ``I`` as well as the initiator's identity ``CRED_I``
    /// needs to be provided, as well as the peer's credential ``CRED_R`` (as looked up by its
    /// ``ID_CRED_R`` from the preceeding :meth:`parse_message_2()` output).
    pub fn verify_message_2(
        &mut self,
        i: Vec<u8>,
        cred_i: super::AutoCredential,
        valid_cred_r: super::AutoCredential,
    ) -> PyResult<()> {
        let cred_i = cred_i.to_credential()?;
        let valid_cred_r = valid_cred_r.to_credential()?;

        match i_verify_message_2(
            &self.processing_m2.take().ok_or(StateMismatch)?,
            &mut default_crypto(),
            valid_cred_r,
            i.as_slice()
                .try_into()
                .expect("Wrong length of initiator private key"),
        ) {
            Ok(state) => {
                self.processed_m2 = Some(state);
                self.cred_i = Some(cred_i);
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Generates a message 3.
    ///
    /// Input influences whether the credential previously provided in :meth:`verify_message_2()` is
    /// sent by value or reference, and whether any additional EAD data is to be sent.
    #[pyo3(signature = (cred_transfer, ead_3=None))]
    pub fn prepare_message_3<'a>(
        &mut self,
        py: Python<'a>,
        cred_transfer: CredentialTransfer,
        ead_3: Option<EADItem>,
    ) -> PyResult<(Bound<'a, PyBytes>, Bound<'a, PyBytes>)> {
        match i_prepare_message_3(
            &mut self.processed_m2.take().ok_or(StateMismatch)?,
            &mut default_crypto(),
            self.cred_i.unwrap(),
            cred_transfer,
            &ead_3,
        ) {
            Ok((state, message_3, prk_out)) => {
                self.wait_m4 = Some(state);
                Ok((
                    PyBytes::new_bound(py, message_3.as_slice()),
                    PyBytes::new_bound(py, prk_out.as_slice()),
                ))
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Declares the protocol to have completed without the need of a message 4.
    ///
    /// Key material can be extracted after this point, but some properties of the protocol only
    /// hold when non-EDHOC messages protected with the extracted key material are received from
    /// the peer.
    pub fn completed_without_message_4<'a>(&mut self, py: Python<'a>) -> PyResult<()> {
        match i_complete_without_message_4(&self.wait_m4.take().ok_or(StateMismatch)?) {
            Ok(state) => {
                self.completed = Some(state);
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Processes and verifies message 4.
    ///
    /// This produces EAD data if the peer sent any.
    pub fn process_message_4<'a>(
        &mut self,
        py: Python<'a>,
        message_4: Vec<u8>,
    ) -> PyResult<Option<EADItem>> {
        let message_4 = EdhocMessageBuffer::new_from_slice(message_4.as_slice())?;

        match i_process_message_4(
            &mut self.wait_m4.take().ok_or(StateMismatch)?,
            &mut default_crypto(),
            &message_4,
        ) {
            Ok((state, ead_4)) => {
                self.completed = Some(state);
                Ok(ead_4)
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Exports key material.
    pub fn edhoc_exporter<'a>(
        &mut self,
        py: Python<'a>,
        label: u8,
        context: Vec<u8>,
        length: usize,
    ) -> PyResult<Bound<'a, PyBytes>> {
        let mut context_buf: BytesMaxContextBuffer = [0x00u8; MAX_KDF_CONTEXT_LEN];
        context_buf[..context.len()].copy_from_slice(context.as_slice());

        let res = edhoc_exporter(
            self.completed.as_ref().ok_or(StateMismatch)?,
            &mut default_crypto(),
            label,
            &context_buf,
            context.len(),
            length,
        );
        Ok(PyBytes::new_bound(py, &res[..length]))
    }

    /// Performs the key update procedure, enabling the production of new key material.
    pub fn edhoc_key_update<'a>(
        &mut self,
        py: Python<'a>,
        context: Vec<u8>,
    ) -> PyResult<Bound<'a, PyBytes>> {
        let mut context_buf = [0x00u8; MAX_KDF_CONTEXT_LEN];
        context_buf[..context.len()].copy_from_slice(context.as_slice());

        let res = edhoc_key_update(
            self.completed.as_mut().ok_or(StateMismatch)?,
            &mut default_crypto(),
            &context_buf,
            context.len(),
        );
        Ok(PyBytes::new_bound(py, &res[..SHA256_DIGEST_LEN]))
    }

    pub fn get_h_message_1<'a>(&self, py: Python<'a>) -> PyResult<Bound<'a, PyBytes>> {
        Ok(PyBytes::new_bound(
            py,
            &self.wait_m2.as_ref().ok_or(StateMismatch)?.h_message_1[..],
        ))
    }

    pub fn compute_ephemeral_secret<'a>(
        &self,
        py: Python<'a>,
        g_a: Vec<u8>,
    ) -> PyResult<Bound<'a, PyBytes>> {
        let mut g_a_arr = BytesP256ElemLen::default();
        g_a_arr.copy_from_slice(&g_a[..]);
        let secret = default_crypto().p256_ecdh(&self.start.x, &g_a_arr);
        Ok(PyBytes::new_bound(py, &secret[..]))
    }

    /// The cipher suite that is agreed on by the exchange.
    pub fn selected_cipher_suite(&self) -> PyResult<u8> {
        Ok(self.start.suites_i[self.start.suites_i.len() - 1])
    }
}
