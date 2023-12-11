#![no_std]

#[cfg(test)]
mod test_vectors;

pub mod initiator;
pub mod responder;
pub mod server;
mod shared;

#[cfg(test)]
mod test_lib {
    use super::*;
    use crate::{
        initiator::ZeroTouchDevice, responder::ZeroTouchAuthenticator, server::ZeroTouchServer,
        test_vectors::*,
    };
    use edhoc_crypto::default_crypto;

    #[test]
    fn test_complete() {
        let device = ZeroTouchDevice::new(
            ID_U_TV.try_into().unwrap(),
            G_W_TV.try_into().unwrap(),
            LOC_W_TV.try_into().unwrap(),
        );
        let authenticator = ZeroTouchAuthenticator::new();
        let server = ZeroTouchServer::new(
            CRED_V_TV.try_into().unwrap(),
            W_TV.try_into().unwrap(),
            Some(ACL_TV.try_into().unwrap()),
        );
    }
}
