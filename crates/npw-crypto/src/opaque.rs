//! OPAQUE (RFC 9807) login, via opaque-ke. The OPAQUE "password" is the
//! high-entropy LOGIN key from [`crate::kdf`], so the key-stretching function is
//! the identity: the expensive Argon2id already ran on the client.
//!
//! The server never sees anything it could test a password guess against, and a
//! successful login also proves to the client that the server holds the record
//! made at registration.

use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialFinalization, CredentialRequest,
    CredentialResponse, RegistrationRequest, RegistrationResponse, RegistrationUpload, ServerLogin,
    ServerLoginStartParameters, ServerRegistration, ServerSetup,
};
use rand::rngs::OsRng;

use crate::{CryptoError, Key32, Result};

pub struct Suite;

impl opaque_ke::CipherSuite for Suite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeGroup = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDh;
    type Ksf = opaque_ke::ksf::Identity;
}

fn e<T>(_: T) -> CryptoError {
    CryptoError::Opaque
}

// ---------- client ----------

pub struct ClientRegistrationState(ClientRegistration<Suite>);

/// Step 1: the registration request to send.
pub fn client_register_start(login_key: &Key32) -> Result<(ClientRegistrationState, Vec<u8>)> {
    let r = ClientRegistration::<Suite>::start(&mut OsRng, login_key.as_bytes()).map_err(e)?;
    Ok((
        ClientRegistrationState(r.state),
        r.message.serialize().to_vec(),
    ))
}

/// Step 3: the registration upload (the server stores it as the account's record).
pub fn client_register_finish(
    state: ClientRegistrationState,
    login_key: &Key32,
    response: &[u8],
) -> Result<Vec<u8>> {
    let resp = RegistrationResponse::<Suite>::deserialize(response).map_err(e)?;
    let r = state
        .0
        .finish(
            &mut OsRng,
            login_key.as_bytes(),
            resp,
            ClientRegistrationFinishParameters::default(),
        )
        .map_err(e)?;
    Ok(r.message.serialize().to_vec())
}

pub struct ClientLoginState(ClientLogin<Suite>);

pub fn client_login_start(login_key: &Key32) -> Result<(ClientLoginState, Vec<u8>)> {
    let r = ClientLogin::<Suite>::start(&mut OsRng, login_key.as_bytes()).map_err(e)?;
    Ok((ClientLoginState(r.state), r.message.serialize().to_vec()))
}

/// Returns the finalization message for the server. Fails when the password,
/// the Secret Key or the server's record is wrong (indistinguishable on purpose).
pub fn client_login_finish(
    state: ClientLoginState,
    login_key: &Key32,
    response: &[u8],
) -> Result<Vec<u8>> {
    let resp = CredentialResponse::<Suite>::deserialize(response).map_err(e)?;
    let r = state
        .0
        .finish(
            login_key.as_bytes(),
            resp,
            ClientLoginFinishParameters::default(),
        )
        .map_err(e)?;
    Ok(r.message.serialize().to_vec())
}

// ---------- server ----------

/// The server's long-term OPAQUE key material; created once, kept in the database.
pub fn server_setup_new() -> Vec<u8> {
    ServerSetup::<Suite>::new(&mut OsRng).serialize().to_vec()
}

fn setup(bytes: &[u8]) -> Result<ServerSetup<Suite>> {
    ServerSetup::<Suite>::deserialize(bytes).map_err(e)
}

pub fn server_register_start(
    setup_bytes: &[u8],
    request: &[u8],
    credential_id: &[u8],
) -> Result<Vec<u8>> {
    let req = RegistrationRequest::<Suite>::deserialize(request).map_err(e)?;
    let r =
        ServerRegistration::<Suite>::start(&setup(setup_bytes)?, req, credential_id).map_err(e)?;
    Ok(r.message.serialize().to_vec())
}

/// The password file to store for the account.
pub fn server_register_finish(upload: &[u8]) -> Result<Vec<u8>> {
    let up = RegistrationUpload::<Suite>::deserialize(upload).map_err(e)?;
    Ok(ServerRegistration::<Suite>::finish(up).serialize().to_vec())
}

/// Returns (state to keep until finish, response to send). `record` is `None`
/// for unknown accounts: the response then looks like a real one, so logins
/// cannot be used to discover which accounts exist.
pub fn server_login_start(
    setup_bytes: &[u8],
    record: Option<&[u8]>,
    request: &[u8],
    credential_id: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let record = match record {
        Some(r) => Some(ServerRegistration::<Suite>::deserialize(r).map_err(e)?),
        None => None,
    };
    let req = CredentialRequest::<Suite>::deserialize(request).map_err(e)?;
    let r = ServerLogin::start(
        &mut OsRng,
        &setup(setup_bytes)?,
        record,
        req,
        credential_id,
        ServerLoginStartParameters::default(),
    )
    .map_err(e)?;
    Ok((r.state.serialize().to_vec(), r.message.serialize().to_vec()))
}

/// Succeeds only if the client proved knowledge of the password-derived key.
pub fn server_login_finish(state: &[u8], finalization: &[u8]) -> Result<()> {
    let st = ServerLogin::<Suite>::deserialize(state).map_err(e)?;
    let fin = CredentialFinalization::<Suite>::deserialize(finalization).map_err(e)?;
    st.finish(fin).map_err(e)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn register(setup: &[u8], key: &Key32, id: &[u8]) -> Vec<u8> {
        let (st, req) = client_register_start(key).unwrap();
        let resp = server_register_start(setup, &req, id).unwrap();
        let upload = client_register_finish(st, key, &resp).unwrap();
        server_register_finish(&upload).unwrap()
    }

    fn login(setup: &[u8], record: Option<&[u8]>, key: &Key32, id: &[u8]) -> bool {
        let (st, req) = client_login_start(key).unwrap();
        let (sst, resp) = server_login_start(setup, record, &req, id).unwrap();
        match client_login_finish(st, key, &resp) {
            Ok(fin) => server_login_finish(&sst, &fin).is_ok(),
            Err(_) => false,
        }
    }

    #[test]
    fn register_and_login() {
        let setup = server_setup_new();
        let key = Key32::generate();
        let record = register(&setup, &key, b"acct-1");
        assert!(login(&setup, Some(&record), &key, b"acct-1"));
        assert!(!login(&setup, Some(&record), &Key32::generate(), b"acct-1"));
        assert!(!login(&setup, Some(&record), &key, b"acct-2"));
        assert!(!login(&setup, None, &key, b"acct-1"));
        assert!(!login(&server_setup_new(), Some(&record), &key, b"acct-1"));
    }
}
