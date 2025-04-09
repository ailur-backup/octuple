use crate::database::get_connection;
use crate::handlers::server::OctupleServer;
use crate::handlers::{new_response, new_response_string, OctupleRequest};
use crate::key::SIGNING_KEY;
use ed25519_dalek::ed25519::SignatureBytes;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use libcharm::endpoints::user::{Create, Login};
use libcharm::request::{BlankRequest, Request};
use libcharm::user::{Certificate, CertificateComponents};
use rusqlite::Error::QueryReturnedNoRows;
use signature::{Keypair, Signer, Verifier};
use std::error;

pub trait OctupleCertificateComponents {
    fn sign(&self, key: &SigningKey) -> SignatureBytes;
}

impl OctupleCertificateComponents for CertificateComponents {
    fn sign(&self, key: &SigningKey) -> SignatureBytes {
        let bytes = rmp_serde::to_vec(&self).expect("Failed to serialize components");
        key.sign(&bytes).to_bytes()
    }
}

pub trait OctupleCertificate {
    fn verify(&self) -> Result<(), Box<dyn error::Error>>;
}

impl OctupleCertificate for Certificate {
    fn verify(&self) -> Result<(), Box<dyn error::Error>> {
        let bytes = rmp_serde::to_vec(&self.components)?;
        let key = self.components.user.server.get_server_key()?;
        key.verify(&bytes, &Signature::from(self.signature))?;
        Ok(())
    }
}

pub fn init(app: &mut tide::Server<()>) {
    app.at("/api/v1/users/create").post(create);
    app.at("/api/v1/users/delete").post(delete);
    app.at("/api/v1/users/login").post(login);
}

pub async fn create(mut req: tide::Request<()>) -> tide::Result {
    let create: Create = req.body_json().await?;
    let connection = get_connection();
    let result = connection.execute(
        "INSERT INTO users (username, key) VALUES (?, ?);",
        (create.user.username, create.key),
    );
    if result.is_err() {
        let err = result.err().expect("Failed to get error");
        if err.sqlite_error_code().expect("Failed to get error code") == rusqlite::ErrorCode::ConstraintViolation {
            return Ok(new_response("User already exists", 409))
        } else {
            panic!("Failed to insert user into database: {}", err)
        }
    }
    Ok(new_response("User created", 201))
}

pub async fn delete(mut req: tide::Request<()>) -> tide::Result {
    let request: Request<BlankRequest> = req.body_json().await?;
    let error = request.verify();
    if error.is_err() {
        return Ok(new_response_string(format!("Invalid signature: {}", error.err().unwrap()), 403))
    }
    let connection = get_connection();
    let result = connection.execute(
        "DELETE FROM users WHERE username = ?;",
        (request.certificate.components.user.username,)
    );
    if result.is_err() {
        let err = result.err().expect("Failed to get error");
        if err.sqlite_error_code().expect("Failed to get error code") == rusqlite::ErrorCode::ConstraintViolation {
            return Ok(new_response("User not found", 404))
        } else {
            panic!("Failed to delete user from database: {}", err)
        }
    }
    Ok(new_response("User deleted", 200))
}

pub async fn login(mut req: tide::Request<()>) -> tide::Result {
    let login: Login = req.body_json().await?;
    let connection = get_connection();
    let query_result = connection.query_row(
        "SELECT key FROM users WHERE username = ?",
        &[&login.user.username],
        |row| row.get(0)
    );
    if query_result.is_err() {
        let err = query_result.err().expect("Failed to get error");
        if err == QueryReturnedNoRows {
            return Ok(new_response("User not found", 404))
        } else {
            panic!("Failed to get user from database: {}", err)
        }
    }
    let key: [u8; 32] = query_result.expect("Failed to get key");
    let public_key = VerifyingKey::from_bytes(&key).expect("Failed to convert key");
    if public_key.verify(&[login.data], &Signature::from_bytes(&login.signature)).is_err() {
        return Ok(new_response("Username or password incorrect", 401))
    }
    let components = CertificateComponents {
        key,
        user: login.user,
    };
    let signature = components.sign(SIGNING_KEY.get().expect("Failed to get key"));
    let mut response = tide::Response::new(200);
    response.set_body(tide::Body::from_json(&Certificate {
        components,
        signature,
    }).expect("Failed to create response"));
    Ok(response)
}