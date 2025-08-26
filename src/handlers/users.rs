use crate::errors::Error;
use crate::database::get_connection;
use crate::handlers::{new_response, OctupleRequest};
use crate::handlers::server::OctupleServer;
use crate::key::SIGNING_KEY;
use axum::response::IntoResponse;
use axum::{Json, Router};
use ed25519_dalek::ed25519::SignatureBytes;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use libcharm::endpoints::user::{Create, Login};
use libcharm::request::{BlankRequest, Request, Response};
use libcharm::user::{Certificate, CertificateComponents, User};
use signature::{Signer, Verifier};
use axum::http::StatusCode;
use axum::routing::post;
use libcharm::server::Server;
use log::info;
use r2d2_sqlite::rusqlite::Error::QueryReturnedNoRows;
use r2d2_sqlite::rusqlite::ErrorCode::{self, ConstraintViolation};
use crate::settings::get_string;

pub trait OctupleCertificateComponents {
    fn sign(&self, key: &SigningKey) -> SignatureBytes;
}

impl OctupleCertificateComponents for CertificateComponents {
    fn sign(&self, key: &SigningKey) -> SignatureBytes {
        let bytes = serde_json::to_vec(&self).expect("Failed to serialize components");
        key.sign(&bytes).to_bytes()
    }
}

pub trait OctupleCertificate {
    async fn verify(&self) -> Result<(), Error>;
}

impl OctupleCertificate for Certificate {
    async fn verify(&self) -> Result<(), Error> {
        let bytes = serde_json::to_vec(&self.components)?;
        let key = self.components.user.server.get_server_key().await?;
        key.verify(&bytes, &Signature::from(self.signature))?;
        Ok(())
    }
}

pub fn init(app: Router) -> Router {
    info!("Initializing users handlers");
    app
        .route("/api/v1/users/create", post(create))
        .route("/api/v1/users/delete", post(delete))
        .route("/api/v1/users/login", post(login))
}

pub async fn create(Json(create): Json<Create>) -> (StatusCode, Json<Response<String>>) {
    let connection = get_connection();
    let result = connection.execute(
        "INSERT INTO users (username, key) VALUES (?, ?);",
        (create.user.username, create.key),
    );
    if result.is_err() {
        let err = result.err().expect("Failed to get error");
        if err.sqlite_error_code().expect("Failed to get error code") == ConstraintViolation {
            return new_response(String::from("User already exists"), 409)
        } else {
            panic!("Failed to insert user into database: {}", err)
        }
    }
    new_response(String::from("User created"), 201)
}

pub async fn delete(Json(request): Json<Request<BlankRequest>>) -> (StatusCode, Json<Response<String>>) {
    let error = request.verify().await;
    if error.is_err() {
        return new_response(format!("Invalid signature: {}", error.err().unwrap()), 403)
    }

    let connection = get_connection();
    let result = connection.execute(
        "DELETE FROM users WHERE username = ?;",
        (request.certificate.components.user.username,)
    );
    if result.is_err() {
        let err = result.err().expect("Failed to get error");
        if err.sqlite_error_code().expect("Failed to get error code") == ErrorCode::ConstraintViolation {
            return new_response(String::from("User not found"), 404)
        } else {
            panic!("Failed to delete user from database: {}", err)
        }
    }
    new_response(String::from("User deleted"), 200)
}

pub async fn login(Json(login): Json<Login>) -> axum::response::Response {
    let connection = get_connection();
    let query_result = connection.query_row(
        "SELECT key FROM users WHERE username = ?",
        &[&login.user.username],
        |row| row.get(0)
    );
    if query_result.is_err() {
        let err = query_result.err().expect("Failed to get error");
        if err == QueryReturnedNoRows {
            return new_response("User not found", 404).into_response()
        } else {
            panic!("Failed to get user from database: {}", err)
        }
    }
    let key: [u8; 32] = query_result.expect("Failed to get key");
    let public_key = VerifyingKey::from_bytes(&key).expect("Failed to convert key");
    if public_key.verify(&[login.data], &Signature::from_bytes(&login.signature)).is_err() {
        return new_response("Username or password incorrect", 401).into_response()
    }
    let components = CertificateComponents {
        key,
        user: User {
            username: login.user.username,
            server: Server {
                domain: get_string("core.domain")
            }
        },
    };
    let signature = components.sign(SIGNING_KEY.get().expect("Failed to get key"));
    Json::from(Certificate {
        components,
        signature,
    }).into_response()
}