use crate::handlers::users::OctupleCertificate;
use crate::settings::{get_bool, get_string};
use ed25519_dalek::{Signature, VerifyingKey};
use libcharm::error::Error;
use libcharm::request::{Request, Response};
use serde::Serialize;
use signature::Verifier;
use tide::http::headers::HeaderValue;
use tide::security::Origin;

pub mod server;
mod rooms;
mod users;
mod spaces;

trait OctupleRequest {
    fn verify(&self) -> Result<(), Box<dyn std::error::Error>>;
}

impl<T: Serialize> OctupleRequest for Request<T> {
    fn verify(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.certificate.verify().map_err(|e|
            Box::new(Error::new(&format!("Failed to verify certificate: {}", e))) as Box<dyn std::error::Error>
        )?;
        let data = rmp_serde::to_vec(&self.data).expect("Failed to serialize data");
        let key = VerifyingKey::from_bytes(&self.certificate.components.key)?;
        key.verify(data.as_slice(), &Signature::from(self.signature)).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
    }
}

pub fn new_response(message: &str, status: u16) -> tide::Response {
    new_response_string(message.to_string(), status)
}

pub fn new_response_string(message: String, status: u16) -> tide::Response {
    let mut response = tide::Response::new(status);
    response.set_body(tide::Body::from_json(&Response {
        message,
        status,
    }).expect("Failed to create response"));
    response
}

pub async fn init() -> tide::Result<()> {
    let mut app = tide::new();
    // Add CORS headers
    app.with(tide::security::CorsMiddleware::new()
        .allow_methods("GET, POST, OPTIONS".parse::<HeaderValue>()?)
        .allow_origin(Origin::from("*"))
        .allow_credentials(false));
    app.at("/").get(welcome);
    if get_bool("federation.enabled") {
        server::init(&mut app);
    }
    rooms::init(&mut app);
    users::init(&mut app);
    app.listen(get_string("core.listener")).await?;
    Ok(())
}

pub async fn welcome(_req: tide::Request<()>) -> tide::Result {
    let mut response = tide::Response::new(200);
    response.set_body(tide::Body::from_string(include_str!("welcome.html").parse()?));
    response.set_content_type("text/html");
    Ok(response)
}