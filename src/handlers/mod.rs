use crate::settings::{get_bool, get_string};
use libcharm::request::{Request, Response};
use serde::Serialize;
use tide::http::headers::HeaderValue;
use tide::security::Origin;

pub mod server;
mod rooms;
mod users;
mod spaces;
mod messages;

trait OctupleRequest {
    fn verify(&self) -> Result<(), Box<dyn std::error::Error>>;
}

impl<T: Serialize> OctupleRequest for Request<T> {
    fn verify(&self) -> Result<(), Box<dyn std::error::Error>> {
        /*
        self.certificate.verify().map_err(|e|
            Box::new(Error::new(&format!("Failed to verify certificate: {}", e))) as Box<dyn std::error::Error>
        )?;
        let data = rmp_serde::to_vec(&self.data).expect("Failed to serialize data");
        let key = VerifyingKey::from_bytes(&self.certificate.components.key)?;
        key.verify(data.as_slice(), &Signature::from(self.signature)).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
        */
        // Authentication is disabled for the beta release
        Ok(())
    }
}

pub fn new_response<T: Serialize>(data: T, status: u16) -> tide::Response {
    let mut response = tide::Response::new(status);
    response.set_body(tide::Body::from_json(&Response{
        data,
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
    messages::init(&mut app);
    // DISABLED FOR BETA RELEASE, SEE HISTORY.TXT
    // spaces::init(&mut app);
    app.listen(get_string("core.listener")).await?;
    Ok(())
}

pub async fn welcome(_req: tide::Request<()>) -> tide::Result {
    let mut response = tide::Response::new(200);
    response.set_body(tide::Body::from_string(include_str!("welcome.html").parse()?));
    response.set_content_type("text/html");
    Ok(response)
}