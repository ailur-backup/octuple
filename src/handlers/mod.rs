use crate::errors::Error;
use crate::settings::{get_bool, get_string};
use axum::http::{StatusCode};
use axum::response::Html;
use axum::routing::get;
use axum::{Json, Router};
use ed25519_dalek::{Signature, VerifyingKey};
use libcharm::request::{Request, Response};
use reqwest::Method;
use serde::Serialize;
use tokio::net::TcpListener;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use log::info;
use signature::Verifier;
use tower::ServiceBuilder;
use crate::handlers::users::OctupleCertificate;

pub mod server;
mod rooms;
mod users;
mod spaces;
mod messages;

trait OctupleRequest {
    async fn verify(&self) -> Result<(), Error>;
}

impl<T: Serialize> OctupleRequest for Request<T> {
    async fn verify(&self) -> Result<(), Error> {
        self.certificate.verify().await?;
        let data = serde_json::to_vec(&self.data)?;
        let key = VerifyingKey::from_bytes(&self.certificate.components.key)?;
        key.verify(data.as_slice(), &Signature::from(self.signature))?;
        Ok(())
    }
}

pub fn new_response<T: Serialize>(data: T, status: u16) -> (StatusCode, Json<Response<T>>) {
    (StatusCode::from_u16(status).unwrap(), Json::from(Response {
        data,
        status,
    }))
}

pub async fn init() {
    info!("Initializing Octuple server");
    let mut app = Router::new()
        .route("/", get(welcome));
    if get_bool("federation.enabled") {
        app = server::init(app);
    }
    app = rooms::init(app);
    app = users::init(app);
    app = messages::init(app);
    app = spaces::init(app);
    info!("All handlers initialized, setting up middleware");
    app = app.layer(
        ServiceBuilder::new()
            .layer(TraceLayer::new_for_http())
            .layer(CorsLayer::new().allow_origin(Any).allow_headers(Any).allow_methods([Method::GET, Method::POST, Method::OPTIONS]))
    );
    info!("Starting server on {}", get_string("core.listener"));
    let listener = TcpListener::bind(get_string("core.listener")).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

pub async fn welcome() -> Html<&'static str> {
    Html(include_str!("welcome.html"))
}
