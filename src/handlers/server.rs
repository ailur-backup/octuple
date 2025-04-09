use crate::database::get_connection;
use crate::handlers::new_response;
use crate::key::SIGNING_KEY;
use crate::settings::{get_bool, get_string};
use ed25519_dalek::VerifyingKey;
use libcharm::server::{Key, Ping, Server};
use std::time::{SystemTime, UNIX_EPOCH};
use libcharm::error::Error;
use tide::{Body, Request};

pub fn init(app: &mut tide::Server<()>) {
    app.at("/api/v1/server/push").post(push);
    app.at("/api/v1/server/key").get(key);
    app.at("/api/v1/server/ping").get(ping);
}

pub trait OctupleServer {
    fn tls_supported(&self) -> Result<bool, reqwest::Error>;
    fn ping(&self, https: bool) -> Result<(), reqwest::Error>;
    fn fetch_and_save_remote_key(&self) -> Result<[u8; 32], Box<dyn std::error::Error>>;
    fn fetch_remote_key(&self) -> Result<[u8; 32], reqwest::Error>;
    fn fetch_local_key(&self) -> Result<[u8; 32], rusqlite::Error>;
    fn get_server_key(&self) -> Result<VerifyingKey, Box<dyn std::error::Error>>;
}

impl OctupleServer for Server {
    fn tls_supported(&self) -> Result<bool, reqwest::Error> {
        let https_ping = self.ping(true);
        if https_ping.is_ok() {
            Ok(true)
        } else {
            if get_bool("federation.allow_http") {
                let http_ping = self.ping(false);
                if http_ping.is_ok() {
                    Ok(false)
                } else {
                    Err(http_ping.err().expect("Failed to get error"))
                }
            } else {
                Err(https_ping.err().expect("Failed to get error"))
            }
        }
    }

    fn ping(&self, https: bool) -> Result<(), reqwest::Error> {
        let scheme = if https { "https" } else { "http" };
        let url = format!("{scheme}://{}/api/v1/server/ping", self.domain);
        let url = url.parse::<reqwest::Url>().expect(format!("Failed to parse URL: {}", url).as_str());
        let client = reqwest::blocking::Client::new();
        let response = client.get(url).send()?;
        response.error_for_status_ref()?;
        Ok(())
    }

    fn fetch_and_save_remote_key(&self) -> Result<[u8; 32], Box<dyn std::error::Error>> {
        let key = self.fetch_remote_key()?;
        let conn = get_connection();
        conn.execute(
            "INSERT INTO keys (domain, key) VALUES (?, ?)",
            (self.domain.clone(), key),
        )?;
        Ok(key)
    }

    fn fetch_remote_key(&self) -> Result<[u8; 32], reqwest::Error> {
        let scheme = if self.tls_supported()? { "https" } else { "http" };
        let url = format!("{scheme}://{}/api/v1/server/key", self.domain);
        let url = url.parse::<reqwest::Url>().expect(format!("Failed to parse URL: {}", url).as_str());
        let client = reqwest::blocking::Client::new();
        let response = client.get(url).send()?;
        response.error_for_status_ref()?;
        let remote_key: Key = response.json()?;
        Ok(remote_key.data)
    }

    fn fetch_local_key(&self) -> Result<[u8; 32], rusqlite::Error> {
        let conn = get_connection();
        conn.query_row(
            "SELECT key FROM keys WHERE domain = ?",
            [self.domain.clone()],
            |row| row.get(0),
        )
    }

    fn get_server_key(&self) -> Result<VerifyingKey, Box<dyn std::error::Error>> {
        if self.domain != get_string("core.domain") {
            if get_bool("federation.enabled") {
                let key = self.fetch_local_key();
                if key.is_err() {
                    let err = key.err().expect("Failed to get error");
                    if err == rusqlite::Error::QueryReturnedNoRows {
                        let key = self.fetch_and_save_remote_key()?;
                        let key = VerifyingKey::from_bytes(&key)?;
                        Ok(key)
                    } else {
                        Err(Box::new(err))
                    }
                } else {
                    let key = key?;
                    let key = VerifyingKey::from_bytes(&key)?;
                    Ok(key)
                }
            } else {
                Err(Box::new(Error::new("Federation is disabled")))
            }
        } else {
            Ok(SIGNING_KEY.get().expect("Failed to get signing key").verifying_key())
        }
    }
}

pub async fn push(mut req: Request<()>) -> tide::Result {
    let server: Server = req.body_json().await?;
    let result = server.fetch_and_save_remote_key();
    if result.is_err() {
        let err = result.err().expect("Failed to get error");
        return if err.downcast_ref::<reqwest::Error>().is_some() {
            Ok(new_response("Failed to fetch remote key", 500))
        } else {
            Ok(new_response("Failed to save remote key", 500))
        }
    }
    Ok(new_response("Key pushed", 200))
}

pub async fn key(_req: Request<()>) -> tide::Result {
    let mut response = tide::Response::new(200);
    response.set_body(Body::from_json(&Key {
        data: *SIGNING_KEY.get().expect("Failed to get signing key").verifying_key().as_bytes(),
    })?);
    Ok(response)
}


pub async fn ping(_req: Request<()>) -> tide::Result {
    let mut response = tide::Response::new(200);
    response.set_body(Body::from_json(&Ping {
        timestamp: SystemTime::now().duration_since(UNIX_EPOCH).expect("Failed to get time").as_secs(),
    })?);
    Ok(response)
}
