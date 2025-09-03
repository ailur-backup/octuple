use crate::database::get_connection;
use crate::handlers::new_response;
use crate::key::SIGNING_KEY;
use crate::settings::{get_bool, get_string};
use axum::{Json, Router};
use crate::errors::{Error, OctupleError};
use ed25519_dalek::VerifyingKey;
use libcharm::request::Response;
use libcharm::server::{Key, Ping, Server};
use std::time::{SystemTime, UNIX_EPOCH};
use axum::http::StatusCode;
use log::{debug, info, trace};
use r2d2_sqlite::rusqlite;
use reqwest::Url;

//noinspection HttpUrlsUsage
fn compare_domains(domain1: &str, domain2: &str) -> bool {
    if domain1.contains("://") && !domain2.contains("://") {
        if strip_scheme(domain1) == domain2 {
            true
        } else {
            false
        }
    } else if !domain1.contains("://") && domain2.contains("://") {
        if strip_scheme(domain2) == domain1 {
            true
        } else {
            false
        }
    } else {
        domain1 == domain2
    }
}

fn strip_scheme(url: &str) -> String {
    url.split("://")
        .nth(1)
        .map_or_else(|| url.to_string(), |s| s.to_string())
}

pub trait OctupleServer {
    async fn tls_supported(&self) -> Result<bool, Error>;
    async fn ping(&self, https: bool) -> Result<(), Error>;
    async fn fetch_and_save_remote_key(&self) -> Result<[u8; 32], Error>;
    async fn fetch_remote_key(&self) -> Result<[u8; 32], Error>;
    async fn get_server_key(&self) -> Result<VerifyingKey, Error>;
    async fn get_absolute_domain(&self) -> Result<Url, Error>;
    fn fetch_local_key(&self) -> Result<[u8; 32], Error>;
}

impl OctupleServer for Server {
    async fn tls_supported(&self) -> Result<bool, Error> {
        let https_ping = self.ping(true).await;
        if https_ping.is_ok() {
            Ok(true)
        } else {
            if get_bool("federation.allow_http") {
                let http_ping = self.ping(false).await;
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

    async fn ping(&self, https: bool) -> Result<(), Error> {
        let scheme = if https { "https" } else { "http" };
        let url = format!("{scheme}://{}/api/v1/server/ping", self.domain);
        let url = Url::parse(url.as_str())?;
        let client = reqwest::Client::new();
        let response = client.get(url).send().await?;
        response.error_for_status_ref()?;
        Ok(())
    }

    async fn fetch_and_save_remote_key(&self) -> Result<[u8; 32], Error> {
        let key = self.fetch_remote_key().await?;
        let conn = get_connection();
        conn.execute(
            "INSERT INTO keys (domain, key) VALUES (?, ?)",
            (self.domain.as_str(), key),
        )?;
        Ok(key)
    }

    async fn fetch_remote_key(&self) -> Result<[u8; 32], Error> {
        let client = reqwest::Client::new();
        let response = client.get(self.get_absolute_domain().await?.join("api/v1/server/key")?)
            .send()
            .await?;
        response.error_for_status_ref()?;
        let remote_key: Key = response.json().await?;
        Ok(remote_key.data)
    }

    async fn get_server_key(&self) -> Result<VerifyingKey, Error> {
        trace!("Comparing domains: {} and {}", self.domain, get_string("core.domain"));
        if !compare_domains(&self.domain, &get_string("core.domain")) {
            trace!("Using remote signing key for domain: {}", self.domain);
            debug!("Fetching remote key for domain: {}", self.domain);
            if get_bool("federation.enabled") {
                let key = self.fetch_local_key();
                if key.is_err() {
                    let err = key.err().expect("Failed to get error");
                    let sql_error = err.as_sql().expect("Error is not a SQL error");
                    if *sql_error == rusqlite::Error::QueryReturnedNoRows {
                        let key = self.fetch_and_save_remote_key().await?;
                        let key = VerifyingKey::from_bytes(&key)?;
                        Ok(key)
                    } else {
                        Err(err)
                    }
                } else {
                    let key = key?;
                    let key = VerifyingKey::from_bytes(&key)?;
                    Ok(key)
                }
            } else {
                Err(Error::from(OctupleError::FederationDisabled))
            }
        } else {
            trace!("Using local signing key for domain: {}", self.domain);
            Ok(SIGNING_KEY.get().expect("Failed to get signing key").verifying_key())
        }
    }

    //noinspection HttpUrlsUsage
    async fn get_absolute_domain(&self) -> Result<Url, Error> {
        if self.domain.contains("://") {
            Url::parse(self.domain.as_str()).map_err(|e| {
                Error::from(e)
            })
        } else {
            if self.tls_supported().await? {
                Url::parse(format!("https://{}", self.domain).as_str()).map_err(|e| {
                    Error::from(e)
                })
            } else {
                Url::parse(format!("http://{}", self.domain).as_str()).map_err(|e| {
                    Error::from(e)
                })
            }
        }
    }

    fn fetch_local_key(&self) -> Result<[u8; 32], Error> {
        let conn = get_connection();
        conn.query_row(
            "SELECT key FROM keys WHERE domain = ?",
            [self.domain.as_str()],
            |row| row.get(0),
        ).map_err(|e| {
            Error::from(e)
        })
    }
}

pub async fn push(Json(server): Json<Server>) -> (StatusCode, Json<Response<String>>) {
    let result = server.fetch_and_save_remote_key().await;
    if result.is_err() {
        let err = result.err().expect("Failed to get error");
        return if err.as_reqwest().is_some() {
            new_response(String::from("Failed to fetch remote key"), 500)
        } else {
            new_response(String::from("Failed to save remote key"), 500)
        }
    }
    new_response(String::from("Key pushed"), 200)
}

pub fn init(app: Router) -> Router {
    info!("Initializing server handlers");
    app
        .route("/api/v1/server/push", axum::routing::post(push))
        .route("/api/v1/server/key", axum::routing::get(key))
        .route("/api/v1/server/ping", axum::routing::get(ping))
}

pub async fn key() -> Json<Key> {
    Json::from(Key {
        data: *SIGNING_KEY.get().expect("Failed to get signing key").verifying_key().as_bytes(),
    })
}

pub async fn ping() -> Json<Ping> {
    Json::from(Ping {
        timestamp: SystemTime::now().duration_since(UNIX_EPOCH).expect("Failed to get time").as_secs(),
    })
}
