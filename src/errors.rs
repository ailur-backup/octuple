use std::{error, fmt::{self, Display, Formatter}};
use r2d2_sqlite::rusqlite::Error as RusqliteError;
use reqwest::Error as ReqwestError;
use serde_json::Error as SerdeError;
use axum::Error as AxumError;
use ed25519_dalek::ed25519::Error as Ed25519Error;
use url::ParseError as ParseError;

#[derive(Debug, PartialEq)]
pub enum OctupleError {
    UserNotMember,
    FederationDisabled,
}

impl Display for OctupleError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            OctupleError::UserNotMember => write!(f, "user not member of space"),
            OctupleError::FederationDisabled => write!(f, "federation is disabled on this server"),
        }
    }
}

impl error::Error for OctupleError {

}

#[derive(Debug)]
pub enum Error {
    Octuple(OctupleError),
    Sql(RusqliteError),
    Reqwest(ReqwestError),
    Serde(SerdeError),
    Axum(AxumError),
    Ed25519(Ed25519Error),
    Parse(ParseError),
}


impl Error {
    pub fn into_sql(self) -> Option<RusqliteError> {
        match self {
            Error::Sql(e) => Some(e),
            _ => None,
        }
    }

    pub fn as_sql(&self) -> Option<&RusqliteError> {
        match self {
            Error::Sql(e) => Some(e),
            _ => None,
        }
    }

    pub fn as_octuple(&self) -> Option<&OctupleError> {
        match self {
            Error::Octuple(e) => Some(e),
            _ => None,
        }
    }

    pub fn as_reqwest(&self) -> Option<&ReqwestError> {
        match self {
            Error::Reqwest(e) => Some(e),
            _ => None,
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Error::Octuple(e) => write!(f, "octuple error: {}", e),
            Error::Sql(e) => write!(f, "sql error: {}", e),
            Error::Reqwest(e) => write!(f, "reqwest error: {}", e),
            Error::Serde(e) => write!(f, "serde error: {}", e),
            Error::Axum(e) => write!(f, "axum error: {}", e),
            Error::Ed25519(e) => write!(f, "ed25519 error: {}", e),
            Error::Parse(e) => write!(f, "parse error: {}", e),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Error::Octuple(e) => Some(e),
            Error::Sql(e) => Some(e),
            Error::Reqwest(e) => Some(e),
            Error::Serde(e) => Some(e),
            Error::Axum(e) => Some(e),
            Error::Ed25519(e) => Some(e),
            Error::Parse(e) => Some(e),
        }
    }
}

macro_rules! impl_from_methods {
    ($error_name:ident, $error_type:ident) => {
        impl From<$error_type> for Error {
            fn from(e: $error_type) -> Self { Error::$error_name(e) }
        }
    };
}

impl_from_methods!{Octuple, OctupleError}
impl_from_methods!{Sql, RusqliteError}
impl_from_methods!{Reqwest, ReqwestError}
impl_from_methods!{Serde, SerdeError}
impl_from_methods!{Axum, AxumError}
impl_from_methods!{Ed25519, Ed25519Error}
impl_from_methods!{Parse, ParseError}