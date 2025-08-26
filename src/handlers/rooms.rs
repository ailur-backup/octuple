use crate::database::get_connection;
use crate::errors::Error;
use crate::handlers::spaces::OctupleSpace;
use crate::handlers::{new_response, OctupleRequest};
use axum::{Json, Router};
use axum::http::StatusCode;
use libcharm::request::{Request, Response};
use libcharm::room::{Room};
use libcharm::space::Space;
use log::info;
use r2d2_sqlite::rusqlite::{Connection};
use r2d2_sqlite::rusqlite::ErrorCode::ConstraintViolation;
use serde_json::{json, Value};

pub trait OctupleRoom {
    fn delete(&self, connection: &Connection) -> Result<(), Error>;
    fn insert(&self, connection: &Connection) -> Result<(), Error>;
}

impl OctupleRoom for Room {
    fn delete(&self, connection: &Connection) -> Result<(), Error> {
        connection.execute(
            "DELETE FROM messages WHERE room = ?",
            (self.to_string(),),
        )?;
        /*
        connection.execute(
            "DELETE FROM room_permissions WHERE room = ?",
            (self.to_string(),),
        )?;
        */
        connection.execute(
            "DELETE FROM rooms WHERE name = ? AND space = ?",
            (self.name.clone(), self.space.to_string()),
        )?;
        Ok(())
    }

    fn insert(&self, connection: &Connection) -> Result<(), Error> {
        connection.execute(
            "INSERT INTO rooms (name, space) VALUES (?, ?)",
            (self.name.clone(), self.space.to_string()),
        )?;

        Ok(())
    }
}

pub fn init(app: Router) -> Router {
    info!("Initializing rooms handlers");
    app
        .route("/api/v1/rooms/create", axum::routing::post(create))
        .route("/api/v1/rooms/delete", axum::routing::post(delete))
        .route("/api/v1/rooms/list", axum::routing::post(list))
}

pub async fn create(Json(request): Json<Request<Room>>) -> (StatusCode, Json<Response<String>>) {
    let error = request.verify().await;
    if error.is_err() {
        return new_response(format!("Invalid signature: {}", error.err().unwrap()), 403)
    }
    let connection = get_connection();
    let result = request.data.insert(&connection);
    if result.is_err() {
        let err = result.err().expect("Failed to get error").into_sql().expect("Error is not a SQL error");
        if err.sqlite_error_code().expect("Failed to get error code") == ConstraintViolation {
            println!("The actual error was: {}", err);
            return new_response(String::from("Room already exists"), 409)
        } else {
            panic!("Failed to insert room into database: {}", err)
        }
    }
    new_response(String::from("Room created"), 201)
}

pub async fn delete(Json(request): Json<Request<Room>>) -> (StatusCode, Json<Response<String>>) {
    let error = request.verify().await;
    if error.is_err() {
        return new_response(format!("Invalid signature: {}", error.err().unwrap()), 403)
    }
    let connection = get_connection();
    let result = request.data.delete(&connection);
    if result.is_err() {
        let err = result.err().expect("Failed to get error");
        panic!("Failed to delete room from database: {}", err)
    }
    new_response(String::from("Room deleted"), 200)
}

pub async fn list(Json(request): Json<Request<Space>>) -> (StatusCode, Json<Response<Value>>) {
    let error = request.verify().await;
    if error.is_err() {
        return new_response(Value::from(format!("Invalid signature: {}", error.err().unwrap())), 403)
    }
    let connection = get_connection();
    let result = request.data.get_config(&connection);
    if result.is_err() {
        let err = result.err().expect("Failed to get error");
        panic!("Failed to get space configuration from database: {}", err)
    }
    new_response(json!(result.unwrap().rooms), 200)
}