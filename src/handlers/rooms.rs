use crate::database::get_connection;
use crate::handlers::{new_response, OctupleRequest};
use axum::{Json, Router};
use axum::http::StatusCode;
use libcharm::request::{BlankRequest, Request, Response};
use libcharm::room::Room;
use log::info;
use r2d2_sqlite::rusqlite;
use r2d2_sqlite::rusqlite::{Connection, Error};
use r2d2_sqlite::rusqlite::ErrorCode::ConstraintViolation;
use serde_json::{json, Value};

pub trait OctupleRoom {
    // CREATE IS TEMPORARY FOR THE BETA RELEASE; IT WILL BE REMOVED
    fn create(name: String) -> Result<Room, Error>;
    fn load(name: String) -> Result<Room, Error>;
    fn delete(&self, connection: &Connection) -> Result<(), Error>;
}

impl OctupleRoom for Room {
    fn create(name: String) -> Result<Room, Error> {
        let connection = get_connection();
        connection.execute(
            "INSERT INTO rooms (name) VALUES (?)",
            (name.clone(),),
        )?;
        Ok(Room {
            name,
        })
    }

    fn load(name: String) -> Result<Room, Error> {
        Ok(Room {
            name,
        })
    }

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
            "DELETE FROM rooms WHERE name = ?", // AND space = ?",
            (self.name.clone(),) // self.space.to_string()),
        )?;
        Ok(())
    }
}

pub fn init(app: Router) -> Router {
    info!("Initializing rooms handlers");
    app
        .route("/api/v1/rooms/create", axum::routing::post(create))
        .route("/api/v1/rooms/delete", axum::routing::post(delete))
        .route("/api/v1/rooms/get", axum::routing::post(get))
        .route("/api/v1/rooms/list", axum::routing::post(list))
}

pub async fn create(Json(request): Json<Request<String>>) -> (StatusCode, Json<Response<String>>) {
    let error = request.verify().await;
    if error.is_err() {
        return new_response(format!("Invalid signature: {}", error.err().unwrap()), 403)
    }
    let connection = get_connection();
    let result = connection.execute(
        "INSERT INTO rooms (name) VALUES (?);",
        (request.data,),
    );
    if result.is_err() {
        let err = result.err().expect("Failed to get error");
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
    let result = connection.execute(
        "DELETE FROM rooms WHERE name = ?;",
        (request.data.name,),
    );
    if result.is_err() {
        let err = result.err().expect("Failed to get error");
        if err.sqlite_error_code().expect("Failed to get error code") == ConstraintViolation {
            return new_response(String::from("Room not found"), 404)
        } else {
            panic!("Failed to delete room from database: {}", err)
        }
    }
    new_response(String::from("Room deleted"), 200)
}

pub async fn get(Json(request): Json<Request<Room>>) -> (StatusCode, Json<Response<String>>) {
    let error = request.verify().await;
    if error.is_err() {
        return new_response(format!("Invalid signature: {}", error.err().unwrap()), 403)
    }
    let connection = get_connection();
    let result = connection.query_row(
        "SELECT name FROM rooms WHERE name = ?;",
        (request.data.name,),
        |row| -> rusqlite::Result<String> { row.get(0) },
    );
    if result.is_err() {
        let err = result.err().expect("Failed to get error");
        if err == Error::QueryReturnedNoRows {
            return new_response(String::from("Room not found"), 404)
        } else {
            panic!("Failed to get room from database: {}", err)
        }
    }
    new_response(String::from("Room found"), 200)
}

pub async fn list(Json(request): Json<Request<BlankRequest>>) -> (StatusCode, Json<Response<Value>>) {
    let error = request.verify().await;
    if error.is_err() {
        return new_response(Value::from(format!("Invalid signature: {}", error.err().unwrap())), 403)
    }
    let connection = get_connection();
    let mut stmt = connection.prepare("SELECT name FROM rooms;").expect("Failed to prepare statement");
    let room_iter = stmt.query_map([], |row| {
        Ok(Room {
            name: row.get(0)?,
        })
    }).expect("Failed to query rooms");
    let mut rooms = Vec::new();
    for room in room_iter {
        rooms.push(room.expect("Failed to get room"));
    }
    new_response(json!(rooms), 200)
}