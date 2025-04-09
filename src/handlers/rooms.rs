use crate::database::get_connection;
use crate::handlers::{new_response, new_response_string, OctupleRequest};
use crate::settings::{get_bool, get_string};
use libcharm::request::{BlankRequest, Request};
use libcharm::room::{Config, Room};
use log::error;

pub fn init(app: &mut tide::Server<()>) {
    app.at("/api/v1/rooms/create").post(create);
    app.at("/api/v1/rooms/delete").post(delete);
    app.at("/api/v1/rooms/list").post(list);
}

pub async fn create(mut req: tide::Request<()>) -> tide::Result {
    let request: Request<Config> = req.body_json().await?;
    let error = request.verify();
    if error.is_err() {
        return Ok(new_response_string(format!("Invalid signature: {}", error.err().unwrap()), 403))
    }
    if request.certificate.components.user.server.domain != get_string("core.domain") && (!get_bool("federation.enabled") || !get_bool("federation.rooms.allow_create")) {
        return Ok(new_response("Federated room creation is disabled", 403))
    }
    let connection = get_connection();
    let result = connection.execute(
        "INSERT INTO rooms (name, federated, encrypted, space) VALUES (?, ?, ?, ?, ?);",
        (request.data.room.name.clone(), request.data.federated, request.data.encrypted, request.data.room.to_string()),
    );
    if result.is_err() {
        let error = result.unwrap_err();
        return if error.sqlite_error_code().expect("Failed to get error code") == rusqlite::ErrorCode::ConstraintViolation {
            Ok(new_response("Room already exists", 409))
        } else {
            error!("Failed to create room: {}", error.to_string());
            Ok(new_response("Failed to create room", 500))
        }
    }
    let result = connection.execute(
        "INSERT INTO members (room, user) VALUES (?, ?);",
        (request.data.room.name, request.certificate.components.user.to_string()),
    );
    if result.is_err() {
        let error = result.unwrap_err();
        error!("Failed to add user to room: {}", error.to_string());
        return Ok(new_response("Failed to add user to room", 500))
    }
    Ok(new_response("Room created", 201))
}

pub async fn delete(mut req: tide::Request<()>) -> tide::Result {
    let request: Request<Room> = req.body_json().await?;
    let error = request.verify();
    if error.is_err() {
        return Ok(new_response_string(format!("Invalid signature: {}", error.err().unwrap()), 403))
    }
    let connection = get_connection();
    let result = connection.execute(
        "DELETE FROM rooms WHERE name = ? AND owner = ?;",
        (request.data.name, request.certificate.components.user.to_string()),
    );
    if result.is_err() {
        let error = result.unwrap_err();
        error!("Failed to delete room: {}", error.to_string());
        return Ok(new_response("Failed to delete room", 500))
    }
    if result? == 0 {
        Ok(new_response("Room not owned or no such room", 403))
    } else {
        Ok(new_response("Room deleted", 200))
    }
}

pub async fn list(mut req: tide::Request<()>) -> tide::Result {
    let request: Request<BlankRequest> = req.body_json().await?;
    let error = request.verify();
    if error.is_err() {
        return Ok(new_response_string(format!("Invalid signature: {}", error.err().unwrap()), 403))
    }
    let connection = get_connection();
    let mut statement = connection.prepare("SELECT room FROM members WHERE user = ?")?;
    let rows = statement.query_map([request.certificate.components.user.to_string()], |row| {
        let row: String = row.get(0)?;
        Ok(Room::from_string(&*row))
    })?;
    let mut rooms = Vec::new();
    for row in rows {
        rooms.push(row.expect("Failed to get row"));
    }
    let mut response = tide::Response::new(200);
    response.set_body(tide::Body::from_json(&rooms)?);
    Ok(response)
}