use crate::database::get_connection;
use crate::handlers::{new_response, new_response_string, OctupleRequest};
use libcharm::request::{BlankRequest, Request};
use libcharm::room::{Room};
use rusqlite::{Connection, Error};

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

pub fn init(app: &mut tide::Server<()>) {
    app.at("/api/v1/rooms/create").post(create);
    app.at("/api/v1/rooms/delete").post(delete);
    app.at("/api/v1/rooms/get").post(get);
    app.at("/api/v1/rooms/list").post(list);
}

pub async fn create(mut req: tide::Request<()>) -> tide::Result {
    let request: Request<String> = req.body_json().await?;
    let error = request.verify();
    if error.is_err() {
        return Ok(new_response_string(format!("Invalid signature: {}", error.err().unwrap()), 403))
    }
    let connection = get_connection();
    let result = connection.execute(
        "INSERT INTO rooms (name) VALUES (?);",
        (request.data,),
    );
    if result.is_err() {
        let err = result.err().expect("Failed to get error");
        if err.sqlite_error_code().expect("Failed to get error code") == rusqlite::ErrorCode::ConstraintViolation {
            println!("The actual error was: {}", err);
            return Ok(new_response("Room already exists", 409))
        } else {
            panic!("Failed to insert room into database: {}", err)
        }
    }
    Ok(new_response("Room created", 201))
}

pub async fn delete(mut req: tide::Request<()>) -> tide::Result {
    let request: Request<String> = req.body_json().await?;
    let error = request.verify();
    if error.is_err() {
        return Ok(new_response_string(format!("Invalid signature: {}", error.err().unwrap()), 403))
    }
    let connection = get_connection();
    let result = connection.execute(
        "DELETE FROM rooms WHERE name = ?;",
        (request.data,),
    );
    if result.is_err() {
        let err = result.err().expect("Failed to get error");
        if err.sqlite_error_code().expect("Failed to get error code") == rusqlite::ErrorCode::ConstraintViolation {
            return Ok(new_response("Room not found", 404))
        } else {
            panic!("Failed to delete room from database: {}", err)
        }
    }
    Ok(new_response("Room deleted", 200))
}

pub async fn get(mut req: tide::Request<()>) -> tide::Result {
    let request: Request<String> = req.body_json().await?;
    let error = request.verify();
    if error.is_err() {
        return Ok(new_response_string(format!("Invalid signature: {}", error.err().unwrap()), 403))
    }
    let connection = get_connection();
    let result = connection.query_row(
        "SELECT name FROM rooms WHERE name = ?;",
        (request.data,),
        |row| -> rusqlite::Result<String> { row.get(0) },
    );
    if result.is_err() {
        let err = result.err().expect("Failed to get error");
        if err == Error::QueryReturnedNoRows {
            return Ok(new_response("Room not found", 404))
        } else {
            panic!("Failed to get room from database: {}", err)
        }
    }
    Ok(new_response("Room found", 200))
}

pub async fn list(mut req: tide::Request<()>) -> tide::Result {
    let request: Request<BlankRequest> = req.body_json().await?;
    let error = request.verify();
    if error.is_err() {
        return Ok(new_response_string(format!("Invalid signature: {}", error.err().unwrap()), 403))
    }
    let connection = get_connection();
    let mut stmt = connection.prepare("SELECT name FROM rooms;")?;
    let room_iter = stmt.query_map([], |row| {
        Ok(Room {
            name: row.get(0)?,
        })
    })?;
    let mut rooms = Vec::new();
    for room in room_iter {
        rooms.push(room?);
    }
    Ok(new_response_string(serde_json::to_string(&rooms)?, 200))
}