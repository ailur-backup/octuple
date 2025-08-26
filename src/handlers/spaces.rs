use crate::errors::{Error, OctupleError};
use axum::{Json, Router};
use libcharm::endpoints::space::CreateInvite;
use libcharm::request::{BlankRequest, Request, Response};
use libcharm::room::Room;
use libcharm::space::{Config, Invite, Space};
use libcharm::user::User;
use log::info;
use r2d2_sqlite::rusqlite::{Connection};
use r2d2_sqlite::rusqlite::ErrorCode::ConstraintViolation;
use rand::RngCore;
use reqwest::StatusCode;
use serde_json::{json, Value};
use std::time::{SystemTime, UNIX_EPOCH};
use crate::database::get_connection;
use crate::handlers::{new_response, OctupleRequest};
use crate::handlers::rooms::{OctupleRoom};

pub trait OctupleSpaceConfig {
    fn insert(&self, connection: &Connection) -> Result<(), Error>;
    fn get_rooms(space: &Space, connection: &Connection) -> Result<Vec<Room>, Error>;
    fn get_members(space: &Space, connection: &Connection) -> Result<Vec<User>, Error>;
    fn get(space: &Space, connection: &Connection) -> Result<Config, Error>;
}

impl OctupleSpaceConfig for Config {
    fn insert(&self, connection: &Connection) -> Result<(), Error> {
        connection.execute(
            "INSERT INTO spaces (name) VALUES (?);",
            (self.space.name.clone(),),
        )?;
        connection.execute(
            "INSERT INTO members (space, user) VALUES (?, ?);",
            (self.space.to_string(), self.space.server.domain.clone()),
        )?;
        for room in &self.rooms {
            room.insert(connection)?;
        }
        Ok(())
    }

    fn get_rooms(space: &Space, connection: &Connection) -> Result<Vec<Room>, Error> {
        let mut stmt = connection.prepare("SELECT name FROM rooms WHERE space = ?")?;
        let mut rows = stmt.query([space.to_string()])?;
        let mut rooms = Vec::new();
        while let Some(row) = rows.next()? {
            let room = Room {
                name: row.get(0)?,
                space: space.clone(),
            };
            rooms.push(room);
        }
        Ok(rooms)
    }

    fn get_members(space: &Space, connection: &Connection) -> Result<Vec<User>, Error> {
        let mut stmt = connection.prepare("SELECT user FROM members WHERE space = ?")?;
        let mut rows = stmt.query([space.to_string()])?;
        let mut members: Vec<User> = Vec::new();
        while let Some(row) = rows.next()? {
            members.push(
                User::from(row.get::<usize, String>(0)?.as_str())
            );
        }
        Ok(members)
    }

    fn get(space: &Space, connection: &Connection) -> Result<Config, Error> {
        let image: String = connection.query_row(
            "SELECT image FROM spaces WHERE name = ?", 
            (space.name.as_str(),), 
            |row| Ok(row.get::<usize, String>(0)?)
        )?;
        Ok(Config {
            space: space.clone(),
            rooms: Self::get_rooms(space, connection)?,
            members: Self::get_members(space, connection)?,
            image,
        })
    }
}

pub trait OctupleSpace {
    fn get_config(&self, connection: &Connection) -> Result<Config, Error>;
    fn is_member(&self, user: &User, connection: &Connection) -> Result<(), Error>;
    fn add_member(&self, user: &User, connection: &Connection) -> Result<(), Error>;
    fn remove_member(&self, user: &User, connection: &Connection) -> Result<(), Error>;
    fn delete(&self, connection: &Connection) -> Result<(), Error>;
}

impl OctupleSpace for Space {
    fn get_config(&self, connection: &Connection) -> Result<Config, Error> {
        Config::get(self, connection)
    }

    fn is_member(&self, user: &User, connection: &Connection) -> Result<(), Error> {
        if connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM members WHERE user = ? AND space = ?)",
            (user.to_string(), self.to_string()), 
            |row| row.get::<usize, i64>(0)
        )? == 1 {
            Ok(())
        } else {
            Err(Error::from(OctupleError::UserNotMember))
        }
    }

    fn add_member(&self, user: &User, connection: &Connection) -> Result<(), Error> {
        connection.execute("INSERT INTO members (space, user) VALUES (?, ?)", [self.to_string(), user.to_string()])?;
        Ok(())
    }

    fn remove_member(&self, user: &User, connection: &Connection) -> Result<(), Error> {
        connection.execute("DELETE FROM members WHERE space = ? AND user = ?", [self.to_string(), user.to_string()])?;
        Ok(())
    }

    fn delete(&self, connection: &Connection) -> Result<(), Error> {
        let config = self.get_config(connection)?;
        for room in config.rooms {
            room.delete(connection)?
        }
        connection.execute(
            "DELETE FROM spaces WHERE name = ?",
            (&self.name,),
        )?;
        connection.execute(
            "DELETE FROM members WHERE space = ?",
            (self.to_string(),),
        )?;
        Ok(())
    }
}

pub fn init(app: Router) -> Router {
    info!("Initializing space handlers");
    app
        .route("/api/v1/spaces/create", axum::routing::post(create))
        .route("/api/v1/spaces/delete", axum::routing::post(delete))
        .route("/api/v1/spaces/list", axum::routing::post(list))
        .route("/api/v1/spaces/join", axum::routing::post(join))
        .route("/api/v1/spaces/leave", axum::routing::post(leave))
        .route("/api/v1/spaces/invite", axum::routing::post(invite))
}

pub async fn create(Json(request): Json<Request<Config>>) -> (StatusCode, Json<Response<String>>) {
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
            return new_response(String::from("Space already exists"), 409)
        } else {
            panic!("Failed to insert space into database: {}", err)
        }
    }
    new_response(String::from("Space created"), 201)
}

macro_rules! check_for_member {
    ($space:expr, $user:expr, $response_type:ident, $connection:expr) => {
        let error = $space.is_member(&$user, &$connection);
        if error.is_err() {
            let err = error.err().expect("Failed to get error");
            let octuple_error = err.as_octuple();
            if octuple_error.is_none() {
                let err = err.into_sql().expect("Error is not a SQL error");
                panic!("Failed to check members in database: {}", err)
            } else {
                if *octuple_error.unwrap() == OctupleError::UserNotMember {
                    return new_response($response_type::from("User is not a member of the space"), 403)
                } else {
                    panic!("Failed to check members: {}", err)
                }
            }
        }
    };
}

pub async fn delete(Json(request): Json<Request<Space>>) -> (StatusCode, Json<Response<String>>) {
    let error = request.verify().await;
    if error.is_err() {
        return new_response(format!("Invalid signature: {}", error.err().unwrap()), 403)
    }

    let connection = get_connection();
    check_for_member!(request.data, request.certificate.components.user, String, connection);

    let result = request.data.delete(&connection);
    if result.is_err() {
        let err = result.err().expect("Failed to get error").into_sql().expect("Error is not a SQL error");
        panic!("Failed to remove user from database: {}", err)
    }
    
    new_response(String::from("Deleted sucessfully"), 200)
}

pub async fn list(Json(request): Json<Request<BlankRequest>>) -> (StatusCode, Json<Response<Value>>) {
    let error = request.verify().await;
    if error.is_err() {
        return new_response(Value::from(format!("Invalid signature: {}", error.err().unwrap())), 403)
    }

    let connection: r2d2::PooledConnection<r2d2_sqlite::SqliteConnectionManager> = get_connection();
    let mut stmt = connection.prepare("SELECT space FROM members WHERE user = ?").expect("Failed to prepare statement");
    let mut rows = stmt.query([request.certificate.components.user.to_string()]).expect("Failed to fetch rows");
    let mut spaces: Vec<Space> = Vec::new();
    while let Some(row) = rows.next().expect("Failed to go to select next row") {
        let space = Space::from(row.get::<usize, String>(0).expect("Failed to fetch item from row").as_str());
        spaces.push(space);
    }

    new_response(json!(spaces), 200)
}

pub async fn join(Json(request): Json<Request<Invite>>) -> (StatusCode, Json<Response<Value>>) {
    let error = request.verify().await;
    if error.is_err() {
        return new_response(Value::from(format!("Invalid signature: {}", error.err().unwrap())), 403)
    }

    let connection: r2d2::PooledConnection<r2d2_sqlite::SqliteConnectionManager> = get_connection();
    let result = connection.query_row(
    "SELECT expiry, space FROM invites WHERE code = ?",
        (request.data,), 
        |row| {
            Ok((
                row.get::<usize, u64>(0)?,
                row.get::<usize, String>(1)?
            ))
        }
    );
    if result.is_err() {
        panic!("Failed to check invite in database: {}", result.err().unwrap())
    }

    let values = result.unwrap();

    let unix_time = SystemTime::now().duration_since(UNIX_EPOCH).expect("Failed to get UNIX time").as_secs();
    if values.0 < unix_time {
        return new_response(Value::from("Invite expired"), 403)
    }

    let space: Space = Space::from(values.1.as_str());
    let result = space.add_member(&request.certificate.components.user, &connection);
    if result.is_err() {
        let err = result.err().expect("Failed to get error").into_sql().expect("Error is not a SQL error");
        if err.sqlite_error_code().expect("Failed to get error code") == ConstraintViolation {
            println!("The actual error was: {}", err);
            return new_response(Value::from("Member already present"), 409)
        } else {
            panic!("Failed to add member to space: {}", err)
        }
    }

    new_response(json!(space), 200)
}

pub async fn leave(Json(request): Json<Request<Space>>) -> (StatusCode, Json<Response<String>>) {
    let error = request.verify().await;
    if error.is_err() {
        return new_response(format!("Invalid signature: {}", error.err().unwrap()), 403)
    }

    let connection: r2d2::PooledConnection<r2d2_sqlite::SqliteConnectionManager> = get_connection();
    check_for_member!(request.data, request.certificate.components.user, String, connection);
    let result = request.data.remove_member(&request.certificate.components.user, &connection);
    if result.is_err() {
        let err = result.err().expect("Failed to get error").into_sql().expect("Error is not a SQL error");
        panic!("Failed to remove user from database: {}", err)
    }

    new_response(String::from("Left sucessfully"), 200)
}

pub async fn invite(Json(request): Json<Request<CreateInvite>>) -> (StatusCode, Json<Response<Value>>) {
    let error = request.verify().await;
    if error.is_err() {
        return new_response(Value::from(format!("Invalid signature: {}", error.err().unwrap())), 403)
    }

    let connection: r2d2::PooledConnection<r2d2_sqlite::SqliteConnectionManager> = get_connection();
    check_for_member!(request.data.space, request.certificate.components.user, Value, connection);

    let mut invite: Invite = [0u8; 8];
    rand::rng().fill_bytes(&mut invite);

    let result = connection.execute(
        "INSERT INTO invites (creator, space, expiry, code) VALUES (?, ?, ?, ?)",
        (
            request.certificate.components.user.to_string(),
            request.data.space.to_string(),
            request.data.expiry_time,
            invite
        )
    );
    if result.is_err() {
        let err = result.err().expect("Failed to get error");
        if err.sqlite_error_code().expect("Failed to get error code") == ConstraintViolation {
            println!("The actual error was: {}", err);
            return new_response(Value::from("Invite already exists"), 409)
        } else {
            panic!("Failed to insert invite into database: {}", err)
        }       
    }

    new_response(json!(invite), 200)
}