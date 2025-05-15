/*
use std::collections::{HashMap, HashSet};
use std::iter::Map;
use libcharm::request::{BlankRequest, Request};
use libcharm::room;
use libcharm::room::Room;
use libcharm::server::Server;
use libcharm::space::{Config, Permission, Role, Space, Permission::Delete, OWNER_PERMISSIONS, Member};
use libcharm::user::User;
use log::error;
use rusqlite::ffi::Mem;
use crate::database::get_connection;
use crate::handlers::{new_response, new_response_string, OctupleRequest};
use crate::handlers::rooms::{OctupleRoom};
use crate::settings::{get_bool, get_string};

pub trait OctupleSpaceConfig {
    fn insert(&self, creator: &User, connection: &rusqlite::Connection) -> Result<(), rusqlite::Error>;
    fn update(&self, connection: &rusqlite::Connection) -> Result<(), rusqlite::Error>;
    fn get_permissions(space: Space, role_string: String, connection: &rusqlite::Connection) -> Result<Vec<Permission>, rusqlite::Error>;
    fn get_roles(space: Space, connection: &rusqlite::Connection) -> Result<Vec<Role>, rusqlite::Error>;
    fn get_rooms(space: &Space, connection: &rusqlite::Connection) -> Result<Vec<Room>, rusqlite::Error>;
    fn get_member_roles(space: &Space, roles: HashMap<String, Role>, user: &User, connection: &rusqlite::Connection) -> Result<Vec<Role>, rusqlite::Error>;
    fn get_members(space: &Space, connection: &rusqlite::Connection, roles: HashMap<String, Role>) -> Result<Vec<Member>, rusqlite::Error>;
    fn get(space: &Space, connection: &rusqlite::Connection) -> Result<Config, rusqlite::Error>;
    fn get_roles_hashmap(&self, connection: &rusqlite::Connection) -> Result<HashMap<String, Role>, rusqlite::Error>;
}

impl OctupleSpaceConfig for Config {
    fn insert(&self, creator: &User, connection: &rusqlite::Connection) -> Result<(), rusqlite::Error> {
        connection.execute(
            "INSERT INTO spaces (name, public, hierarchy, default) VALUES (?, ?, ?);",
            (self.space.name.clone(), self.public, self.hierarchy.join(","), self.default.to_string()),
        )?;
        connection.execute(
            "INSERT INTO members (space, user) VALUES (?, ?);",
            (self.space.to_string(), self.space.server.domain.clone()),
        )?;
        for role in [&self.default, &Role {
            space: self.space.clone(),
            name: "Owner".to_string(),
            color: [255, 255, 255],
            display: false,
            permissions: OWNER_PERMISSIONS
        }] {
            connection.execute(
                "INSERT INTO roles (space, name, color, display) VALUES (?, ?, ?, ?);",
                (self.space.to_string(), role.name.clone(), role.color, role.display),
            )?;
            for permission in role.permissions {
                connection.execute(
                    "INSERT INTO space_permissions (space, role, permission) VALUES (?, ?, ?);",
                    (self.space.to_string(), role.to_string(), permission.to_int()),
                )?;
            }
            connection.execute(
                "INSERT INTO member_roles (space, user, role) VALUES (?, ?, ?);",
                (self.space.to_string(), creator.to_string(), role.to_string()),
            )?;
        };
        for room in &self.rooms {
            room.insert(connection)?;
        }
        Ok(())
    }

    fn update(&self, connection: &rusqlite::Connection) -> Result<(), rusqlite::Error> {
        connection.execute(
            "UPDATE spaces SET public = ?, hierarchy = ?, default = ? WHERE name = ?;",
            (self.public, self.hierarchy.join(","), self.default.to_string(), self.space.name.clone()),
        )?;
        for room in &self.rooms {
            room.update(connection)?;
        }
        for role in &self.hierarchy {
            connection.execute(
                "UPDATE roles SET color = ?, display = ? WHERE space = ? AND name = ?;",
                (role.color, role.display, self.space.to_string(), role.name.clone()),
            )?;
            for permission in role.permissions {
                connection.execute(
                    "UPDATE space_permissions SET permission = ? WHERE space = ? AND role = ?;",
                    (permission.to_int(), self.space.to_string(), role.to_string()),
                )?;
            }
        }
        Ok(())
    }

    // Not using the Role struct here to avoid a circular dependency
    fn get_permissions(space: &Space, role_string: String, connection: &rusqlite::Connection) -> Result<Vec<Permission>, rusqlite::Error> {
        let mut stmt = connection.prepare("SELECT permission FROM space_permissions WHERE space = ? AND role = ?")?;
        let mut rows = stmt.query([space.to_string(), role_string])?;
        let mut permissions = Vec::new();
        while let Some(row) = rows.next()? {
            let permission = Permission::from_int(row.get(0)?);
            permissions.push(permission);
        }
        Ok(permissions)
    }

    fn get_roles(space: &Space, connection: &rusqlite::Connection) -> Result<Vec<Role>, rusqlite::Error> {
        let mut stmt = connection.prepare("SELECT name, color, display FROM roles WHERE space = ?")?;
        let mut rows = stmt.query([space.to_string()])?;
        let mut roles = Vec::new();
        while let Some(row) = rows.next()? {
            let role = Role {
                space: space.clone(),
                name: row.get(0)?,
                color: row.get(1)?,
                display: row.get(2)?,
                permissions: Self::get_permissions(
                    space,
                    format!("%{}:{}:{}", row.get(0)?, space.name, space.server.domain),
                    connection,
                )?,
            };
            roles.push(role);
        }
        Ok(roles)
    }

    fn get_rooms(space: &Space, connection: &rusqlite::Connection) -> Result<Vec<Room>, rusqlite::Error> {
        let mut stmt = connection.prepare("SELECT name FROM rooms WHERE space = ?")?;
        let mut rows = stmt.query([space.to_string()])?;
        let mut rooms = Vec::new();
        while let Some(row) = rows.next()? {
            let room = Room::load(row.get(0)?)?;
            rooms.push(room);
        }
        Ok(rooms)
    }

    fn get_member_roles(roles_map: HashMap<String, Role>, space: &Space, user: &User, connection: &rusqlite::Connection) -> Result<Vec<Role>, rusqlite::Error> {
        let mut stmt = connection.prepare("SELECT role FROM member_roles WHERE space = ? AND user = ?")?;
        let mut rows = stmt.query([space.to_string(), user.to_string()])?;
        let mut roles: Vec<Role> = Vec::new();
        while let Some(row) = rows.next()? {
            let role: Role = roles_map.get(row.get(0)?).expect("Failed to get role").to_owned();
            roles.push(role);
        }
        Ok(roles)
    }

    fn get_members(roles: HashMap<String, Role>, space: &Space, connection: &rusqlite::Connection) -> Result<Vec<Member>, rusqlite::Error> {
        let mut stmt = connection.prepare("SELECT user FROM members WHERE space = ?")?;
        let mut rows = stmt.query([space.to_string()])?;
        let mut members: Vec<Member> = Vec::new();
        while let Some(row) = rows.next()? {
            let user = User::from_string(row.get(0)?);
            members.push(Member {
                user: user.clone(),
                roles: Self::get_member_roles(roles.clone(), space, &user, connection)?,
            });
        }
        Ok(members)
    }

    fn get(space: &Space, connection: &rusqlite::Connection) -> Result<Config, rusqlite::Error> {
        let roles = Self::get_roles(space, connection)?;
        let roles: HashMap<String, Role> = roles.iter().map(|role| {
            (role.to_string(), role.clone())
        }).collect();
        let mut stmt = connection.prepare("SELECT public, hierarchy, default FROM spaces WHERE name = ? AND server = ?")?;
        stmt.query_row([space.name.clone(), space.server.domain.clone()], |row| {
            let public: bool = row.get(0)?;
            let hierarchy: String = row.get(1)?;
            let hierarchy: Vec<Role> = hierarchy.split(",").map(|role| {
                roles.get(role).expect("Failed to get role")
            }).collect();
            let default: String = row.get(2)?;
            let default: Role = roles.get(&default).expect("Failed to get default role").to_owned();
            Ok(Config {
                space: space.clone(),
                public,
                hierarchy,
                default,
                rooms: Self::get_rooms(space, connection)?,
                members: Self::get_members(roles, space, connection)?,
            })
        })
    }

    fn get_roles_hashmap(&self, connection: &rusqlite::Connection) -> Result<HashMap<String, Role>, rusqlite::Error> {
        let roles = Self::get_roles(&self.space, connection)?;
        let mut roles_map = HashMap::new();
        for role in roles {
            roles_map.insert(role.to_string(), role);
        }
        Ok(roles_map)
    }
}

trait OctupleSpace {
    fn delete(&self, connection: &rusqlite::Connection) -> Result<(), rusqlite::Error>;
}

impl OctupleSpace for Space {
    fn delete(&self, connection: &rusqlite::Connection) -> Result<(), rusqlite::Error> {
        let mut stmt = connection.prepare("SELECT name FROM rooms WHERE space = ?")?;
        let mut rows = stmt.query([self.to_string()])?;
        for row in rows {
            let room = Room::load(row.get(0)?)?;
            room.delete(&connection)?;
        };
        connection.execute(
            "DELETE FROM spaces WHERE name = ? AND server = ?;",
            (self.name.clone(), self.server.domain.clone()),
        )?;
        connection.execute(
            "DELETE FROM roles WHERE space = ?;",
            (self.to_string(),),
        )?;
        connection.execute(
            "DELETE FROM space_permissions WHERE space = ?;",
            (self.to_string(),),
        )?;
        connection.execute(
            "DELETE FROM members WHERE space = ?;",
            (self.to_string(),),
        )?;
        connection.execute(
            "DELETE FROM member_roles WHERE space = ?;",
            (self.to_string(),),
        )?;
        Ok(())
    }
}

// DISABLED FOR BETA RELEASE, SEE HISTORY.TXT
/*
pub fn init(app: &mut tide::Server<()>) {
    app.at("/api/v1/spaces/create").post(create);
    app.at("/api/v1/spaces/delete").post(delete);
    app.at("/api/v1/spaces/get").post(get);
    app.at("/api/v1/spaces/update").post(update);
    app.at("/api/v1/spaces/join").post(join);
    app.at("/api/v1/spaces/leave").post(leave);
    app.at("/api/v1/spaces/invite").post(invite);
    app.at("/api/v1/spaces/list").post(list);
}
*/

pub async fn create(mut req: tide::Request<()>) -> tide::Result {
    let request: Request<Config> = req.body_json().await?;
    let error = request.verify();
    if error.is_err() {
        return Ok(new_response_string(format!("Invalid signature: {}", error.err().unwrap()), 403))
    }
    if request.certificate.components.user.server.domain != get_string("core.domain") && (!get_bool("federation.enabled") || !get_bool("federation.spaces.allow_create")) {
        return Ok(new_response("Federated space creation is disabled", 403))
    }
    let result = request.data.insert(&request.certificate.components.user, &get_connection());
    if result.is_err() {
        let error = result.unwrap_err();
        if error.sqlite_error_code().expect("Error getting error code") == rusqlite::ErrorCode::ConstraintViolation {
            Ok(new_response("Space already exists", 409))
        } else {
            error!("Failed to create space: {}", error.to_string());
            Ok(new_response("Failed to create space", 500))
        }
    } else {
        Ok(new_response("Space created", 201))
    }
}

pub async fn delete(mut req: tide::Request<()>) -> tide::Result {
    let request: Request<Space> = req.body_json().await?;
    let error = request.verify();
    if error.is_err() {
        return Ok(new_response_string(format!("Invalid signature: {}", error.err().unwrap()), 403))
    }
    let result = request.data.delete(&get_connection());
    if result.is_err() {
        let error = result.unwrap_err();
        if error == rusqlite::Error::QueryReturnedNoRows {
            Ok(new_response("Space not found", 404))
        } else {
            error!("Failed to delete space: {}", error.to_string());
            Ok(new_response("Failed to delete space", 500))
        }
    } else {
        Ok(new_response("Space deleted", 200))
    }
}

pub async fn get(mut req: tide::Request<()>) -> tide::Result {
    let request: Request<Space> = req.body_json().await?;
    let error = request.verify();
    if error.is_err() {
        return Ok(new_response_string(format!("Invalid signature: {}", error.err().unwrap()), 403))
    }
    let connection = get_connection();
    let mut stmt = connection.prepare("SELECT space FROM members WHERE user = ? AND space = ?")?;
    let mut rows = stmt.query([request.certificate.components.user.to_string(), request.data.to_string()])?;
    if rows.next().is_none() {
        return Ok(new_response("Space doesn't exist or not a member", 403))
    }
    let result = Config::get(&request.data, &connection);
    if result.is_err() {
        let error = result.unwrap_err();
        if error == rusqlite::Error::QueryReturnedNoRows {
            Ok(new_response("Space not found", 404))
        } else {
            error!("Failed to get space: {}", error.to_string());
            Ok(new_response("Failed to get space", 500))
        }
    } else {
        let config = result?;
        let mut response = tide::Response::new(200);
        response.set_body(tide::Body::from_json(&config).expect("Failed to create response"));
        Ok(response)
    }
}

pub async fn update(mut req: tide::Request<()>) -> tide::Result {
    let request: Request<Config> = req.body_json().await?;
    let error = request.verify();
    if error.is_err() {
        return Ok(new_response_string(format!("Invalid signature: {}", error.err().unwrap()), 403))
    }
    let connection = get_connection();
    let mut stmt = connection.prepare("SELECT space FROM members WHERE user = ? AND space = ?")?;
    let mut rows = stmt.query([request.certificate.components.user.to_string(), request.data.space.to_string()])?;
    if rows.next().is_none() {
        return Ok(new_response("Space doesn't exist or not a member", 403))
    }
    let result = request.data.update(&connection);
    if result.is_err() {
        let error = result.unwrap_err();
        if error == rusqlite::Error::QueryReturnedNoRows {
            Ok(new_response("Space not found", 404))
        } else {
            error!("Failed to update space: {}", error.to_string());
            Ok(new_response("Failed to update space", 500))
        }
    } else {
        Ok(new_response("Space updated", 200))
    }
}

pub async fn join(mut req: tide::Request<()>) -> tide::Result {
    let request: Request<Space> = req.body_json().await?;
    let error = request.verify();
    if error.is_err() {
        return Ok(new_response_string(format!("Invalid signature: {}", error.err().unwrap()), 403))
    }
    let connection = get_connection();
    let result = connection.execute(
        "INSERT INTO members (space, user) VALUES (?, ?);",
        (request.data.to_string(), request.certificate.components.user.to_string()),
    );
    if result.is_err() {
        let error = result.unwrap_err();
        if error == rusqlite::Error::QueryReturnedNoRows {
            Ok(new_response("Space not found", 404))
        } else {
            error!("Failed to join space: {}", error.to_string());
            Ok(new_response("Failed to join space", 500))
        }
    } else {
        Ok(new_response("Joined space", 200))
    }
}
*/