use crate::database::get_connection;
use crate::handlers::OctupleRequest;
use crate::handlers::{new_response, new_response_string};
use libcharm::message::Message;
use libcharm::request::Request;
use libcharm::room::Room;
use uuid::Uuid;
use libcharm::user::User;
use rusqlite::fallible_iterator::FallibleIterator;

pub async fn list(mut req: tide::Request<()>) -> tide::Result {
    let request: Request<Room> = req.body_json().await?;
    let error = request.verify();
    if error.is_err() {
        return Ok(new_response("Invalid request", 400));
    }
    let connection = get_connection();
    let mut statement = connection.prepare("SELECT content, id, sender FROM messages WHERE room = ?;")?;
    let message_iter = statement.query_map([request.data.name.clone()], |row| {
        Ok(Message {
            room: request.data.clone(),
            content: row.get(0)?,
            id: Uuid::from_slice(&*row.get::<_, Vec<u8>>(1)?).unwrap(),
            sender: User::from_string(&*row.get::<_, String>(2)?),
        })
    })?;
    Ok(new_response_string(
        serde_json::to_string(&message_iter.collect::<Result<Vec<_>, rusqlite::Error>>()?)?,
        200,
    ))
}

pub async fn send(mut req: tide::Request<()>) -> tide::Result {
    let request: Request<Message> = req.body_json().await?;
    let error = request.verify();
    if error.is_err() {
        return Ok(new_response("Invalid request", 400));
    }
    let connection = get_connection();
    let result = connection.execute(
        "INSERT INTO messages (id, content, room, sender) VALUES (?, ?, ?, ?);",
        (
            uuid::Uuid::new_v4().as_bytes(),
            request.data.content,
            request.data.room.name.clone(),
            request.data.sender.to_string(),
        ),
    );
    if result.is_err() {
        let err = result.err().expect("Failed to get error");
        if err.sqlite_error_code().expect("Failed to get error code") == rusqlite::ErrorCode::ConstraintViolation {
            return Ok(new_response("Message already exists", 409));
        } else {
            panic!("Failed to insert message into database: {}", err);
        }
    }
    Ok(new_response("Message sent", 201))
}

pub fn init(app: &mut tide::Server<()>) {
    app.at("/api/v1/message/list").post(list);
    app.at("/api/v1/message/send").post(send);
}