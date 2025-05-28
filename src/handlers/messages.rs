use std::collections::HashMap;
use std::sync::{RwLock};
use std::time::Duration;
use axum::{Json, Router, debug_handler};
use axum::extract::ws;
use axum::extract::ws::Message::Pong;
use axum::extract::ws::{Utf8Bytes, WebSocketUpgrade};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{any, post};
use crate::database::get_connection;
use crate::handlers::OctupleRequest;
use crate::handlers::{new_response};
use libcharm::message::{Message, Uuid};
use libcharm::request::{Request, Response};
use libcharm::room::Room;
use libcharm::user::User;
use log::{debug, info, trace};
use serde_json::{json, Value};
use tokio::select;
use tokio::sync::broadcast::{Sender};
use bytes::Bytes;
use lazy_static::lazy_static;
use r2d2_sqlite::rusqlite;
use r2d2_sqlite::rusqlite::ErrorCode::ConstraintViolation;
use tokio::time::sleep;

lazy_static! {
    static ref ROOM_CHANNELS: RwLock<HashMap<Room, Sender<Message>>> = RwLock::new(HashMap::new());
}

pub async fn list(Json(request): Json<Request<Room>>) -> (StatusCode, Json<Response<Value>>) {
    let error = request.verify().await;
    if error.is_err() {
        return new_response(Value::from("Invalid request"), 400);
    }
    let connection = get_connection();
    let mut statement = connection.prepare("SELECT content, id, sender FROM messages WHERE room = ?;").expect("Failed to prepare statement");
    let message_iter = statement.query_map([request.data.name.clone()], |row| {
        Ok(Message {
            room: request.data.clone(),
            content: row.get(0)?,
            id: Some(Uuid::from_slice(&*row.get::<_, Vec<u8>>(1)?).unwrap()),
            sender: Some(User::from_string(&*row.get::<_, String>(2)?)),
        })
    }).expect("Failed to query messages");
    let map = message_iter.collect::<Result<Vec<_>, rusqlite::Error>>().expect("Failed to collect messages");
    new_response(
        json!(map),
        200,
    )
}

#[debug_handler]
pub async fn send(Json(request): Json<Request<Message>>) -> (StatusCode, Json<Response<String>>) {
    let error = request.verify().await;
    if error.is_err() {
        return new_response(String::from("Invalid request"), 400);
    }
    let connection = get_connection();
    let id = Uuid::new_v4();
    let result = connection.execute(
        "INSERT INTO messages (id, content, room, sender) VALUES (?, ?, ?, ?);",
        (
            id.as_bytes(),
            request.data.content.clone(),
            request.data.room.name.clone(),
            &request.certificate.components.user.to_string(),
        ),
    );
    if result.is_err() {
        let err = result.err().expect("Failed to get error");
        if err.sqlite_error_code().expect("Failed to get error code") == ConstraintViolation {
            return new_response(String::from("Message already exists"), 409);
        } else {
            panic!("Failed to insert message into database: {}", err);
        }
    }
    if let Some(sender) = ROOM_CHANNELS.read().expect("Failed to get ROOM_CHANNELS").get(&request.data.room) {
        sender.send(Message {
            room: request.data.room.clone(),
            content: request.data.content.clone(),
            id: Some(id),
            sender: Some(request.certificate.components.user.clone()),
        }).expect("Failed to send message to room channel");
    } else {
        debug!("No channel found for room {}", request.data.room.name);
    }
    new_response(String::from("Message sent"), 201)
}

#[debug_handler]
pub async fn listen(ws: WebSocketUpgrade) -> impl IntoResponse {
    ws.on_upgrade(|mut socket| async move {
        let request: Request<Room>;
        select! {
            message = socket.recv() => {
                match message {
                    Some(Ok(ws::Message::Text(text))) => {
                        trace!("Received WebSocket message: {}", text);
                        let result = serde_json::from_str(&text);
                        if result.is_err() {
                            socket.send(ws::Message::Close(Some(ws::CloseFrame {
                                code: ws::CloseCode::from(StatusCode::BAD_REQUEST),
                                reason: Utf8Bytes::from("Invalid request format"),
                            }))).await.expect("Failed to send close message");
                            trace!("Invalid request format: {}", result.err().unwrap());
                            return;
                        } else {
                            request = result.unwrap();
                        }
                    },
                    Some(Ok(ws::Message::Close(_))) => {
                        debug!("WebSocket connection closed by client");
                        return;
                    },
                    Some(Err(e)) => {
                        debug!("Error receiving WebSocket message: {}", e);
                        return;
                    },
                    None => {
                        debug!("WebSocket connection closed unexpectedly");
                        return;
                    },
                    _ => {
                        debug!("Received unsupported WebSocket message type");
                        return;
                    }
                }
            },
            _ = sleep(Duration::from_secs(20)) => {
                socket.send(ws::Message::Close(None)).await.expect("Failed to send close message");
                return;
            },
        }
        let error = request.verify().await;
        if error.is_err() {
            return;
        }
        if !ROOM_CHANNELS.read().expect("Failed to get ROOM_CHANNELS").contains_key(&request.data) {
            ROOM_CHANNELS.write().expect("Failed to get ROOM_CHANNELS").insert(
                request.data.clone(),
                tokio::sync::broadcast::channel(100).0,
            );
        }
        let mut receiver = ROOM_CHANNELS.read().expect("Failed to get ROOM_CHANNELS").get(&request.data).unwrap().subscribe();
        loop {
            select! {
                message = receiver.recv() => {
                    debug!("Broadcasting message to room {}", request.data.name);
                    socket.send(
                        ws::Message::Text(Utf8Bytes::from(
                            serde_json::to_string(
                                &message.expect("Failed to get message")
                            ).expect("Failed to serialize message")
                        ))
                    ).await.expect("Failed to send message");
                },
                result = socket.recv() => {
                    match result {
                        Some(Ok(ws::Message::Close(_))) => {
                            debug!("WebSocket connection closed for room {}", request.data.name);
                            return;
                        }
                        Some(Ok(ws::Message::Ping(_))) => {
                            socket.send(Pong(Bytes::from("pong"))).await.expect("Failed to send pong");
                        }
                        None => {
                            debug!("WebSocket connection closed unexpectedly for room {}", request.data.name);
                            return;
                        }
                        Some(Err(e)) => {
                            debug!("Error receiving WebSocket message: {}", e);
                            return;
                        }
                        _ => {}
                    }
                },
            }
        }
    })
}

pub fn init(app: Router) -> Router {
    info!("Initializing messages handlers");
    app
        .route("/api/v1/messages/list", post(list))
        .route("/api/v1/messages/send", post(send))
        .route("/api/v1/messages/listen", any(listen))
}