use std::str::FromStr;
use tracing_subscriber::filter::LevelFilter;
use crate::settings::get_string;

mod database;
mod handlers;
mod key;
mod settings;
mod errors;

#[tokio::main]
async fn main() {
    settings::init();
    tracing_subscriber::fmt()
        .with_max_level(LevelFilter::from_str(get_string("log.level").as_str()).expect("Failed to parse log level"))
        .init();
    key::init();
    database::init();
    handlers::init().await
}
