mod database;
mod handlers;
mod key;
mod settings;

use crate::settings::get_string;
use log::LevelFilter;
use std::str::FromStr;

#[async_std::main]
async fn main() -> tide::Result<()> {
    settings::init();
    tide::log::with_level(LevelFilter::from_str(&*get_string("log.level")).expect("Failed to get log level"));
    key::init();
    database::init();
    handlers::init().await
}
