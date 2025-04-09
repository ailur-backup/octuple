use config::{Config, Value};
use std::sync::OnceLock;

pub static SETTINGS: OnceLock<Config> = OnceLock::new();

pub fn init() {
    SETTINGS.set(Config::builder()
        .add_source(config::File::with_name("octuple"))
        .build()
        .expect("Failed to load configuration"))
        .expect("Failed to set configuration");
}

pub fn get(name: &str) -> Value {
    SETTINGS.get().expect("Failed to get settings").get(name).expect("Failed to get setting")
}

pub fn get_string(name: &str) -> String {
    get(name).into_string().expect("Failed to get string")
}

pub fn get_bool(name: &str) -> bool {
    get(name).into_bool().expect("Failed to get bool")
}