use std::sync::OnceLock;
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::{pkcs8, SecretKey, SigningKey};
use log;
use rand::rngs::OsRng;
use rand::TryRngCore;

pub static SIGNING_KEY: OnceLock<SigningKey> = OnceLock::new();

pub fn init() {
    let key: SigningKey;
    if std::fs::metadata("octuple.pem").is_ok() {
        key = pkcs8::DecodePrivateKey::read_pkcs8_pem_file("octuple.pem").expect("Failed to read key from file")
    } else {
        log::info!("No key file found, generating new key");
        let mut random_bytes: SecretKey = [0; 32];
        OsRng::default().try_fill_bytes(&mut random_bytes).expect("Failed to fill bytes");
        key = SigningKey::from(random_bytes);
        pkcs8::EncodePrivateKey::write_pkcs8_pem_file(&key, "octuple.pem", LineEnding::LF).expect("Failed to write key to file");
    }

    SIGNING_KEY.set(key).expect("Failed to set signing key");
}
