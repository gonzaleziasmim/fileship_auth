use bcrypt::{hash, verify};
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, Header, EncodingKey};
use serde::Serialize;
use std::env;

#[derive(Debug, Serialize)]
struct Claims {
    sub: String,
    exp: usize,
}

// Hash the password using bcrypt
pub async fn hash_password(password: &str) -> Result<String, bcrypt::BcryptError> {
    let hashed = hash(password, 12)?;
    Ok(hashed)
}

// Verify the password using bcrypt
pub async fn verify_password(password: &str, hashed: &str) -> Result<bool, bcrypt::BcryptError> {
    verify(password, hashed)
}

// Generate a JWT for the user
pub async fn generate_jwt(email: &str) -> String {
    let secret_key = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    let expiration_in_days = 7;
    let expiration_time = Utc::now() + Duration::days(expiration_in_days);

    let claims = Claims {
        sub: email.to_string(),
        exp: expiration_time.timestamp() as usize,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret_key.as_ref()),
    )
    .unwrap()
}
