use bcrypt::{hash, verify};
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

    let my_claims = Claims {
        sub: email.to_string(),
        exp: 10000000000,
    };

    encode(
        &Header::default(),
        &my_claims,
        &EncodingKey::from_secret(secret_key.as_ref()),
    )
    .unwrap()
}
