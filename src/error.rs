use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("Hashing error: {0}")]
    HashingError(#[from] bcrypt::BcryptError),
    
    #[error("JWT error: {0}")]
    JwtError(#[from] jsonwebtoken::errors::Error),
    
    #[error("MongoDB error: {0}")]
    DatabaseError(#[from] mongodb::error::Error),
}
