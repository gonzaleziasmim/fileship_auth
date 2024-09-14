use mongodb::{Client, Database};
use std::env;

pub async fn init_db() -> Result<Database, mongodb::error::Error> {
    let uri = env::var("MONGODB_URI").expect("MONGODB_URI must be set");
    let client = Client::with_uri_str(&uri).await?;
    let db = client.database("auth_db");
    Ok(db)
}
