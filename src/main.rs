mod routes;
mod services;
mod db;
mod models;
mod error;

use hyper::{Server, Request, Body};
use std::sync::Arc;
use std::convert::Infallible;
use std::net::SocketAddr;
use dotenvy::dotenv;
use routes::handle_request;

#[tokio::main]
async fn main() {
    dotenv().ok();  // Load environment variables

    // Initialize MongoDB connection
    let db = Arc::new(db::init_db().await.unwrap());

    // Define the service for handling requests
    let make_svc = hyper::service::make_service_fn(move |_conn| {
        let db = Arc::clone(&db);
        async move { Ok::<_, Infallible>(hyper::service::service_fn(move |req: Request<Body>| handle_request(req, db.clone()))) }
    });

    // Define the server address
    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));

    // Start the server
    let server = Server::bind(&addr).serve(make_svc);

    println!("Server running on http://localhost:3000");

    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
}
