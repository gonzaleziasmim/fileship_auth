use hyper::{Body, Request, Response, Method, StatusCode};
use mongodb::Database;
use std::sync::Arc;
use std::convert::Infallible;
use futures_util::TryStreamExt;
use crate::services::auth_service::{hash_password, verify_password, generate_jwt};
use crate::models::user::User;
use serde_json::json;

pub async fn handle_request(req: Request<Body>, db: Arc<Database>) -> Result<Response<Body>, Infallible> {
    match (req.method(), req.uri().path()) {
        (&Method::POST, "/register") => handle_register(req, db).await,
        (&Method::POST, "/login") => handle_login(req, db).await,
        _ => Ok(not_found_response()),
    }
}

// Handle user registration
async fn handle_register(req: Request<Body>, db: Arc<Database>) -> Result<Response<Body>, Infallible> {
    let body_bytes = hyper::body::to_bytes(req.into_body()).await.unwrap();
    let register_form: User = match serde_json::from_slice(&body_bytes) {
        Ok(form) => form,
        Err(_) => return Ok(bad_request_response("Invalid JSON")),
    };

    let users_collection = db.collection::<User>("users");

    // Hash the password using bcrypt
    let hashed_password = match hash_password(&register_form.password).await {
        Ok(hashed) => hashed,
        Err(_) => return Ok(internal_server_error_response("Password hashing failed")),
    };

    // Insert user into MongoDB
    let user = User {
        email: register_form.email.clone(),
        password: hashed_password,
    };

    match users_collection.insert_one(user).await {
        Ok(_) => Ok(success_response(&format!("User {} registered successfully!", register_form.email))),
        Err(_) => Ok(internal_server_error_response("Failed to register user")),
    }
}

// Handle user login
async fn handle_login(req: Request<Body>, db: Arc<Database>) -> Result<Response<Body>, Infallible> {
    let body_bytes = hyper::body::to_bytes(req.into_body()).await.unwrap();
    let login_form: User = match serde_json::from_slice(&body_bytes) {
        Ok(form) => form,
        Err(_) => return Ok(bad_request_response("Invalid JSON")),
    };

    let users_collection = db.collection::<User>("users");

    // Search for the user in MongoDB
    let filter = mongodb::bson::doc! { "email": &login_form.email };
    let mut cursor = users_collection.find(filter).await.unwrap();

    if let Some(user_doc) = cursor.try_next().await.unwrap() {
        // Verify password
        if verify_password(&login_form.password, &user_doc.password).await.unwrap_or(false) {
            // Generate JWT
            let token = generate_jwt(&user_doc.email).await;
            let response_body = json!({ "token": token });
            return Ok(success_response(&response_body.to_string()));
        }
    }

    // If credentials are invalid, return unauthorized
    Ok(unauthorized_response())
}

// Utility functions to generate standard HTTP responses
fn success_response(message: &str) -> Response<Body> {
    Response::builder()
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .status(StatusCode::OK)
        .body(Body::from(message.to_string()))
        .unwrap()
}

fn bad_request_response(message: &str) -> Response<Body> {
    Response::builder()
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .status(StatusCode::BAD_REQUEST)
        .body(Body::from(message.to_string())) 
        .unwrap()
}

fn internal_server_error_response(message: &str) -> Response<Body> {
    Response::builder()
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .body(Body::from(message.to_string()))
        .unwrap()
}

fn unauthorized_response() -> Response<Body> {
    Response::builder()
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .status(StatusCode::UNAUTHORIZED)
        .body(Body::from("Invalid credentials".to_string()))
        .unwrap()
}

fn not_found_response() -> Response<Body> {
    Response::builder()
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .status(StatusCode::NOT_FOUND)
        .body(Body::from("Not Found".to_string()))
        .unwrap()
}
