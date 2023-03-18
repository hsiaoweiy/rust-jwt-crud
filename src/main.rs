use std::process;

use actix_cors::Cors;
use actix_web::{http::header, middleware::Logger, web, App, HttpServer};
use config::Config;
use dotenv::dotenv;
use redis::Client;
use sqlx::{pool::PoolOptions, Pool, Postgres};

mod config;
mod handler;
mod jwt_auth_middleware;
mod model;
mod request;
mod response;
mod token;

pub struct AppState {
    db: Pool<Postgres>,
    env: Config,
    redis_client: Client,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "actix_web=info")
    }
    dotenv().ok();
    env_logger::init();

    let config = Config::init();

    let pool = match PoolOptions::new()
        .max_connections(10)
        .connect(&config.database_url)
        .await
    {
        Ok(pool) => {
            println!("database connected");
            pool
        }
        Err(e) => {
            println!("could not connect database, {}", e);
            process::exit(1);
        }
    };

    let redis_client = match Client::open(config.redis_url.to_owned()) {
        Ok(client) => {
            println!("redis successfully connected");
            client
        }
        Err(e) => {
            println!("error connecting redis: {}", e);
            process::exit(1);
        }
    };
    HttpServer::new(move || {
        let cors = Cors::default()
            .allowed_origin(&config.client_origin)
            .allowed_methods(vec!["GET", "POST"])
            .allowed_headers(vec![
                header::CONTENT_TYPE,
                header::AUTHORIZATION,
                header::ACCEPT,
            ])
            .supports_credentials();
        App::new()
            .app_data(web::Data::new(AppState {
                db: pool.clone(),
                env: config.clone(),
                redis_client: redis_client.clone(),
            }))
            .configure(handler::config)
            .wrap(cors)
            .wrap(Logger::default())
    })
    .bind(("127.0.0.1", 8000))?
    .run()
    .await
}
