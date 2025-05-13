use actix_web::web;
use super::handlers;

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api")
            .route("/transaction", web::post().to(handlers::create_transaction))
            .route("/transaction/{id}", web::get().to(handlers::get_transaction))
            .route("/transactions", web::get().to(handlers::get_all_transactions))
            .route("/metrics", web::get().to(handlers::get_metrics))
    );
} 