use actix_web::{web, HttpResponse, Responder};
use crate::types::transaction::{Transaction, TransactionPool};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::{Arc, Mutex};

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateTransactionRequest {
    pub sender: String,
    pub recipient: String,
    pub amount: u64,
    pub gas_limit: u64,
    pub gas_price: u64,
    pub chain_id: String,
}

pub async fn create_transaction(
    pool: web::Data<Arc<Mutex<TransactionPool>>>,
    transaction: web::Json<Transaction>,
) -> impl Responder {
    let mut pool = pool.lock().unwrap(); // Acquire mutable lock
    match pool.add_transaction(transaction.into_inner()) {
        Ok(_) => HttpResponse::Ok().json(json!({
            "status": "success",
            "message": "Transaction added to pool"
        })),
        Err(e) => HttpResponse::BadRequest().json(json!({
            "status": "error",
            "error": e.to_string()
        }))
    }
}

pub async fn get_transaction(
    pool: web::Data<Arc<Mutex<TransactionPool>>>,
    tx_id: web::Path<String>,
) -> impl Responder {
    let pool = pool.lock().unwrap(); // Immutable access is fine too
    match pool.get_transaction(&tx_id) {
        Some(tx) => HttpResponse::Ok().json(tx),
        None => HttpResponse::NotFound().json(json!({
            "status": "error",
            "error": "Transaction not found"
        }))
    }
}

pub async fn get_all_transactions(
    pool: web::Data<Arc<Mutex<TransactionPool>>>,
) -> impl Responder {
    let pool = pool.lock().unwrap();
    let transactions = pool.get_all_transactions();
    HttpResponse::Ok().json(transactions)
}

pub async fn remove_transaction(
    pool: web::Data<Arc<Mutex<TransactionPool>>>,
    tx_id: web::Path<String>,
) -> impl Responder {
    let mut pool = pool.lock().unwrap(); // Acquire mutable lock
    pool.remove_transaction(&tx_id);
    HttpResponse::Ok().json(json!({
        "status": "success",
        "message": "Transaction removed from pool"
    }))
}

pub async fn get_metrics() -> impl Responder {
    let metrics = crate::metrics::get_metrics();
    HttpResponse::Ok().json(metrics)
}