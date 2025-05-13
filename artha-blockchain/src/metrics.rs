use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

static BLOCK_COUNT: AtomicU64 = AtomicU64::new(0);
static TRANSACTION_COUNT: AtomicU64 = AtomicU64::new(0);
static START_TIME: AtomicU64 = AtomicU64::new(0);

pub fn init_metrics() {
    START_TIME.store(Instant::now().elapsed().as_secs(), Ordering::SeqCst);
}

pub fn increment_block_count() {
    BLOCK_COUNT.fetch_add(1, Ordering::SeqCst);
}

pub fn increment_transaction_count() {
    TRANSACTION_COUNT.fetch_add(1, Ordering::SeqCst);
}

pub fn get_metrics() -> serde_json::Value {
    let uptime = Instant::now().elapsed().as_secs() - START_TIME.load(Ordering::SeqCst);
    
    serde_json::json!({
        "blocks": BLOCK_COUNT.load(Ordering::SeqCst),
        "transactions": TRANSACTION_COUNT.load(Ordering::SeqCst),
        "uptime_seconds": uptime
    })
} 