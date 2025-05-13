use crate::types::transaction::Transaction;
use std::collections::HashMap;

pub struct LedgerState {
    transactions: HashMap<String, Transaction>,
}

impl LedgerState {
    pub fn new() -> Self {
        Self {
            transactions: HashMap::new(),
        }
    }

    pub fn add_transaction(&mut self, transaction: Transaction) {
        self.transactions.insert(transaction.id.clone(), transaction);
    }

    pub fn get_transaction(&self, id: &str) -> Option<&Transaction> {
        self.transactions.get(id)
    }

    pub fn get_all_transactions(&self) -> Vec<&Transaction> {
        self.transactions.values().collect()
    }
} 
