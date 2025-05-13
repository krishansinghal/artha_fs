use std::collections::HashMap;
use crate::types::transaction::Transaction;

pub struct TransactionPool {
    transactions: HashMap<String, Transaction>,
}

impl TransactionPool {
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

    pub fn remove_transaction(&mut self, id: &str) {
        self.transactions.remove(id);
    }
} 