pub mod state;

use std::{collections::HashMap, vec};

use bincode::{Decode, Encode};
use solana_sdk::{pubkey::Pubkey, transaction::Transaction};
use state::RollupState;

/// All the inputs needed to execute a block in the zkSVM
#[derive(Decode, Encode)]
pub struct ExecutionInput {
    pub block: RollupBlock,
    pub state: RollupState,
}

impl From<Vec<u8>> for ExecutionInput {
    fn from(value: Vec<u8>) -> Self {
        bincode::decode_from_slice(&value, bincode::config::standard())
            .unwrap()
            .0
    }
}

impl Into<Vec<u8>> for ExecutionInput {
    fn into(self) -> Vec<u8> {
        bincode::encode_to_vec(self, bincode::config::standard()).unwrap()
    }
}

/// A rollup block, containing all the accounts used and the sequence of instruction.
///
/// The concept of transaction is given up for simplicity and compacity.
#[derive(Decode, Encode)]
pub struct RollupBlock {
    // List of accounts pubkeys used
    pub accounts: Vec<[u8; 32]>,
    // TODO: Include txs and verify signatures
    pub instructions: Vec<RollupInstruction>,
}

impl From<Vec<u8>> for RollupBlock {
    fn from(value: Vec<u8>) -> Self {
        bincode::decode_from_slice(&value, bincode::config::standard())
            .unwrap()
            .0
    }
}

impl Into<Vec<u8>> for RollupBlock {
    fn into(self) -> Vec<u8> {
        bincode::encode_to_vec(self, bincode::config::standard()).unwrap()
    }
}

/// A single instruction of a rollup
#[derive(Decode, Encode)]
pub struct RollupInstruction {
    pub accounts_indices: Vec<u16>,
    pub data: Vec<u8>,
}

/// This function takes a vector of transactions and outputs the corresponding rollup block.
/// The goal is to compress transactions to minimize the size of the serialized block.
///
/// **Assumes that transactions are sanitized!**
///
/// # Arguments
///
/// * `txs` - A vector of `Transaction` objects to be processed.
fn rollup_txs(txs: Vec<Transaction>) -> RollupBlock {
    // Create the accounts map with all accounts
    let mut all_accounts: Vec<Pubkey> = vec![];
    for tx in &txs {
        all_accounts = [all_accounts, tx.message.account_keys.clone()].concat();
    }

    // Deduplicate accounts
    let mut unique_accounts: HashMap<Pubkey, bool> = HashMap::new();
    all_accounts.retain(|account| unique_accounts.insert(*account, true).is_none());

    // Build rollup transactions
    let mut rollup_ixs: Vec<RollupInstruction> = vec![];
    for tx in txs {
        for ix in tx.message.instructions {
            rollup_ixs.push(RollupInstruction {
                // Putting the program as the first id
                accounts_indices: std::iter::once(
                    all_accounts
                        .iter()
                        .position(|pk| {
                            pk.eq(&tx.message.account_keys[ix.program_id_index as usize])
                        })
                        .unwrap() as u16,
                )
                .chain(
                    ix.accounts
                        .iter()
                        .filter(|index| **index != ix.program_id_index)
                        .map(|index| {
                            all_accounts
                                .iter()
                                .position(|pk| pk.eq(&tx.message.account_keys[*index as usize]))
                                .unwrap() as u16
                        }),
                )
                .collect(),
                data: ix.data,
            });
        }
    }

    RollupBlock {
        accounts: all_accounts
            .iter()
            .map(|account| account.to_bytes())
            .collect(),
        instructions: rollup_ixs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_sdk::{
        message::Message, pubkey::Pubkey, system_instruction::transfer, transaction::Transaction,
    };

    fn create_dummy_transaction() -> Transaction {
        let from = Pubkey::new_unique();
        let to = Pubkey::new_unique();
        let ixs = vec![transfer(&from, &to, 10)];
        Transaction {
            message: Message::new(&ixs, Some(&from)),
            ..Transaction::default()
        }
    }

    #[test]
    fn test_rollup_txs_multiple_transactions() {
        let num_transactions = 11;
        let txs: Vec<Transaction> = (0..num_transactions)
            .map(|_| create_dummy_transaction())
            .collect();

        let rollup_block = rollup_txs(txs);

        assert_eq!(rollup_block.accounts.len(), num_transactions * 2 + 1);
        assert_eq!(rollup_block.instructions.len(), num_transactions);
        let encoded_vec: Vec<u8> = rollup_block.into();
        assert_eq!(
            encoded_vec.len(),
            114 + 80 * (num_transactions - 1) // First tx is bigger, then they reduce because of dedup
        )
    }
}
