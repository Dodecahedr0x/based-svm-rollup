use std::{collections::HashMap, io::Read, vec};

use solana_sdk::{pubkey::Pubkey, transaction::Transaction};

/// A rollup block, containing all the accounts used and the sequence of instruction.
///
/// The concept of transaction is given up for simplicity and compacity.
pub struct RollupBlock {
    accounts: Vec<Pubkey>,
    instructions: Vec<RollupInstruction>,
}

/// Using custom serialization because it's simple and more compact than borsh.
/// Using this scheme, it's possible to pack almost 15 transfers in a single L1 tx.
impl Into<Vec<u8>> for RollupBlock {
    fn into(self) -> Vec<u8> {
        vec![
            (self.accounts.len() as u16).to_le_bytes().to_vec(),
            self.accounts
                .iter()
                .map(|account| account.to_bytes().to_vec())
                .collect::<Vec<Vec<u8>>>()
                .concat(),
            self.instructions
                .iter()
                .map(|ix| {
                    vec![
                        (ix.accounts_indices.len() as u8).to_le_bytes().to_vec(),
                        ix.accounts_indices
                            .iter()
                            .map(|index| index.to_le_bytes().to_vec())
                            .collect::<Vec<Vec<u8>>>()
                            .concat(),
                        ix.data.clone(),
                    ]
                    .concat()
                })
                .collect::<Vec<Vec<u8>>>()
                .concat(),
        ]
        .concat()
    }
}

impl From<Vec<u8>> for RollupBlock {
    fn from(value: Vec<u8>) -> Self {
        let mut cursor = std::io::Cursor::new(value);

        let accounts_len = u16::from_le_bytes([cursor.get_ref()[0], cursor.get_ref()[1]]) as usize;
        cursor.set_position(2);

        let mut accounts = Vec::with_capacity(accounts_len);
        for _ in 0..accounts_len {
            let mut pubkey_bytes = [0u8; 32];
            cursor.read_exact(&mut pubkey_bytes).unwrap();
            accounts.push(Pubkey::new_from_array(pubkey_bytes));
        }

        let mut instructions = Vec::new();
        while (cursor.position() as usize) < cursor.get_ref().len() {
            let accounts_indices_len = cursor.get_ref()[cursor.position() as usize] as usize;
            cursor.set_position(cursor.position() + 1);

            let mut accounts_indices = Vec::with_capacity(accounts_indices_len);
            for _ in 0..accounts_indices_len {
                let mut index_bytes = [0u8; 2];
                cursor.read_exact(&mut index_bytes).unwrap();
                accounts_indices.push(u16::from_le_bytes(index_bytes));
            }

            let mut data = Vec::new();
            cursor.read_to_end(&mut data).unwrap();

            instructions.push(RollupInstruction {
                accounts_indices,
                data,
            });
        }

        RollupBlock {
            accounts,
            instructions,
        }
    }
}

/// A single instruction of a rollup
pub struct RollupInstruction {
    accounts_indices: Vec<u16>,
    data: Vec<u8>,
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
                accounts_indices: ix
                    .accounts
                    .iter()
                    .map(|index| {
                        all_accounts
                            .iter()
                            .position(|pk| pk.eq(&tx.message.account_keys[*index as usize]))
                            .unwrap() as u16
                    })
                    .collect(),
                data: ix.data,
            });
        }
    }

    RollupBlock {
        accounts: all_accounts,
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
        let num_transactions = 14;
        let txs: Vec<Transaction> = (0..num_transactions)
            .map(|_| create_dummy_transaction())
            .collect();

        let rollup_block = rollup_txs(txs);

        assert_eq!(rollup_block.accounts.len(), num_transactions * 2 + 1);
        assert_eq!(rollup_block.instructions.len(), num_transactions);
        assert_eq!(
            <RollupBlock as Into<Vec<u8>>>::into(rollup_block).len(),
            115 + 81 * (num_transactions - 1) // First tx is bigger, then they reduce because of dedup
        )
    }
}
