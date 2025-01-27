//! A simple program that takes a number `n` as input, and writes the `n-1`th and `n`th fibonacci
//! number as an output.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

use std::sync::{atomic::AtomicBool, Arc};

use block_builder::{state::RollupAccount, ExecutionInput};
use merkle_tree::TreeNode;
use solana_runtime::{bank::Bank, runtime_config::RuntimeConfig};
use solana_sdk::{
    account::AccountSharedData,
    genesis_config::GenesisConfig,
    instruction::{AccountMeta, Instruction},
    message::Message,
    pubkey::Pubkey,
    transaction::Transaction,
};

pub fn main() {
    // Read the input of the program.
    // It must contain everything needed to execute the block
    let input_bytes: Vec<u8> = sp1_zkvm::io::read::<Vec<u8>>();
    let input = &mut ExecutionInput::from(input_bytes);

    // Transform the rollup block back into normal transactions
    let txs = input.block.instructions.iter().map(|ix| {
        Transaction::new_unsigned(Message::new(
            &vec![Instruction {
                program_id: Pubkey::new_from_array(
                    input.block.accounts[ix.accounts_indices[0] as usize],
                ),
                accounts: ix
                    .accounts_indices
                    .iter()
                    .map(|index| AccountMeta {
                        pubkey: Pubkey::new_from_array(input.block.accounts[*index as usize]),
                        is_signer: false,
                        is_writable: false,
                    })
                    .collect(),
                data: ix.data.clone(),
            }],
            None,
        ))
    });

    // Recreate the state
    let bank = Bank::new_with_paths(
        &GenesisConfig::new(
            &input
                .state
                .accounts
                .iter()
                .map(|(pk, node)| {
                    if let TreeNode::Leaf(data) = node.clone() {
                        let rollup_account = RollupAccount::from(data);

                        (Pubkey::new_from_array(*pk), rollup_account.into())
                    } else {
                        // TODO: Handle gracefully
                        panic!("Account should have been a leaf!")
                    }
                })
                .collect::<Vec<(Pubkey, AccountSharedData)>>(),
            &[],
        ),
        Arc::new(RuntimeConfig::default()),
        vec![],
        None,
        None,
        false,
        None,
        None,
        None,
        Arc::new(AtomicBool::new(false)),
        None,
        None,
    );

    // Process transactions
    for tx in txs {
        bank.process_transaction(&tx).unwrap();
    }

    // Update accounts
    for pk in input.state.accounts.clone().keys() {
        input.state.accounts.insert(
            *pk,
            TreeNode::Leaf(
                RollupAccount::from(bank.get_account(&Pubkey::new_from_array(*pk)).unwrap()).into(),
            ),
        );
    }

    // Update state root
    let root_bytes = input.state.root.hash();

    // Commit to the output state of the blockchain
    sp1_zkvm::io::commit_slice(&root_bytes);
}
