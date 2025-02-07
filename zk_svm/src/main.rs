//! A simple program that takes a number `n` as input, and writes the `n-1`th and `n`th fibonacci
//! number as an output.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]

use std::sync::Arc;

use deterministic_svm::InvokeContext;
use solana_sbpf::{
    memory_region::MemoryMapping,
    program::{BuiltinProgram, SBPFVersion},
    vm::EbpfVm,
};

sp1_zkvm::entrypoint!(main);

pub fn main() {
    // Read the input of the program.
    // It must contain everything needed to execute the block
    let _input_bytes: Vec<u8> = sp1_zkvm::io::read::<Vec<u8>>();
    // let _input = &mut ExecutionInput::from(input_bytes);

    // Transform the rollup block back into normal transactions
    // let _txs = input.block.instructions.iter().map(|ix| {
    //     Transaction::new_unsigned(Message::new(
    //         &vec![Instruction {
    //             program_id: Pubkey::new_from_array(
    //                 input.block.accounts[ix.accounts_indices[0] as usize],
    //             ),
    //             accounts: ix
    //                 .accounts_indices
    //                 .iter()
    //                 .map(|index| AccountMeta {
    //                     pubkey: Pubkey::new_from_array(input.block.accounts[*index as usize]),
    //                     is_signer: false,
    //                     is_writable: false,
    //                 })
    //                 .collect(),
    //             data: ix.data.clone(),
    //         }],
    //         None,
    //     ))
    // });

    // Recreate the state
    // let ctx = InvokeContext::new();
    // let mut vm = EbpfVm::new(
    //     Arc::new(BuiltinProgram::new_mock()),
    //     SBPFVersion::V0,
    //     unsafe { std::mem::transmute::<&mut InvokeContext, &mut InvokeContext>(ctx) },
    //     MemoryMapping::Identity,
    //     4096,
    // );
    // let mut svm = LiteSVM::new();

    // Process transactions
    // for tx in txs {
    //     svm.send_transaction(tx).unwrap();
    // }

    // Update accounts
    // for pk in input.state.accounts.clone().keys() {
    //     input.state.accounts.insert(
    //         *pk,
    //         TreeNode::Leaf(
    //             RollupAccount::from(svm.get_account(&Pubkey::new_from_array(*pk)).unwrap()).into(),
    //         ),
    //     );
    // }

    // Update state root
    // let root_bytes = TreeNode::Leaf(vec![1, 2, 3, 4]).hash();

    // Commit to the output state of the blockchain
    sp1_zkvm::io::commit_slice(&[1]);
}
