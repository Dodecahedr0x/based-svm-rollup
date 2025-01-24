//! A simple program that takes a number `n` as input, and writes the `n-1`th and `n`th fibonacci
//! number as an output.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

use block_builder::ExecutionInput;
use solana_sdk::keccak;

pub fn main() {
    // Read the input of the program.
    // It must contain everything needed to execute the block
    let block_bytes: Vec<u8> = sp1_zkvm::io::read::<Vec<u8>>();
    let (_block, _): (ExecutionInput, usize) =
        bincode::decode_from_slice(&block_bytes.clone(), bincode::config::standard()).unwrap();

    // Transform the rollup block back into normal transactions

    // Create the processing context

    // Process transactions

    // Update accounts

    // Update state root

    // Encode the public values of the program: state commitments before, after, and the block
    let bytes = vec![block_bytes].concat();
    let input_hash = keccak::hash(&bytes).to_bytes();

    // Commit to the public values of the program. The final proof will have a commitment to all the
    // bytes that were committed to.
    sp1_zkvm::io::commit_slice(&input_hash);
}
