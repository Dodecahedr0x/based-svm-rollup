//! An end-to-end example of using the SP1 SDK to generate a proof of a program that can be executed
//! or have a core proof generated.
//!
//! You can run this script using the following command:
//! ```shell
//! RUST_LOG=info cargo run --release -- --execute
//! ```
//! or
//! ```shell
//! RUST_LOG=info cargo run --release -- --prove
//! ```

use clap::Parser;
use deterministic_svm::{
    system_interface, system_program, Account, AccountMeta, ExecutionInput, Instruction,
    Transaction,
};
use solana_sdk::{pubkey::Pubkey, signature::Keypair, signer::Signer};
use sp1_sdk::{include_elf, ProverClient, SP1Stdin};

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const FRACTAL_ELF: &[u8] = include_elf!("zkSVM");

/// The arguments for the command.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(long)]
    execute: bool,

    #[clap(long)]
    prove: bool,

    #[clap(long)]
    input: Option<Vec<u8>>,
}

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();
    dotenv::dotenv().ok();

    // Parse the command line arguments.
    let args = Args::parse();

    if args.execute == args.prove {
        eprintln!("Error: You must specify either --execute or --prove");
        std::process::exit(1);
    }

    // Setup the prover client.
    let client = ProverClient::from_env();

    // Setup the inputs.
    let test_initial_lamports = 10000000;
    let test_sender_kp = Keypair::new();
    let pk_a = test_sender_kp.pubkey();
    let pk_b = Pubkey::new_unique();
    let ser_txs = bincode::serialize(&Transaction::new_with_payer(
        &[Instruction::new_with_bincode(
            system_program::ID,
            &system_interface::SystemInstruction::Transfer {
                lamports: test_initial_lamports / 2,
            },
            vec![
                AccountMeta::new(
                    deterministic_svm::Pubkey::new_from_array(pk_a.to_bytes()),
                    true,
                ),
                AccountMeta::new(
                    deterministic_svm::Pubkey::new_from_array(pk_b.to_bytes()),
                    false,
                ),
            ],
        )],
        Some(&deterministic_svm::Pubkey::new_from_array(pk_a.to_bytes())),
    ))
    .unwrap();
    println!("{}", ser_txs.len());
    let test_input = ExecutionInput {
        accounts: vec![
            (
                deterministic_svm::Pubkey::new_from_array(pk_a.to_bytes()),
                Account::new(10000000, 0, &system_program::id()),
            ),
            (
                deterministic_svm::Pubkey::new_from_array(pk_b.to_bytes()),
                Account::new(0, 0, &system_program::id()),
            ),
        ],
        // Ser/de to avoid types conflicts
        txs: vec![bincode::deserialize(&ser_txs).unwrap()],
    };
    let input = if let Some(input) = args.input {
        input
    } else {
        bincode::serialize(&test_input).unwrap()
    };
    let mut stdin = SP1Stdin::new();
    stdin.write(&input);

    if args.execute {
        // Execute the program
        let (output, report) = client.execute(FRACTAL_ELF, &stdin).run().unwrap();
        println!("Program executed successfully.");

        // Read the output.
        // let decoded = PublicValuesStruct::abi_decode(output.as_slice(), true).unwrap();
        // let PublicValuesStruct { n, a, b } = decoded;
        // println!("n: {}", n);
        // println!("a: {}", a);
        println!("buffer: {}", output.raw());

        // Record the number of cycles executed.
        println!("Number of cycles: {}", report.total_instruction_count());
    } else {
        // Setup the program for proving.
        let (pk, vk) = client.setup(FRACTAL_ELF);

        // Generate the proof
        let proof = client
            .prove(&pk, &stdin)
            .groth16()
            .run()
            .expect("failed to generate proof");
        proof.save("./proof.bin").expect("failed to save proof");

        println!("Successfully generated proof!");

        // Verify the proof.
        client.verify(&proof, &vk).expect("failed to verify proof");
        println!("Successfully verified proof!");
    }
}
