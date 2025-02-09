//! A simple program that takes a number `n` as input, and writes the `n-1`th and `n`th fibonacci
//! number as an output.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]

use std::sync::Arc;

use deterministic_svm::{
    AccountSharedData, ComputeBudget, FeatureSet, FeeStructure, InvokeContext, Pubkey, Rent,
    TransactionContext,
};
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
    let compute_budget = ComputeBudget::default();
    let feature_set = FeatureSet::all_enabled();
    let fee_structure = FeeStructure::default();
    let lamports_per_signature = fee_structure.lamports_per_signature;
    // let rent_collector = RentCollector::default();

    // Solana runtime.
    // let fork_graph = Arc::new(RwLock::new(SequencerForkGraph {}));

    // // create transaction processor, add accounts and programs, builtins,
    // let processor = TransactionBatchProcessor::<SequencerForkGraph>::default();

    // let mut cache = processor.program_cache.write().unwrap();

    // // Initialize the mocked fork graph.
    // // let fork_graph = Arc::new(RwLock::new(PayTubeForkGraph {}));
    // cache.fork_graph = Some(Arc::downgrade(&fork_graph));

    // let rent = Rent::default();

    let accounts_data = transaction
        .message
        .account_keys
        .iter()
        .map(|pubkey| {
            (
                pubkey.clone(),
                rpc_client_temp.get_account(pubkey).unwrap().into(),
            )
        })
        .collect::<Vec<(Pubkey, AccountSharedData)>>();

    let mut transaction_context = TransactionContext::new(accounts_data, Rent::default(), 0, 0);

    let runtime_env = Arc::new(
        create_program_runtime_environment_v1(&feature_set, &compute_budget, false, false).unwrap(),
    );

    let mut prog_cache = ProgramCacheForTxBatch::new(
        Slot::default(),
        ProgramRuntimeEnvironments {
            program_runtime_v1: runtime_env.clone(),
            program_runtime_v2: runtime_env,
        },
        None,
        Epoch::default(),
    );

    let sysvar_c = sysvar_cache::SysvarCache::default();
    let env = EnvironmentConfig::new(
        Hash::default(),
        None,
        None,
        Arc::new(feature_set),
        lamports_per_signature,
        &sysvar_c,
    );
    // let default_env = EnvironmentConfig::new(blockhash, epoch_total_stake, epoch_vote_accounts, feature_set, lamports_per_signature, sysvar_cache)

    // let processing_environment = TransactionProcessingEnvironment {
    //     blockhash: Hash::default(),
    //     epoch_total_stake: None,
    //     epoch_vote_accounts: None,
    //     feature_set: Arc::new(feature_set),
    //     fee_structure: Some(&fee_structure),
    //     lamports_per_signature,
    //     rent_collector: Some(&rent_collector),
    // };

    let mut invoke_context = InvokeContext::new(
        &mut transaction_context,
        &mut prog_cache,
        env,
        None,
        compute_budget.to_owned(),
    );

    let mut used_cu = 0u64;
    let sanitized = SanitizedTransaction::try_from_legacy_transaction(
        Transaction::from(transaction.clone()),
        &HashSet::new(),
    );
    log::info!("{:?}", sanitized.clone());

    let mut timings = ExecuteTimings::default();

    let _result_msg = MessageProcessor::process_message(
        sanitized.unwrap().message(),
        &vec![],
        &mut invoke_context,
        &mut timings,
        &mut used_cu,
    );

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
