use std::{cell::RefCell, pin::Pin, rc::Rc, sync::Arc};

pub type Pubkey = [u8; 32];
pub type Epoch = u64;
pub type IndexOfAccount = u16;

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct AccountSharedData {
    /// lamports in the account
    lamports: u64,
    /// data held in this account
    data: Arc<Vec<u8>>,
    /// the program that owns this account. If executable, the program that loads this account.
    owner: Pubkey,
    /// this account's data contains a loaded program (and is now read-only)
    executable: bool,
    /// the epoch at which this account will next owe rent
    rent_epoch: Epoch,
}

#[derive(Clone, Debug, PartialEq)]
pub struct TransactionAccounts {
    accounts: Vec<RefCell<AccountSharedData>>,
    touched_flags: RefCell<Box<[bool]>>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TransactionReturnData {
    pub program_id: Pubkey,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstructionAccount {
    /// Points to the account and its key in the `TransactionContext`
    pub index_in_transaction: IndexOfAccount,
    /// Points to the first occurrence in the parent `InstructionContext`
    ///
    /// This excludes the program accounts.
    pub index_in_caller: IndexOfAccount,
    /// Points to the first occurrence in the current `InstructionContext`
    ///
    /// This excludes the program accounts.
    pub index_in_callee: IndexOfAccount,
    /// Is this account supposed to sign
    pub is_signer: bool,
    /// Is this account allowed to become writable
    pub is_writable: bool,
}

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct InstructionContext {
    nesting_level: usize,
    instruction_accounts_lamport_sum: u128,
    program_accounts: Vec<IndexOfAccount>,
    instruction_accounts: Vec<InstructionAccount>,
    instruction_data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TransactionContext {
    account_keys: Pin<Box<[Pubkey]>>,
    accounts: Rc<TransactionAccounts>,
    instruction_stack_capacity: usize,
    instruction_trace_capacity: usize,
    instruction_stack: Vec<usize>,
    instruction_trace: Vec<InstructionContext>,
    return_data: TransactionReturnData,
    accounts_resize_delta: RefCell<i64>,
}
