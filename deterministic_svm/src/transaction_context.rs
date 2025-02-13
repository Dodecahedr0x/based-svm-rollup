use std::{
    borrow::Cow,
    cell::{Ref, RefCell, RefMut},
    cmp::Ordering,
    collections::HashSet,
    fmt,
    mem::MaybeUninit,
    pin::Pin,
    ptr::copy_nonoverlapping,
    rc::Rc,
    result,
    str::{from_utf8, FromStr},
    sync::Arc,
};

use crate::{
    ed25519_program, secp256k1_program, secp256r1_program, Account, AccountKeys,
    CompiledInstruction, Hash, Instruction, InstructionError, LamportsError, MessageHeader, Pubkey,
    Rent, Sanitize, SanitizeError,
};
use serde::{
    de::{self, SeqAccess, Unexpected, Visitor},
    ser::SerializeTuple,
    Deserializer, Serializer,
};
use serde_big_array::BigArray;
use serde_derive::{Deserialize, Serialize};
use v0::MessageAddressTableLookup;

pub const MAX_BASE58_LEN: usize = 44;
// Inlined to avoid solana_system_interface dep
const MAX_PERMITTED_DATA_LENGTH: u64 = 10 * 1024 * 1024;

// Inlined to avoid solana_system_interface dep
const MAX_PERMITTED_ACCOUNTS_DATA_ALLOCATIONS_PER_TRANSACTION: i64 =
    MAX_PERMITTED_DATA_LENGTH as i64 * 2;

// Inlined to avoid solana_account_info dep
const MAX_PERMITTED_DATA_INCREASE: usize = 1_024 * 10;
pub const MESSAGE_VERSION_PREFIX: u8 = 0x80;

pub type TransactionAccount = (Pubkey, AccountSharedData);
pub type Epoch = u64;
pub type IndexOfAccount = u16;

#[derive(PartialEq, Eq, Clone, Default)]
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

impl From<AccountSharedData> for Account {
    fn from(mut other: AccountSharedData) -> Self {
        let account_data = Arc::make_mut(&mut other.data);
        Self {
            lamports: other.lamports,
            data: std::mem::take(account_data),
            owner: other.owner,
            executable: other.executable,
            rent_epoch: other.rent_epoch,
        }
    }
}

impl From<Account> for AccountSharedData {
    fn from(other: Account) -> Self {
        Self {
            lamports: other.lamports,
            data: Arc::new(other.data),
            owner: other.owner,
            executable: other.executable,
            rent_epoch: other.rent_epoch,
        }
    }
}

pub trait WritableAccount: ReadableAccount {
    fn set_lamports(&mut self, lamports: u64);
    fn checked_add_lamports(&mut self, lamports: u64) -> Result<(), LamportsError> {
        self.set_lamports(
            self.lamports()
                .checked_add(lamports)
                .ok_or(LamportsError::ArithmeticOverflow)?,
        );
        Ok(())
    }
    fn checked_sub_lamports(&mut self, lamports: u64) -> Result<(), LamportsError> {
        self.set_lamports(
            self.lamports()
                .checked_sub(lamports)
                .ok_or(LamportsError::ArithmeticUnderflow)?,
        );
        Ok(())
    }
    fn saturating_add_lamports(&mut self, lamports: u64) {
        self.set_lamports(self.lamports().saturating_add(lamports))
    }
    fn saturating_sub_lamports(&mut self, lamports: u64) {
        self.set_lamports(self.lamports().saturating_sub(lamports))
    }
    fn data_as_mut_slice(&mut self) -> &mut [u8];
    fn set_owner(&mut self, owner: Pubkey);
    fn copy_into_owner_from_slice(&mut self, source: &[u8]);
    fn set_executable(&mut self, executable: bool);
    fn set_rent_epoch(&mut self, epoch: Epoch);
    fn create(
        lamports: u64,
        data: Vec<u8>,
        owner: Pubkey,
        executable: bool,
        rent_epoch: Epoch,
    ) -> Self;
}

pub trait ReadableAccount: Sized {
    fn lamports(&self) -> u64;
    fn data(&self) -> &[u8];
    fn owner(&self) -> &Pubkey;
    fn executable(&self) -> bool;
    fn rent_epoch(&self) -> Epoch;
    fn to_account_shared_data(&self) -> AccountSharedData {
        AccountSharedData::create(
            self.lamports(),
            self.data().to_vec(),
            *self.owner(),
            self.executable(),
            self.rent_epoch(),
        )
    }
}

impl ReadableAccount for Account {
    fn lamports(&self) -> u64 {
        self.lamports
    }
    fn data(&self) -> &[u8] {
        &self.data
    }
    fn owner(&self) -> &Pubkey {
        &self.owner
    }
    fn executable(&self) -> bool {
        self.executable
    }
    fn rent_epoch(&self) -> Epoch {
        self.rent_epoch
    }
}

impl WritableAccount for Account {
    fn set_lamports(&mut self, lamports: u64) {
        self.lamports = lamports;
    }
    fn data_as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }
    fn set_owner(&mut self, owner: Pubkey) {
        self.owner = owner;
    }
    fn copy_into_owner_from_slice(&mut self, source: &[u8]) {
        self.owner.as_mut().copy_from_slice(source);
    }
    fn set_executable(&mut self, executable: bool) {
        self.executable = executable;
    }
    fn set_rent_epoch(&mut self, epoch: Epoch) {
        self.rent_epoch = epoch;
    }
    fn create(
        lamports: u64,
        data: Vec<u8>,
        owner: Pubkey,
        executable: bool,
        rent_epoch: Epoch,
    ) -> Self {
        Account {
            lamports,
            data,
            owner,
            executable,
            rent_epoch,
        }
    }
}

impl WritableAccount for AccountSharedData {
    fn set_lamports(&mut self, lamports: u64) {
        self.lamports = lamports;
    }
    fn data_as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data_mut()[..]
    }
    fn set_owner(&mut self, owner: Pubkey) {
        self.owner = owner;
    }
    fn copy_into_owner_from_slice(&mut self, source: &[u8]) {
        self.owner.as_mut().copy_from_slice(source);
    }
    fn set_executable(&mut self, executable: bool) {
        self.executable = executable;
    }
    fn set_rent_epoch(&mut self, epoch: Epoch) {
        self.rent_epoch = epoch;
    }
    fn create(
        lamports: u64,
        data: Vec<u8>,
        owner: Pubkey,
        executable: bool,
        rent_epoch: Epoch,
    ) -> Self {
        AccountSharedData {
            lamports,
            data: Arc::new(data),
            owner,
            executable,
            rent_epoch,
        }
    }
}

impl ReadableAccount for AccountSharedData {
    fn lamports(&self) -> u64 {
        self.lamports
    }
    fn data(&self) -> &[u8] {
        &self.data
    }
    fn owner(&self) -> &Pubkey {
        &self.owner
    }
    fn executable(&self) -> bool {
        self.executable
    }
    fn rent_epoch(&self) -> Epoch {
        self.rent_epoch
    }
    fn to_account_shared_data(&self) -> AccountSharedData {
        // avoid data copy here
        self.clone()
    }
}

impl ReadableAccount for Ref<'_, AccountSharedData> {
    fn lamports(&self) -> u64 {
        self.lamports
    }
    fn data(&self) -> &[u8] {
        &self.data
    }
    fn owner(&self) -> &Pubkey {
        &self.owner
    }
    fn executable(&self) -> bool {
        self.executable
    }
    fn rent_epoch(&self) -> Epoch {
        self.rent_epoch
    }
    fn to_account_shared_data(&self) -> AccountSharedData {
        AccountSharedData {
            lamports: self.lamports(),
            // avoid data copy here
            data: Arc::clone(&self.data),
            owner: *self.owner(),
            executable: self.executable(),
            rent_epoch: self.rent_epoch(),
        }
    }
}

impl ReadableAccount for Ref<'_, Account> {
    fn lamports(&self) -> u64 {
        self.lamports
    }
    fn data(&self) -> &[u8] {
        &self.data
    }
    fn owner(&self) -> &Pubkey {
        &self.owner
    }
    fn executable(&self) -> bool {
        self.executable
    }
    fn rent_epoch(&self) -> Epoch {
        self.rent_epoch
    }
}

fn debug_fmt<T: ReadableAccount>(item: &T, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let mut f = f.debug_struct("Account");

    f.field("lamports", &item.lamports())
        .field("data.len", &item.data().len())
        .field("owner", &item.owner())
        .field("executable", &item.executable())
        .field("rent_epoch", &item.rent_epoch());
    // debug_account_data(item.data(), &mut f);

    f.finish()
}

impl fmt::Debug for Account {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        debug_fmt(self, f)
    }
}

impl fmt::Debug for AccountSharedData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        debug_fmt(self, f)
    }
}

fn shared_new<T: WritableAccount>(lamports: u64, space: usize, owner: &Pubkey) -> T {
    T::create(
        lamports,
        vec![0u8; space],
        *owner,
        bool::default(),
        Epoch::default(),
    )
}

fn shared_new_rent_epoch<T: WritableAccount>(
    lamports: u64,
    space: usize,
    owner: &Pubkey,
    rent_epoch: Epoch,
) -> T {
    T::create(
        lamports,
        vec![0u8; space],
        *owner,
        bool::default(),
        rent_epoch,
    )
}

fn shared_new_ref<T: WritableAccount>(
    lamports: u64,
    space: usize,
    owner: &Pubkey,
) -> Rc<RefCell<T>> {
    Rc::new(RefCell::new(shared_new::<T>(lamports, space, owner)))
}

impl Account {
    pub fn new(lamports: u64, space: usize, owner: &Pubkey) -> Self {
        shared_new(lamports, space, owner)
    }
    pub fn new_ref(lamports: u64, space: usize, owner: &Pubkey) -> Rc<RefCell<Self>> {
        shared_new_ref(lamports, space, owner)
    }
    #[cfg(feature = "bincode")]
    pub fn new_data<T: serde::Serialize>(
        lamports: u64,
        state: &T,
        owner: &Pubkey,
    ) -> Result<Self, bincode::Error> {
        shared_new_data(lamports, state, owner)
    }
    #[cfg(feature = "bincode")]
    pub fn new_ref_data<T: serde::Serialize>(
        lamports: u64,
        state: &T,
        owner: &Pubkey,
    ) -> Result<RefCell<Self>, bincode::Error> {
        shared_new_ref_data(lamports, state, owner)
    }
    #[cfg(feature = "bincode")]
    pub fn new_data_with_space<T: serde::Serialize>(
        lamports: u64,
        state: &T,
        space: usize,
        owner: &Pubkey,
    ) -> Result<Self, bincode::Error> {
        shared_new_data_with_space(lamports, state, space, owner)
    }
    #[cfg(feature = "bincode")]
    pub fn new_ref_data_with_space<T: serde::Serialize>(
        lamports: u64,
        state: &T,
        space: usize,
        owner: &Pubkey,
    ) -> Result<RefCell<Self>, bincode::Error> {
        shared_new_ref_data_with_space(lamports, state, space, owner)
    }
    pub fn new_rent_epoch(lamports: u64, space: usize, owner: &Pubkey, rent_epoch: Epoch) -> Self {
        shared_new_rent_epoch(lamports, space, owner, rent_epoch)
    }
    #[cfg(feature = "bincode")]
    pub fn deserialize_data<T: serde::de::DeserializeOwned>(&self) -> Result<T, bincode::Error> {
        shared_deserialize_data(self)
    }
    #[cfg(feature = "bincode")]
    pub fn serialize_data<T: serde::Serialize>(&mut self, state: &T) -> Result<(), bincode::Error> {
        shared_serialize_data(self, state)
    }
}

impl AccountSharedData {
    pub fn is_shared(&self) -> bool {
        Arc::strong_count(&self.data) > 1
    }

    pub fn reserve(&mut self, additional: usize) {
        if let Some(data) = Arc::get_mut(&mut self.data) {
            data.reserve(additional)
        } else {
            let mut data = Vec::with_capacity(self.data.len().saturating_add(additional));
            data.extend_from_slice(&self.data);
            self.data = Arc::new(data);
        }
    }

    pub fn capacity(&self) -> usize {
        self.data.capacity()
    }

    fn data_mut(&mut self) -> &mut Vec<u8> {
        Arc::make_mut(&mut self.data)
    }

    pub fn resize(&mut self, new_len: usize, value: u8) {
        self.data_mut().resize(new_len, value)
    }

    pub fn extend_from_slice(&mut self, data: &[u8]) {
        self.data_mut().extend_from_slice(data)
    }

    pub fn set_data_from_slice(&mut self, new_data: &[u8]) {
        // If the buffer isn't shared, we're going to memcpy in place.
        let Some(data) = Arc::get_mut(&mut self.data) else {
            // If the buffer is shared, the cheapest thing to do is to clone the
            // incoming slice and replace the buffer.
            return self.set_data(new_data.to_vec());
        };

        let new_len = new_data.len();

        // Reserve additional capacity if needed. Here we make the assumption
        // that growing the current buffer is cheaper than doing a whole new
        // allocation to make `new_data` owned.
        //
        // This assumption holds true during CPI, especially when the account
        // size doesn't change but the account is only changed in place. And
        // it's also true when the account is grown by a small margin (the
        // realloc limit is quite low), in which case the allocator can just
        // update the allocation metadata without moving.
        //
        // Shrinking and copying in place is always faster than making
        // `new_data` owned, since shrinking boils down to updating the Vec's
        // length.

        data.reserve(new_len.saturating_sub(data.len()));

        // Safety:
        // We just reserved enough capacity. We set data::len to 0 to avoid
        // possible UB on panic (dropping uninitialized elements), do the copy,
        // finally set the new length once everything is initialized.
        #[allow(clippy::uninit_vec)]
        // this is a false positive, the lint doesn't currently special case set_len(0)
        unsafe {
            data.set_len(0);
            copy_nonoverlapping(new_data.as_ptr(), data.as_mut_ptr(), new_len);
            data.set_len(new_len);
        };
    }

    #[cfg_attr(feature = "dev-context-only-utils", qualifiers(pub))]
    fn set_data(&mut self, data: Vec<u8>) {
        self.data = Arc::new(data);
    }

    pub fn spare_data_capacity_mut(&mut self) -> &mut [MaybeUninit<u8>] {
        self.data_mut().spare_capacity_mut()
    }

    pub fn new(lamports: u64, space: usize, owner: &Pubkey) -> Self {
        shared_new(lamports, space, owner)
    }
    pub fn new_ref(lamports: u64, space: usize, owner: &Pubkey) -> Rc<RefCell<Self>> {
        shared_new_ref(lamports, space, owner)
    }
    #[cfg(feature = "bincode")]
    pub fn new_data<T: serde::Serialize>(
        lamports: u64,
        state: &T,
        owner: &Pubkey,
    ) -> Result<Self, bincode::Error> {
        shared_new_data(lamports, state, owner)
    }
    #[cfg(feature = "bincode")]
    pub fn new_ref_data<T: serde::Serialize>(
        lamports: u64,
        state: &T,
        owner: &Pubkey,
    ) -> Result<RefCell<Self>, bincode::Error> {
        shared_new_ref_data(lamports, state, owner)
    }
    #[cfg(feature = "bincode")]
    pub fn new_data_with_space<T: serde::Serialize>(
        lamports: u64,
        state: &T,
        space: usize,
        owner: &Pubkey,
    ) -> Result<Self, bincode::Error> {
        shared_new_data_with_space(lamports, state, space, owner)
    }
    #[cfg(feature = "bincode")]
    pub fn new_ref_data_with_space<T: serde::Serialize>(
        lamports: u64,
        state: &T,
        space: usize,
        owner: &Pubkey,
    ) -> Result<RefCell<Self>, bincode::Error> {
        shared_new_ref_data_with_space(lamports, state, space, owner)
    }
    pub fn new_rent_epoch(lamports: u64, space: usize, owner: &Pubkey, rent_epoch: Epoch) -> Self {
        shared_new_rent_epoch(lamports, space, owner, rent_epoch)
    }
    #[cfg(feature = "bincode")]
    pub fn deserialize_data<T: serde::de::DeserializeOwned>(&self) -> Result<T, bincode::Error> {
        shared_deserialize_data(self)
    }
    #[cfg(feature = "bincode")]
    pub fn serialize_data<T: serde::Serialize>(&mut self, state: &T) -> Result<(), bincode::Error> {
        shared_serialize_data(self, state)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct TransactionAccounts {
    accounts: Vec<RefCell<AccountSharedData>>,
    touched_flags: RefCell<Box<[bool]>>,
}

impl TransactionAccounts {
    #[cfg(not(target_os = "solana"))]
    fn new(accounts: Vec<RefCell<AccountSharedData>>) -> TransactionAccounts {
        TransactionAccounts {
            touched_flags: RefCell::new(vec![false; accounts.len()].into_boxed_slice()),
            accounts,
        }
    }

    fn len(&self) -> usize {
        self.accounts.len()
    }

    pub fn get(&self, index: IndexOfAccount) -> Option<&RefCell<AccountSharedData>> {
        self.accounts.get(index as usize)
    }

    #[cfg(not(target_os = "solana"))]
    pub fn touch(&self, index: IndexOfAccount) -> Result<(), InstructionError> {
        *self
            .touched_flags
            .borrow_mut()
            .get_mut(index as usize)
            .ok_or(InstructionError::NotEnoughAccountKeys)? = true;
        Ok(())
    }

    #[cfg(not(target_os = "solana"))]
    pub fn touched_count(&self) -> usize {
        self.touched_flags
            .borrow()
            .iter()
            .fold(0usize, |accumulator, was_touched| {
                accumulator.saturating_add(*was_touched as usize)
            })
    }

    pub fn try_borrow(
        &self,
        index: IndexOfAccount,
    ) -> Result<Ref<'_, AccountSharedData>, InstructionError> {
        self.accounts
            .get(index as usize)
            .ok_or(InstructionError::MissingAccount)?
            .try_borrow()
            .map_err(|_| InstructionError::AccountBorrowFailed)
    }

    pub fn try_borrow_mut(
        &self,
        index: IndexOfAccount,
    ) -> Result<RefMut<'_, AccountSharedData>, InstructionError> {
        self.accounts
            .get(index as usize)
            .ok_or(InstructionError::MissingAccount)?
            .try_borrow_mut()
            .map_err(|_| InstructionError::AccountBorrowFailed)
    }

    pub fn into_accounts(self) -> Vec<AccountSharedData> {
        self.accounts
            .into_iter()
            .map(|account| account.into_inner())
            .collect()
    }
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

impl InstructionContext {
    /// Used together with TransactionContext::get_next_instruction_context()
    #[cfg(not(target_os = "solana"))]
    pub fn configure(
        &mut self,
        program_accounts: &[IndexOfAccount],
        instruction_accounts: &[InstructionAccount],
        instruction_data: &[u8],
    ) {
        self.program_accounts = program_accounts.to_vec();
        self.instruction_accounts = instruction_accounts.to_vec();
        self.instruction_data = instruction_data.to_vec();
    }

    /// How many Instructions were on the stack after this one was pushed
    ///
    /// That is the number of nested parent Instructions plus one (itself).
    pub fn get_stack_height(&self) -> usize {
        self.nesting_level.saturating_add(1)
    }

    /// Number of program accounts
    pub fn get_number_of_program_accounts(&self) -> IndexOfAccount {
        self.program_accounts.len() as IndexOfAccount
    }

    /// Number of accounts in this Instruction (without program accounts)
    pub fn get_number_of_instruction_accounts(&self) -> IndexOfAccount {
        self.instruction_accounts.len() as IndexOfAccount
    }

    /// Assert that enough accounts were supplied to this Instruction
    pub fn check_number_of_instruction_accounts(
        &self,
        expected_at_least: IndexOfAccount,
    ) -> Result<(), InstructionError> {
        if self.get_number_of_instruction_accounts() < expected_at_least {
            Err(InstructionError::NotEnoughAccountKeys)
        } else {
            Ok(())
        }
    }

    /// Data parameter for the programs `process_instruction` handler
    pub fn get_instruction_data(&self) -> &[u8] {
        &self.instruction_data
    }

    /// Searches for a program account by its key
    pub fn find_index_of_program_account(
        &self,
        transaction_context: &TransactionContext,
        pubkey: &Pubkey,
    ) -> Option<IndexOfAccount> {
        self.program_accounts
            .iter()
            .position(|index_in_transaction| {
                transaction_context
                    .account_keys
                    .get(*index_in_transaction as usize)
                    == Some(pubkey)
            })
            .map(|index| index as IndexOfAccount)
    }

    /// Searches for an instruction account by its key
    pub fn find_index_of_instruction_account(
        &self,
        transaction_context: &TransactionContext,
        pubkey: &Pubkey,
    ) -> Option<IndexOfAccount> {
        self.instruction_accounts
            .iter()
            .position(|instruction_account| {
                transaction_context
                    .account_keys
                    .get(instruction_account.index_in_transaction as usize)
                    == Some(pubkey)
            })
            .map(|index| index as IndexOfAccount)
    }

    /// Translates the given instruction wide program_account_index into a transaction wide index
    pub fn get_index_of_program_account_in_transaction(
        &self,
        program_account_index: IndexOfAccount,
    ) -> Result<IndexOfAccount, InstructionError> {
        Ok(*self
            .program_accounts
            .get(program_account_index as usize)
            .ok_or(InstructionError::NotEnoughAccountKeys)?)
    }

    /// Translates the given instruction wide instruction_account_index into a transaction wide index
    pub fn get_index_of_instruction_account_in_transaction(
        &self,
        instruction_account_index: IndexOfAccount,
    ) -> Result<IndexOfAccount, InstructionError> {
        Ok(self
            .instruction_accounts
            .get(instruction_account_index as usize)
            .ok_or(InstructionError::NotEnoughAccountKeys)?
            .index_in_transaction as IndexOfAccount)
    }

    /// Returns `Some(instruction_account_index)` if this is a duplicate
    /// and `None` if it is the first account with this key
    pub fn is_instruction_account_duplicate(
        &self,
        instruction_account_index: IndexOfAccount,
    ) -> Result<Option<IndexOfAccount>, InstructionError> {
        let index_in_callee = self
            .instruction_accounts
            .get(instruction_account_index as usize)
            .ok_or(InstructionError::NotEnoughAccountKeys)?
            .index_in_callee;
        Ok(if index_in_callee == instruction_account_index {
            None
        } else {
            Some(index_in_callee)
        })
    }

    /// Gets the key of the last program account of this Instruction
    pub fn get_last_program_key<'a, 'b: 'a>(
        &'a self,
        transaction_context: &'b TransactionContext,
    ) -> Result<&'b Pubkey, InstructionError> {
        self.get_index_of_program_account_in_transaction(
            self.get_number_of_program_accounts().saturating_sub(1),
        )
        .and_then(|index_in_transaction| {
            transaction_context.get_key_of_account_at_index(index_in_transaction)
        })
    }

    fn try_borrow_account<'a, 'b: 'a>(
        &'a self,
        transaction_context: &'b TransactionContext,
        index_in_transaction: IndexOfAccount,
        index_in_instruction: IndexOfAccount,
    ) -> Result<BorrowedAccount<'a>, InstructionError> {
        let account = transaction_context
            .accounts
            .get(index_in_transaction)
            .ok_or(InstructionError::MissingAccount)?
            .try_borrow_mut()
            .map_err(|_| InstructionError::AccountBorrowFailed)?;
        Ok(BorrowedAccount {
            transaction_context,
            instruction_context: self,
            index_in_transaction,
            index_in_instruction,
            account,
        })
    }

    /// Gets the last program account of this Instruction
    pub fn try_borrow_last_program_account<'a, 'b: 'a>(
        &'a self,
        transaction_context: &'b TransactionContext,
    ) -> Result<BorrowedAccount<'a>, InstructionError> {
        let result = self.try_borrow_program_account(
            transaction_context,
            self.get_number_of_program_accounts().saturating_sub(1),
        );
        debug_assert!(result.is_ok());
        result
    }

    /// Tries to borrow a program account from this Instruction
    pub fn try_borrow_program_account<'a, 'b: 'a>(
        &'a self,
        transaction_context: &'b TransactionContext,
        program_account_index: IndexOfAccount,
    ) -> Result<BorrowedAccount<'a>, InstructionError> {
        let index_in_transaction =
            self.get_index_of_program_account_in_transaction(program_account_index)?;
        self.try_borrow_account(
            transaction_context,
            index_in_transaction,
            program_account_index,
        )
    }

    /// Gets an instruction account of this Instruction
    pub fn try_borrow_instruction_account<'a, 'b: 'a>(
        &'a self,
        transaction_context: &'b TransactionContext,
        instruction_account_index: IndexOfAccount,
    ) -> Result<BorrowedAccount<'a>, InstructionError> {
        let index_in_transaction =
            self.get_index_of_instruction_account_in_transaction(instruction_account_index)?;
        self.try_borrow_account(
            transaction_context,
            index_in_transaction,
            self.get_number_of_program_accounts()
                .saturating_add(instruction_account_index),
        )
    }

    /// Returns whether an instruction account is a signer
    pub fn is_instruction_account_signer(
        &self,
        instruction_account_index: IndexOfAccount,
    ) -> Result<bool, InstructionError> {
        Ok(self
            .instruction_accounts
            .get(instruction_account_index as usize)
            .ok_or(InstructionError::MissingAccount)?
            .is_signer)
    }

    /// Returns whether an instruction account is writable
    pub fn is_instruction_account_writable(
        &self,
        instruction_account_index: IndexOfAccount,
    ) -> Result<bool, InstructionError> {
        Ok(self
            .instruction_accounts
            .get(instruction_account_index as usize)
            .ok_or(InstructionError::MissingAccount)?
            .is_writable)
    }

    /// Calculates the set of all keys of signer instruction accounts in this Instruction
    pub fn get_signers(
        &self,
        transaction_context: &TransactionContext,
    ) -> Result<HashSet<Pubkey>, InstructionError> {
        let mut result = HashSet::new();
        for instruction_account in self.instruction_accounts.iter() {
            if instruction_account.is_signer {
                result.insert(
                    *transaction_context
                        .get_key_of_account_at_index(instruction_account.index_in_transaction)?,
                );
            }
        }
        Ok(result)
    }
}

/// Loaded transaction shared between runtime and programs.
///
/// This context is valid for the entire duration of a transaction being processed.
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
    #[cfg(not(target_os = "solana"))]
    remove_accounts_executable_flag_checks: bool,
    #[cfg(not(target_os = "solana"))]
    rent: Rent,
    /// Useful for debugging to filter by or to look it up on the explorer
    #[cfg(all(
        not(target_os = "solana"),
        feature = "debug-signature",
        debug_assertions
    ))]
    signature: Signature,
}

impl TransactionContext {
    /// Constructs a new TransactionContext
    #[cfg(not(target_os = "solana"))]
    pub fn new(
        transaction_accounts: Vec<TransactionAccount>,
        rent: Rent,
        instruction_stack_capacity: usize,
        instruction_trace_capacity: usize,
    ) -> Self {
        let (account_keys, accounts): (Vec<_>, Vec<_>) = transaction_accounts
            .into_iter()
            .map(|(key, account)| (key, RefCell::new(account)))
            .unzip();
        Self {
            account_keys: Pin::new(account_keys.into_boxed_slice()),
            accounts: Rc::new(TransactionAccounts::new(accounts)),
            instruction_stack_capacity,
            instruction_trace_capacity,
            instruction_stack: Vec::with_capacity(instruction_stack_capacity),
            instruction_trace: vec![InstructionContext::default()],
            return_data: TransactionReturnData::default(),
            accounts_resize_delta: RefCell::new(0),
            remove_accounts_executable_flag_checks: true,
            rent,
            #[cfg(all(
                not(target_os = "solana"),
                feature = "debug-signature",
                debug_assertions
            ))]
            signature: Signature::default(),
        }
    }

    #[cfg(not(target_os = "solana"))]
    pub fn set_remove_accounts_executable_flag_checks(&mut self, enabled: bool) {
        self.remove_accounts_executable_flag_checks = enabled;
    }

    /// Used in mock_process_instruction
    #[cfg(not(target_os = "solana"))]
    pub fn deconstruct_without_keys(self) -> Result<Vec<AccountSharedData>, InstructionError> {
        if !self.instruction_stack.is_empty() {
            return Err(InstructionError::CallDepth);
        }

        Ok(Rc::try_unwrap(self.accounts)
            .expect("transaction_context.accounts has unexpected outstanding refs")
            .into_accounts())
    }

    #[cfg(not(target_os = "solana"))]
    pub fn accounts(&self) -> &Rc<TransactionAccounts> {
        &self.accounts
    }

    /// Stores the signature of the current transaction
    #[cfg(all(
        not(target_os = "solana"),
        feature = "debug-signature",
        debug_assertions
    ))]
    pub fn set_signature(&mut self, signature: &Signature) {
        self.signature = *signature;
    }

    /// Returns the signature of the current transaction
    #[cfg(all(
        not(target_os = "solana"),
        feature = "debug-signature",
        debug_assertions
    ))]
    pub fn get_signature(&self) -> &Signature {
        &self.signature
    }

    /// Returns the total number of accounts loaded in this Transaction
    pub fn get_number_of_accounts(&self) -> IndexOfAccount {
        self.accounts.len() as IndexOfAccount
    }

    /// Searches for an account by its key
    pub fn get_key_of_account_at_index(
        &self,
        index_in_transaction: IndexOfAccount,
    ) -> Result<&Pubkey, InstructionError> {
        self.account_keys
            .get(index_in_transaction as usize)
            .ok_or(InstructionError::NotEnoughAccountKeys)
    }

    /// Searches for an account by its key
    #[cfg(not(target_os = "solana"))]
    pub fn get_account_at_index(
        &self,
        index_in_transaction: IndexOfAccount,
    ) -> Result<&RefCell<AccountSharedData>, InstructionError> {
        self.accounts
            .get(index_in_transaction)
            .ok_or(InstructionError::NotEnoughAccountKeys)
    }

    /// Searches for an account by its key
    pub fn find_index_of_account(&self, pubkey: &Pubkey) -> Option<IndexOfAccount> {
        self.account_keys
            .iter()
            .position(|key| key == pubkey)
            .map(|index| index as IndexOfAccount)
    }

    /// Searches for a program account by its key
    pub fn find_index_of_program_account(&self, pubkey: &Pubkey) -> Option<IndexOfAccount> {
        self.account_keys
            .iter()
            .rposition(|key| key == pubkey)
            .map(|index| index as IndexOfAccount)
    }

    /// Gets the max length of the InstructionContext trace
    pub fn get_instruction_trace_capacity(&self) -> usize {
        self.instruction_trace_capacity
    }

    /// Returns the instruction trace length.
    ///
    /// Not counting the last empty InstructionContext which is always pre-reserved for the next instruction.
    /// See also `get_next_instruction_context()`.
    pub fn get_instruction_trace_length(&self) -> usize {
        self.instruction_trace.len().saturating_sub(1)
    }

    /// Gets an InstructionContext by its index in the trace
    pub fn get_instruction_context_at_index_in_trace(
        &self,
        index_in_trace: usize,
    ) -> Result<&InstructionContext, InstructionError> {
        self.instruction_trace
            .get(index_in_trace)
            .ok_or(InstructionError::CallDepth)
    }

    /// Gets an InstructionContext by its nesting level in the stack
    pub fn get_instruction_context_at_nesting_level(
        &self,
        nesting_level: usize,
    ) -> Result<&InstructionContext, InstructionError> {
        let index_in_trace = *self
            .instruction_stack
            .get(nesting_level)
            .ok_or(InstructionError::CallDepth)?;
        let instruction_context = self.get_instruction_context_at_index_in_trace(index_in_trace)?;
        debug_assert_eq!(instruction_context.nesting_level, nesting_level);
        Ok(instruction_context)
    }

    /// Gets the max height of the InstructionContext stack
    pub fn get_instruction_stack_capacity(&self) -> usize {
        self.instruction_stack_capacity
    }

    /// Gets instruction stack height, top-level instructions are height
    /// `solana_sdk::instruction::TRANSACTION_LEVEL_STACK_HEIGHT`
    pub fn get_instruction_context_stack_height(&self) -> usize {
        self.instruction_stack.len()
    }

    /// Returns the current InstructionContext
    pub fn get_current_instruction_context(&self) -> Result<&InstructionContext, InstructionError> {
        let level = self
            .get_instruction_context_stack_height()
            .checked_sub(1)
            .ok_or(InstructionError::CallDepth)?;
        self.get_instruction_context_at_nesting_level(level)
    }

    /// Returns the InstructionContext to configure for the next invocation.
    ///
    /// The last InstructionContext is always empty and pre-reserved for the next instruction.
    pub fn get_next_instruction_context(
        &mut self,
    ) -> Result<&mut InstructionContext, InstructionError> {
        self.instruction_trace
            .last_mut()
            .ok_or(InstructionError::CallDepth)
    }

    /// Pushes the next InstructionContext
    #[cfg(not(target_os = "solana"))]
    pub fn push(&mut self) -> Result<(), InstructionError> {
        let nesting_level = self.get_instruction_context_stack_height();
        let caller_instruction_context = self
            .instruction_trace
            .last()
            .ok_or(InstructionError::CallDepth)?;
        let callee_instruction_accounts_lamport_sum =
            self.instruction_accounts_lamport_sum(caller_instruction_context)?;
        if !self.instruction_stack.is_empty() {
            let caller_instruction_context = self.get_current_instruction_context()?;
            let original_caller_instruction_accounts_lamport_sum =
                caller_instruction_context.instruction_accounts_lamport_sum;
            let current_caller_instruction_accounts_lamport_sum =
                self.instruction_accounts_lamport_sum(caller_instruction_context)?;
            if original_caller_instruction_accounts_lamport_sum
                != current_caller_instruction_accounts_lamport_sum
            {
                return Err(InstructionError::UnbalancedInstruction);
            }
        }
        {
            let instruction_context = self.get_next_instruction_context()?;
            instruction_context.nesting_level = nesting_level;
            instruction_context.instruction_accounts_lamport_sum =
                callee_instruction_accounts_lamport_sum;
        }
        let index_in_trace = self.get_instruction_trace_length();
        if index_in_trace >= self.instruction_trace_capacity {
            return Err(InstructionError::MaxInstructionTraceLengthExceeded);
        }
        self.instruction_trace.push(InstructionContext::default());
        if nesting_level >= self.instruction_stack_capacity {
            return Err(InstructionError::CallDepth);
        }
        self.instruction_stack.push(index_in_trace);
        Ok(())
    }

    /// Pops the current InstructionContext
    #[cfg(not(target_os = "solana"))]
    pub fn pop(&mut self) -> Result<(), InstructionError> {
        if self.instruction_stack.is_empty() {
            return Err(InstructionError::CallDepth);
        }
        // Verify (before we pop) that the total sum of all lamports in this instruction did not change
        let detected_an_unbalanced_instruction =
            self.get_current_instruction_context()
                .and_then(|instruction_context| {
                    // Verify all executable accounts have no outstanding refs
                    for account_index in instruction_context.program_accounts.iter() {
                        self.get_account_at_index(*account_index)?
                            .try_borrow_mut()
                            .map_err(|_| InstructionError::AccountBorrowOutstanding)?;
                    }
                    self.instruction_accounts_lamport_sum(instruction_context)
                        .map(|instruction_accounts_lamport_sum| {
                            instruction_context.instruction_accounts_lamport_sum
                                != instruction_accounts_lamport_sum
                        })
                });
        // Always pop, even if we `detected_an_unbalanced_instruction`
        self.instruction_stack.pop();
        if detected_an_unbalanced_instruction? {
            Err(InstructionError::UnbalancedInstruction)
        } else {
            Ok(())
        }
    }

    /// Gets the return data of the current InstructionContext or any above
    pub fn get_return_data(&self) -> (&Pubkey, &[u8]) {
        (&self.return_data.program_id, &self.return_data.data)
    }

    /// Set the return data of the current InstructionContext
    pub fn set_return_data(
        &mut self,
        program_id: Pubkey,
        data: Vec<u8>,
    ) -> Result<(), InstructionError> {
        self.return_data = TransactionReturnData { program_id, data };
        Ok(())
    }

    /// Calculates the sum of all lamports within an instruction
    #[cfg(not(target_os = "solana"))]
    fn instruction_accounts_lamport_sum(
        &self,
        instruction_context: &InstructionContext,
    ) -> Result<u128, InstructionError> {
        let mut instruction_accounts_lamport_sum: u128 = 0;
        for instruction_account_index in 0..instruction_context.get_number_of_instruction_accounts()
        {
            if instruction_context
                .is_instruction_account_duplicate(instruction_account_index)?
                .is_some()
            {
                continue; // Skip duplicate account
            }
            let index_in_transaction = instruction_context
                .get_index_of_instruction_account_in_transaction(instruction_account_index)?;
            instruction_accounts_lamport_sum = (self
                .get_account_at_index(index_in_transaction)?
                .try_borrow()
                .map_err(|_| InstructionError::AccountBorrowOutstanding)?
                .lamports() as u128)
                .checked_add(instruction_accounts_lamport_sum)
                .ok_or(InstructionError::ArithmeticOverflow)?;
        }
        Ok(instruction_accounts_lamport_sum)
    }

    /// Returns the accounts resize delta
    pub fn accounts_resize_delta(&self) -> Result<i64, InstructionError> {
        self.accounts_resize_delta
            .try_borrow()
            .map_err(|_| InstructionError::GenericError)
            .map(|value_ref| *value_ref)
    }
}

/// Shared account borrowed from the TransactionContext and an InstructionContext.
#[derive(Debug)]
pub struct BorrowedAccount<'a> {
    transaction_context: &'a TransactionContext,
    instruction_context: &'a InstructionContext,
    index_in_transaction: IndexOfAccount,
    index_in_instruction: IndexOfAccount,
    account: RefMut<'a, AccountSharedData>,
}

impl BorrowedAccount<'_> {
    /// Returns the transaction context
    pub fn transaction_context(&self) -> &TransactionContext {
        self.transaction_context
    }

    /// Returns the index of this account (transaction wide)
    #[inline]
    pub fn get_index_in_transaction(&self) -> IndexOfAccount {
        self.index_in_transaction
    }

    /// Returns the public key of this account (transaction wide)
    #[inline]
    pub fn get_key(&self) -> &Pubkey {
        self.transaction_context
            .get_key_of_account_at_index(self.index_in_transaction)
            .unwrap()
    }

    /// Returns the owner of this account (transaction wide)
    #[inline]
    pub fn get_owner(&self) -> &Pubkey {
        self.account.owner()
    }

    /// Assignes the owner of this account (transaction wide)
    #[cfg(not(target_os = "solana"))]
    pub fn set_owner(&mut self, pubkey: &[u8]) -> Result<(), InstructionError> {
        // Only the owner can assign a new owner
        if !self.is_owned_by_current_program() {
            return Err(InstructionError::ModifiedProgramId);
        }
        // and only if the account is writable
        if !self.is_writable() {
            return Err(InstructionError::ModifiedProgramId);
        }
        // and only if the account is not executable
        if self.is_executable_internal() {
            return Err(InstructionError::ModifiedProgramId);
        }
        // and only if the data is zero-initialized or empty
        if !is_zeroed(self.get_data()) {
            return Err(InstructionError::ModifiedProgramId);
        }
        // don't touch the account if the owner does not change
        if self.get_owner().to_bytes() == pubkey {
            return Ok(());
        }
        self.touch()?;
        self.account.copy_into_owner_from_slice(pubkey);
        Ok(())
    }

    /// Returns the number of lamports of this account (transaction wide)
    #[inline]
    pub fn get_lamports(&self) -> u64 {
        self.account.lamports()
    }

    /// Overwrites the number of lamports of this account (transaction wide)
    #[cfg(not(target_os = "solana"))]
    pub fn set_lamports(&mut self, lamports: u64) -> Result<(), InstructionError> {
        // An account not owned by the program cannot have its balance decrease
        if !self.is_owned_by_current_program() && lamports < self.get_lamports() {
            return Err(InstructionError::ExternalAccountLamportSpend);
        }
        // The balance of read-only may not change
        if !self.is_writable() {
            return Err(InstructionError::ReadonlyLamportChange);
        }
        // The balance of executable accounts may not change
        if self.is_executable_internal() {
            return Err(InstructionError::ExecutableLamportChange);
        }
        // don't touch the account if the lamports do not change
        if self.get_lamports() == lamports {
            return Ok(());
        }
        self.touch()?;
        self.account.set_lamports(lamports);
        Ok(())
    }

    /// Adds lamports to this account (transaction wide)
    #[cfg(not(target_os = "solana"))]
    pub fn checked_add_lamports(&mut self, lamports: u64) -> Result<(), InstructionError> {
        self.set_lamports(
            self.get_lamports()
                .checked_add(lamports)
                .ok_or(InstructionError::ArithmeticOverflow)?,
        )
    }

    /// Subtracts lamports from this account (transaction wide)
    #[cfg(not(target_os = "solana"))]
    pub fn checked_sub_lamports(&mut self, lamports: u64) -> Result<(), InstructionError> {
        self.set_lamports(
            self.get_lamports()
                .checked_sub(lamports)
                .ok_or(InstructionError::ArithmeticOverflow)?,
        )
    }

    /// Returns a read-only slice of the account data (transaction wide)
    #[inline]
    pub fn get_data(&self) -> &[u8] {
        self.account.data()
    }

    /// Returns a writable slice of the account data (transaction wide)
    #[cfg(not(target_os = "solana"))]
    pub fn get_data_mut(&mut self) -> Result<&mut [u8], InstructionError> {
        self.can_data_be_changed()?;
        self.touch()?;
        self.make_data_mut();
        Ok(self.account.data_as_mut_slice())
    }

    /// Returns the spare capacity of the vector backing the account data.
    ///
    /// This method should only ever be used during CPI, where after a shrinking
    /// realloc we want to zero the spare capacity.
    #[cfg(not(target_os = "solana"))]
    pub fn spare_data_capacity_mut(&mut self) -> Result<&mut [MaybeUninit<u8>], InstructionError> {
        debug_assert!(!self.account.is_shared());
        Ok(self.account.spare_data_capacity_mut())
    }

    /// Overwrites the account data and size (transaction wide).
    ///
    /// You should always prefer set_data_from_slice(). Calling this method is
    /// currently safe but requires some special casing during CPI when direct
    /// account mapping is enabled.
    #[cfg(all(
        not(target_os = "solana"),
        any(test, feature = "dev-context-only-utils")
    ))]
    pub fn set_data(&mut self, data: Vec<u8>) -> Result<(), InstructionError> {
        self.can_data_be_resized(data.len())?;
        self.can_data_be_changed()?;
        self.touch()?;

        self.update_accounts_resize_delta(data.len())?;
        self.account.set_data(data);
        Ok(())
    }

    /// Overwrites the account data and size (transaction wide).
    ///
    /// Call this when you have a slice of data you do not own and want to
    /// replace the account data with it.
    #[cfg(not(target_os = "solana"))]
    pub fn set_data_from_slice(&mut self, data: &[u8]) -> Result<(), InstructionError> {
        self.can_data_be_resized(data.len())?;
        self.can_data_be_changed()?;
        self.touch()?;
        self.update_accounts_resize_delta(data.len())?;
        // Note that we intentionally don't call self.make_data_mut() here.  make_data_mut() will
        // allocate + memcpy the current data if self.account is shared. We don't need the memcpy
        // here tho because account.set_data_from_slice(data) is going to replace the content
        // anyway.
        self.account.set_data_from_slice(data);

        Ok(())
    }

    /// Resizes the account data (transaction wide)
    ///
    /// Fills it with zeros at the end if is extended or truncates at the end otherwise.
    #[cfg(not(target_os = "solana"))]
    pub fn set_data_length(&mut self, new_length: usize) -> Result<(), InstructionError> {
        self.can_data_be_resized(new_length)?;
        self.can_data_be_changed()?;
        // don't touch the account if the length does not change
        if self.get_data().len() == new_length {
            return Ok(());
        }
        self.touch()?;
        self.update_accounts_resize_delta(new_length)?;
        self.account.resize(new_length, 0);
        Ok(())
    }

    /// Appends all elements in a slice to the account
    pub fn extend_from_slice(&mut self, data: &[u8]) -> Result<(), InstructionError> {
        let new_len = self.get_data().len().saturating_add(data.len());
        self.can_data_be_resized(new_len)?;
        self.can_data_be_changed()?;

        if data.is_empty() {
            return Ok(());
        }

        self.touch()?;
        self.update_accounts_resize_delta(new_len)?;
        // Even if extend_from_slice never reduces capacity, still realloc using
        // make_data_mut() if necessary so that we grow the account of the full
        // max realloc length in one go, avoiding smaller reallocations.
        self.make_data_mut();
        self.account.extend_from_slice(data);
        Ok(())
    }

    /// Reserves capacity for at least additional more elements to be inserted
    /// in the given account. Does nothing if capacity is already sufficient.
    pub fn reserve(&mut self, additional: usize) -> Result<(), InstructionError> {
        // Note that we don't need to call can_data_be_changed() here nor
        // touch() the account. reserve() only changes the capacity of the
        // memory that holds the account but it doesn't actually change content
        // nor length of the account.
        self.make_data_mut();
        self.account.reserve(additional);

        Ok(())
    }

    /// Returns the number of bytes the account can hold without reallocating.
    pub fn capacity(&self) -> usize {
        self.account.capacity()
    }

    /// Returns whether the underlying AccountSharedData is shared.
    ///
    /// The data is shared if the account has been loaded from the accounts database and has never
    /// been written to. Writing to an account unshares it.
    ///
    /// During account serialization, if an account is shared it'll get mapped as CoW, else it'll
    /// get mapped directly as writable.
    #[cfg(not(target_os = "solana"))]
    pub fn is_shared(&self) -> bool {
        self.account.is_shared()
    }

    #[cfg(not(target_os = "solana"))]
    fn make_data_mut(&mut self) {
        // if the account is still shared, it means this is the first time we're
        // about to write into it. Make the account mutable by copying it in a
        // buffer with MAX_PERMITTED_DATA_INCREASE capacity so that if the
        // transaction reallocs, we don't have to copy the whole account data a
        // second time to fullfill the realloc.
        //
        // NOTE: The account memory region CoW code in bpf_loader::create_vm() implements the same
        // logic and must be kept in sync.
        if self.account.is_shared() {
            self.account.reserve(MAX_PERMITTED_DATA_INCREASE);
        }
    }

    /// Deserializes the account data into a state
    #[cfg(all(not(target_os = "solana"), feature = "bincode"))]
    pub fn get_state<T: serde::de::DeserializeOwned>(&self) -> Result<T, InstructionError> {
        self.account
            .deserialize_data()
            .map_err(|_| InstructionError::InvalidAccountData)
    }

    /// Serializes a state into the account data
    #[cfg(all(not(target_os = "solana"), feature = "bincode"))]
    pub fn set_state<T: serde::Serialize>(&mut self, state: &T) -> Result<(), InstructionError> {
        let data = self.get_data_mut()?;
        let serialized_size =
            bincode::serialized_size(state).map_err(|_| InstructionError::GenericError)?;
        if serialized_size > data.len() as u64 {
            return Err(InstructionError::AccountDataTooSmall);
        }
        bincode::serialize_into(&mut *data, state).map_err(|_| InstructionError::GenericError)?;
        Ok(())
    }

    // Returns whether or the lamports currently in the account is sufficient for rent exemption should the
    // data be resized to the given size
    #[cfg(not(target_os = "solana"))]
    pub fn is_rent_exempt_at_data_length(&self, data_length: usize) -> bool {
        self.transaction_context
            .rent
            .is_exempt(self.get_lamports(), data_length)
    }

    /// Returns whether this account is executable (transaction wide)
    #[inline]
    #[deprecated(since = "2.1.0", note = "Use `get_owner` instead")]
    pub fn is_executable(&self) -> bool {
        self.account.executable()
    }

    /// Feature gating to remove `is_executable` flag related checks
    #[inline]
    fn is_executable_internal(&self) -> bool {
        !self
            .transaction_context
            .remove_accounts_executable_flag_checks
            && self.account.executable()
    }

    /// Configures whether this account is executable (transaction wide)
    pub fn set_executable(&mut self, is_executable: bool) -> Result<(), InstructionError> {
        // To become executable an account must be rent exempt
        if !self
            .transaction_context
            .rent
            .is_exempt(self.get_lamports(), self.get_data().len())
        {
            return Err(InstructionError::ExecutableAccountNotRentExempt);
        }
        // Only the owner can set the executable flag
        if !self.is_owned_by_current_program() {
            return Err(InstructionError::ExecutableModified);
        }
        // and only if the account is writable
        if !self.is_writable() {
            return Err(InstructionError::ExecutableModified);
        }
        // one can not clear the executable flag
        if self.is_executable_internal() && !is_executable {
            return Err(InstructionError::ExecutableModified);
        }
        // don't touch the account if the executable flag does not change
        #[allow(deprecated)]
        if self.is_executable() == is_executable {
            return Ok(());
        }
        self.touch()?;
        self.account.set_executable(is_executable);
        Ok(())
    }

    /// Returns the rent epoch of this account (transaction wide)
    #[cfg(not(target_os = "solana"))]
    #[inline]
    pub fn get_rent_epoch(&self) -> u64 {
        self.account.rent_epoch()
    }

    /// Returns whether this account is a signer (instruction wide)
    pub fn is_signer(&self) -> bool {
        if self.index_in_instruction < self.instruction_context.get_number_of_program_accounts() {
            return false;
        }
        self.instruction_context
            .is_instruction_account_signer(
                self.index_in_instruction
                    .saturating_sub(self.instruction_context.get_number_of_program_accounts()),
            )
            .unwrap_or_default()
    }

    /// Returns whether this account is writable (instruction wide)
    pub fn is_writable(&self) -> bool {
        if self.index_in_instruction < self.instruction_context.get_number_of_program_accounts() {
            return false;
        }
        self.instruction_context
            .is_instruction_account_writable(
                self.index_in_instruction
                    .saturating_sub(self.instruction_context.get_number_of_program_accounts()),
            )
            .unwrap_or_default()
    }

    /// Returns true if the owner of this account is the current `InstructionContext`s last program (instruction wide)
    pub fn is_owned_by_current_program(&self) -> bool {
        self.instruction_context
            .get_last_program_key(self.transaction_context)
            .map(|key| key == self.get_owner())
            .unwrap_or_default()
    }

    /// Returns an error if the account data can not be mutated by the current program
    #[cfg(not(target_os = "solana"))]
    pub fn can_data_be_changed(&self) -> Result<(), InstructionError> {
        // Only non-executable accounts data can be changed
        if self.is_executable_internal() {
            return Err(InstructionError::ExecutableDataModified);
        }
        // and only if the account is writable
        if !self.is_writable() {
            return Err(InstructionError::ReadonlyDataModified);
        }
        // and only if we are the owner
        if !self.is_owned_by_current_program() {
            return Err(InstructionError::ExternalAccountDataModified);
        }
        Ok(())
    }

    /// Returns an error if the account data can not be resized to the given length
    #[cfg(not(target_os = "solana"))]
    pub fn can_data_be_resized(&self, new_length: usize) -> Result<(), InstructionError> {
        let old_length = self.get_data().len();
        // Only the owner can change the length of the data
        if new_length != old_length && !self.is_owned_by_current_program() {
            return Err(InstructionError::AccountDataSizeChanged);
        }
        // The new length can not exceed the maximum permitted length
        if new_length > MAX_PERMITTED_DATA_LENGTH as usize {
            return Err(InstructionError::InvalidRealloc);
        }
        // The resize can not exceed the per-transaction maximum
        let length_delta = (new_length as i64).saturating_sub(old_length as i64);
        if self
            .transaction_context
            .accounts_resize_delta()?
            .saturating_add(length_delta)
            > MAX_PERMITTED_ACCOUNTS_DATA_ALLOCATIONS_PER_TRANSACTION
        {
            return Err(InstructionError::MaxAccountsDataAllocationsExceeded);
        }
        Ok(())
    }

    #[cfg(not(target_os = "solana"))]
    fn touch(&self) -> Result<(), InstructionError> {
        self.transaction_context
            .accounts()
            .touch(self.index_in_transaction)
    }

    #[cfg(not(target_os = "solana"))]
    fn update_accounts_resize_delta(&mut self, new_len: usize) -> Result<(), InstructionError> {
        let mut accounts_resize_delta = self
            .transaction_context
            .accounts_resize_delta
            .try_borrow_mut()
            .map_err(|_| InstructionError::GenericError)?;
        *accounts_resize_delta = accounts_resize_delta
            .saturating_add((new_len as i64).saturating_sub(self.get_data().len() as i64));
        Ok(())
    }
}

fn is_zeroed(buf: &[u8]) -> bool {
    const ZEROS_LEN: usize = 1024;
    const ZEROS: [u8; ZEROS_LEN] = [0; ZEROS_LEN];
    let mut chunks = buf.chunks_exact(ZEROS_LEN);

    #[allow(clippy::indexing_slicing)]
    {
        chunks.all(|chunk| chunk == &ZEROS[..])
            && chunks.remainder() == &ZEROS[..chunks.remainder().len()]
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum TransactionError {
    /// An account is already being processed in another transaction in a way
    /// that does not support parallelism
    AccountInUse,

    /// A `Pubkey` appears twice in the transaction's `account_keys`.  Instructions can reference
    /// `Pubkey`s more than once but the message must contain a list with no duplicate keys
    AccountLoadedTwice,

    /// Attempt to debit an account but found no record of a prior credit.
    AccountNotFound,

    /// Attempt to load a program that does not exist
    ProgramAccountNotFound,

    /// The from `Pubkey` does not have sufficient balance to pay the fee to schedule the transaction
    InsufficientFundsForFee,

    /// This account may not be used to pay transaction fees
    InvalidAccountForFee,

    /// The bank has seen this transaction before. This can occur under normal operation
    /// when a UDP packet is duplicated, as a user error from a client not updating
    /// its `recent_blockhash`, or as a double-spend attack.
    AlreadyProcessed,

    /// The bank has not seen the given `recent_blockhash` or the transaction is too old and
    /// the `recent_blockhash` has been discarded.
    BlockhashNotFound,

    /// An error occurred while processing an instruction. The first element of the tuple
    /// indicates the instruction index in which the error occurred.
    InstructionError(u8, InstructionError),

    /// Loader call chain is too deep
    CallChainTooDeep,

    /// Transaction requires a fee but has no signature present
    MissingSignatureForFee,

    /// Transaction contains an invalid account reference
    InvalidAccountIndex,

    /// Transaction did not pass signature verification
    SignatureFailure,

    /// This program may not be used for executing instructions
    InvalidProgramForExecution,

    /// Transaction failed to sanitize accounts offsets correctly
    /// implies that account locks are not taken for this TX, and should
    /// not be unlocked.
    SanitizeFailure,

    ClusterMaintenance,

    /// Transaction processing left an account with an outstanding borrowed reference
    AccountBorrowOutstanding,

    /// Transaction would exceed max Block Cost Limit
    WouldExceedMaxBlockCostLimit,

    /// Transaction version is unsupported
    UnsupportedVersion,

    /// Transaction loads a writable account that cannot be written
    InvalidWritableAccount,

    /// Transaction would exceed max account limit within the block
    WouldExceedMaxAccountCostLimit,

    /// Transaction would exceed account data limit within the block
    WouldExceedAccountDataBlockLimit,

    /// Transaction locked too many accounts
    TooManyAccountLocks,

    /// Address lookup table not found
    AddressLookupTableNotFound,

    /// Attempted to lookup addresses from an account owned by the wrong program
    InvalidAddressLookupTableOwner,

    /// Attempted to lookup addresses from an invalid account
    InvalidAddressLookupTableData,

    /// Address table lookup uses an invalid index
    InvalidAddressLookupTableIndex,

    /// Transaction leaves an account with a lower balance than rent-exempt minimum
    InvalidRentPayingAccount,

    /// Transaction would exceed max Vote Cost Limit
    WouldExceedMaxVoteCostLimit,

    /// Transaction would exceed total account data limit
    WouldExceedAccountDataTotalLimit,

    /// Transaction contains a duplicate instruction that is not allowed
    DuplicateInstruction(u8),

    /// Transaction results in an account with insufficient funds for rent
    InsufficientFundsForRent {
        account_index: u8,
    },

    /// Transaction exceeded max loaded accounts data size cap
    MaxLoadedAccountsDataSizeExceeded,

    /// LoadedAccountsDataSizeLimit set for transaction must be greater than 0.
    InvalidLoadedAccountsDataSizeLimit,

    /// Sanitized transaction differed before/after feature activiation. Needs to be resanitized.
    ResanitizationNeeded,

    /// Program execution is temporarily restricted on an account.
    ProgramExecutionTemporarilyRestricted {
        account_index: u8,
    },

    /// The total balance before the transaction does not equal the total balance after the transaction
    UnbalancedTransaction,

    /// Program cache hit max limit.
    ProgramCacheHitMaxLimit,

    /// Commit cancelled internally.
    CommitCancelled,
}

impl std::error::Error for TransactionError {}

impl fmt::Display for TransactionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::AccountInUse
             => f.write_str("Account in use"),
            Self::AccountLoadedTwice
             => f.write_str("Account loaded twice"),
            Self::AccountNotFound
             => f.write_str("Attempt to debit an account but found no record of a prior credit."),
            Self::ProgramAccountNotFound
             => f.write_str("Attempt to load a program that does not exist"),
            Self::InsufficientFundsForFee
             => f.write_str("Insufficient funds for fee"),
            Self::InvalidAccountForFee
             => f.write_str("This account may not be used to pay transaction fees"),
            Self::AlreadyProcessed
             => f.write_str("This transaction has already been processed"),
            Self::BlockhashNotFound
             => f.write_str("Blockhash not found"),
            Self::InstructionError(idx, err) =>  write!(f, "Error processing Instruction {idx}: {err}"),
            Self::CallChainTooDeep
             => f.write_str("Loader call chain is too deep"),
            Self::MissingSignatureForFee
             => f.write_str("Transaction requires a fee but has no signature present"),
            Self::InvalidAccountIndex
             => f.write_str("Transaction contains an invalid account reference"),
            Self::SignatureFailure
             => f.write_str("Transaction did not pass signature verification"),
            Self::InvalidProgramForExecution
             => f.write_str("This program may not be used for executing instructions"),
            Self::SanitizeFailure
             => f.write_str("Transaction failed to sanitize accounts offsets correctly"),
            Self::ClusterMaintenance
             => f.write_str("Transactions are currently disabled due to cluster maintenance"),
            Self::AccountBorrowOutstanding
             => f.write_str("Transaction processing left an account with an outstanding borrowed reference"),
            Self::WouldExceedMaxBlockCostLimit
             => f.write_str("Transaction would exceed max Block Cost Limit"),
            Self::UnsupportedVersion
             => f.write_str("Transaction version is unsupported"),
            Self::InvalidWritableAccount
             => f.write_str("Transaction loads a writable account that cannot be written"),
            Self::WouldExceedMaxAccountCostLimit
             => f.write_str("Transaction would exceed max account limit within the block"),
            Self::WouldExceedAccountDataBlockLimit
             => f.write_str("Transaction would exceed account data limit within the block"),
            Self::TooManyAccountLocks
             => f.write_str("Transaction locked too many accounts"),
            Self::AddressLookupTableNotFound
             => f.write_str("Transaction loads an address table account that doesn't exist"),
            Self::InvalidAddressLookupTableOwner
             => f.write_str("Transaction loads an address table account with an invalid owner"),
            Self::InvalidAddressLookupTableData
             => f.write_str("Transaction loads an address table account with invalid data"),
            Self::InvalidAddressLookupTableIndex
             => f.write_str("Transaction address table lookup uses an invalid index"),
            Self::InvalidRentPayingAccount
             => f.write_str("Transaction leaves an account with a lower balance than rent-exempt minimum"),
            Self::WouldExceedMaxVoteCostLimit
             => f.write_str("Transaction would exceed max Vote Cost Limit"),
            Self::WouldExceedAccountDataTotalLimit
             => f.write_str("Transaction would exceed total account data limit"),
            Self::DuplicateInstruction(idx) =>  write!(f, "Transaction contains a duplicate instruction ({idx}) that is not allowed"),
            Self::InsufficientFundsForRent {
                account_index
            } =>  write!(f,"Transaction results in an account ({account_index}) with insufficient funds for rent"),
            Self::MaxLoadedAccountsDataSizeExceeded
             => f.write_str("Transaction exceeded max loaded accounts data size cap"),
            Self::InvalidLoadedAccountsDataSizeLimit
             => f.write_str("LoadedAccountsDataSizeLimit set for transaction must be greater than 0."),
            Self::ResanitizationNeeded
             => f.write_str("ResanitizationNeeded"),
            Self::ProgramExecutionTemporarilyRestricted {
                account_index
            } =>  write!(f,"Execution of the program referenced by account at index {account_index} is temporarily restricted."),
            Self::UnbalancedTransaction
             => f.write_str("Sum of account balances before and after transaction do not match"),
            Self::ProgramCacheHitMaxLimit
             => f.write_str("Program cache hit max limit"),
            Self::CommitCancelled
             => f.write_str("CommitCancelled"),
        }
    }
}

impl From<SanitizeError> for TransactionError {
    fn from(_: SanitizeError) -> Self {
        Self::SanitizeFailure
    }
}

impl From<SanitizeMessageError> for TransactionError {
    fn from(err: SanitizeMessageError) -> Self {
        match err {
            SanitizeMessageError::AddressLoaderError(err) => Self::from(err),
            _ => Self::SanitizeFailure,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum AddressLoaderError {
    /// Address loading from lookup tables is disabled
    Disabled,

    /// Failed to load slot hashes sysvar
    SlotHashesSysvarNotFound,

    /// Attempted to lookup addresses from a table that does not exist
    LookupTableAccountNotFound,

    /// Attempted to lookup addresses from an account owned by the wrong program
    InvalidAccountOwner,

    /// Attempted to lookup addresses from an invalid account
    InvalidAccountData,

    /// Address lookup contains an invalid index
    InvalidLookupIndex,
}

impl std::error::Error for AddressLoaderError {}

impl fmt::Display for AddressLoaderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Disabled => f.write_str("Address loading from lookup tables is disabled"),
            Self::SlotHashesSysvarNotFound => f.write_str("Failed to load slot hashes sysvar"),
            Self::LookupTableAccountNotFound => {
                f.write_str("Attempted to lookup addresses from a table that does not exist")
            }
            Self::InvalidAccountOwner => f.write_str(
                "Attempted to lookup addresses from an account owned by the wrong program",
            ),
            Self::InvalidAccountData => {
                f.write_str("Attempted to lookup addresses from an invalid account")
            }
            Self::InvalidLookupIndex => f.write_str("Address lookup contains an invalid index"),
        }
    }
}

impl From<AddressLoaderError> for TransactionError {
    fn from(err: AddressLoaderError) -> Self {
        match err {
            AddressLoaderError::Disabled => Self::UnsupportedVersion,
            AddressLoaderError::SlotHashesSysvarNotFound => Self::AccountNotFound,
            AddressLoaderError::LookupTableAccountNotFound => Self::AddressLookupTableNotFound,
            AddressLoaderError::InvalidAccountOwner => Self::InvalidAddressLookupTableOwner,
            AddressLoaderError::InvalidAccountData => Self::InvalidAddressLookupTableData,
            AddressLoaderError::InvalidLookupIndex => Self::InvalidAddressLookupTableIndex,
        }
    }
}

#[derive(PartialEq, Debug, Eq, Clone)]
pub enum SanitizeMessageError {
    IndexOutOfBounds,
    ValueOutOfBounds,
    InvalidValue,
    AddressLoaderError(AddressLoaderError),
}

impl std::error::Error for SanitizeMessageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::IndexOutOfBounds => None,
            Self::ValueOutOfBounds => None,
            Self::InvalidValue => None,
            Self::AddressLoaderError(e) => Some(e),
        }
    }
}

impl fmt::Display for SanitizeMessageError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::IndexOutOfBounds => f.write_str("index out of bounds"),
            Self::ValueOutOfBounds => f.write_str("value out of bounds"),
            Self::InvalidValue => f.write_str("invalid value"),
            Self::AddressLoaderError(e) => {
                write!(f, "{e}")
            }
        }
    }
}

impl From<AddressLoaderError> for SanitizeMessageError {
    fn from(source: AddressLoaderError) -> Self {
        SanitizeMessageError::AddressLoaderError(source)
    }
}

impl From<SanitizeError> for SanitizeMessageError {
    fn from(err: SanitizeError) -> Self {
        match err {
            SanitizeError::IndexOutOfBounds => Self::IndexOutOfBounds,
            SanitizeError::ValueOutOfBounds => Self::ValueOutOfBounds,
            SanitizeError::InvalidValue => Self::InvalidValue,
        }
    }
}

#[derive(Debug)]
pub enum TransportError {
    IoError(std::io::Error),
    TransactionError(TransactionError),
    Custom(String),
}

impl std::error::Error for TransportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TransportError::IoError(e) => Some(e),
            TransportError::TransactionError(e) => Some(e),
            TransportError::Custom(_) => None,
        }
    }
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter) -> ::core::fmt::Result {
        match self {
            Self::IoError(e) => f.write_fmt(format_args!("transport io error: {e}")),
            Self::TransactionError(e) => {
                f.write_fmt(format_args!("transport transaction error: {e}"))
            }
            Self::Custom(s) => f.write_fmt(format_args!("transport custom error: {s}")),
        }
    }
}

impl From<std::io::Error> for TransportError {
    fn from(e: std::io::Error) -> Self {
        TransportError::IoError(e)
    }
}

impl From<TransactionError> for TransportError {
    fn from(e: TransactionError) -> Self {
        TransportError::TransactionError(e)
    }
}

impl TransportError {
    pub fn unwrap(&self) -> TransactionError {
        if let TransportError::TransactionError(err) = self {
            err.clone()
        } else {
            panic!("unexpected transport error")
        }
    }
}

pub type TransportResult<T> = std::result::Result<T, TransportError>;

/// Sanitized transaction and the hash of its message
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SanitizedTransaction {
    message: SanitizedMessage,
    message_hash: Hash,
    is_simple_vote_tx: bool,
    signatures: Vec<Signature>,
}

/// Set of accounts that must be locked for safe transaction processing
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct TransactionAccountLocks<'a> {
    /// List of readonly account key locks
    pub readonly: Vec<&'a Pubkey>,
    /// List of writable account key locks
    pub writable: Vec<&'a Pubkey>,
}

/// Type that represents whether the transaction message has been precomputed or
/// not.
pub enum MessageHash {
    Precomputed(Hash),
    Compute,
}

impl From<Hash> for MessageHash {
    fn from(hash: Hash) -> Self {
        Self::Precomputed(hash)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum Legacy {
    Legacy,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum TransactionVersion {
    Legacy(Legacy),
    Number(u8),
}

impl TransactionVersion {
    pub const LEGACY: Self = Self::Legacy(Legacy::Legacy);
}

pub const SIGNATURE_BYTES: usize = 64;
/// Maximum string length of a base58 encoded signature
const MAX_BASE58_SIGNATURE_LEN: usize = 88;

#[repr(transparent)]
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, core::hash::Hash, Deserialize, Serialize)]
pub struct Signature(#[serde(with = "BigArray")] [u8; SIGNATURE_BYTES]);

impl Default for Signature {
    fn default() -> Self {
        Self([0u8; 64])
    }
}

impl Sanitize for Signature {}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

fn write_as_base58(f: &mut fmt::Formatter, s: &Signature) -> fmt::Result {
    let mut out = [0u8; MAX_BASE58_SIGNATURE_LEN];
    let out_slice: &mut [u8] = &mut out;
    // This will never fail because the only possible error is BufferTooSmall,
    // and we will never call it with too small a buffer.
    let len = bs58::encode(s.0).onto(out_slice).unwrap();
    let as_str = from_utf8(&out[..len]).unwrap();
    f.write_str(as_str)
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write_as_base58(f, self)
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write_as_base58(f, self)
    }
}

impl From<Signature> for [u8; 64] {
    fn from(signature: Signature) -> Self {
        signature.0
    }
}

impl From<[u8; SIGNATURE_BYTES]> for Signature {
    #[inline]
    fn from(signature: [u8; SIGNATURE_BYTES]) -> Self {
        Self(signature)
    }
}

impl<'a> TryFrom<&'a [u8]> for Signature {
    type Error = <[u8; SIGNATURE_BYTES] as TryFrom<&'a [u8]>>::Error;

    #[inline]
    fn try_from(signature: &'a [u8]) -> Result<Self, Self::Error> {
        <[u8; SIGNATURE_BYTES]>::try_from(signature).map(Self::from)
    }
}

impl TryFrom<Vec<u8>> for Signature {
    type Error = <[u8; SIGNATURE_BYTES] as TryFrom<Vec<u8>>>::Error;

    #[inline]
    fn try_from(signature: Vec<u8>) -> Result<Self, Self::Error> {
        <[u8; SIGNATURE_BYTES]>::try_from(signature).map(Self::from)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseSignatureError {
    WrongSize,
    Invalid,
}

// impl Error for ParseSignatureError {}

impl fmt::Display for ParseSignatureError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ParseSignatureError::WrongSize => {
                f.write_str("string decoded to wrong size for signature")
            }
            ParseSignatureError::Invalid => f.write_str("failed to decode string to signature"),
        }
    }
}

impl FromStr for Signature {
    type Err = ParseSignatureError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() > MAX_BASE58_SIGNATURE_LEN {
            return Err(ParseSignatureError::WrongSize);
        }
        let mut bytes = [0; SIGNATURE_BYTES];
        let decoded_size = bs58::decode(s)
            .onto(&mut bytes)
            .map_err(|_| ParseSignatureError::Invalid)?;
        if decoded_size != SIGNATURE_BYTES {
            Err(ParseSignatureError::WrongSize)
        } else {
            Ok(bytes.into())
        }
    }
}

#[derive(Debug, PartialEq, Default, Eq, Clone, Deserialize, Serialize)]
pub struct Transaction {
    /// A set of signatures of a serialized [`Message`], signed by the first
    /// keys of the `Message`'s [`account_keys`], where the number of signatures
    /// is equal to [`num_required_signatures`] of the `Message`'s
    /// [`MessageHeader`].
    ///
    /// [`account_keys`]: https://docs.rs/solana-message/latest/solana_message/legacy/struct.Message.html#structfield.account_keys
    /// [`MessageHeader`]: https://docs.rs/solana-message/latest/solana_message/struct.MessageHeader.html
    /// [`num_required_signatures`]: https://docs.rs/solana-message/latest/solana_message/struct.MessageHeader.html#structfield.num_required_signatures
    // NOTE: Serialization-related changes must be paired with the direct read at sigverify.
    pub signatures: Vec<Signature>,

    /// The message to sign.
    pub message: legacy::Message,
}

impl Sanitize for Transaction {
    fn sanitize(&self) -> result::Result<(), SanitizeError> {
        if self.message.header.num_required_signatures as usize > self.signatures.len() {
            return Err(SanitizeError::IndexOutOfBounds);
        }
        if self.signatures.len() > self.message.account_keys.len() {
            return Err(SanitizeError::IndexOutOfBounds);
        }
        self.message.sanitize()
    }
}

impl Transaction {
    pub fn new_unsigned(message: legacy::Message) -> Self {
        Self {
            signatures: vec![Signature::default(); message.header.num_required_signatures as usize],
            message,
        }
    }

    // pub fn new<T: Signers + ?Sized>(
    //     from_keypairs: &T,
    //     message: Message,
    //     recent_blockhash: Hash,
    // ) -> Transaction {
    //     let mut tx = Self::new_unsigned(message);
    //     tx.sign(from_keypairs, recent_blockhash);
    //     tx
    // }

    pub fn new_with_payer(instructions: &[Instruction], payer: Option<&Pubkey>) -> Self {
        let message = legacy::Message::new(instructions, payer);
        Self::new_unsigned(message)
    }

    // pub fn new_signed_with_payer<T: Signers + ?Sized>(
    //     instructions: &[Instruction],
    //     payer: Option<&Pubkey>,
    //     signing_keypairs: &T,
    //     recent_blockhash: Hash,
    // ) -> Self {
    //     let message = Message::new(instructions, payer);
    //     Self::new(signing_keypairs, message, recent_blockhash)
    // }

    // pub fn new_with_compiled_instructions<T: Signers + ?Sized>(
    //     from_keypairs: &T,
    //     keys: &[Pubkey],
    //     recent_blockhash: Hash,
    //     program_ids: Vec<Pubkey>,
    //     instructions: Vec<CompiledInstruction>,
    // ) -> Self {
    //     let mut account_keys = from_keypairs.pubkeys();
    //     let from_keypairs_len = account_keys.len();
    //     account_keys.extend_from_slice(keys);
    //     account_keys.extend(&program_ids);
    //     let message = Message::new_with_compiled_instructions(
    //         from_keypairs_len as u8,
    //         0,
    //         program_ids.len() as u8,
    //         account_keys,
    //         Hash::default(),
    //         instructions,
    //     );
    //     Transaction::new(from_keypairs, message, recent_blockhash)
    // }

    pub fn data(&self, instruction_index: usize) -> &[u8] {
        &self.message.instructions[instruction_index].data
    }

    fn key_index(&self, instruction_index: usize, accounts_index: usize) -> Option<usize> {
        self.message
            .instructions
            .get(instruction_index)
            .and_then(|instruction| instruction.accounts.get(accounts_index))
            .map(|&account_keys_index| account_keys_index as usize)
    }

    pub fn key(&self, instruction_index: usize, accounts_index: usize) -> Option<&Pubkey> {
        self.key_index(instruction_index, accounts_index)
            .and_then(|account_keys_index| self.message.account_keys.get(account_keys_index))
    }

    pub fn signer_key(&self, instruction_index: usize, accounts_index: usize) -> Option<&Pubkey> {
        match self.key_index(instruction_index, accounts_index) {
            None => None,
            Some(signature_index) => {
                if signature_index >= self.signatures.len() {
                    return None;
                }
                self.message.account_keys.get(signature_index)
            }
        }
    }

    /// Return the message containing all data that should be signed.
    pub fn message(&self) -> &legacy::Message {
        &self.message
    }

    pub fn message_data(&self) -> Vec<u8> {
        self.message().serialize()
    }

    // pub fn sign<T: Signers + ?Sized>(&mut self, keypairs: &T, recent_blockhash: Hash) {
    //     if let Err(e) = self.try_sign(keypairs, recent_blockhash) {
    //         panic!("Transaction::sign failed with error {e:?}");
    //     }
    // }

    // pub fn partial_sign<T: Signers + ?Sized>(&mut self, keypairs: &T, recent_blockhash: Hash) {
    //     if let Err(e) = self.try_partial_sign(keypairs, recent_blockhash) {
    //         panic!("Transaction::partial_sign failed with error {e:?}");
    //     }
    // }

    // #[cfg(feature = "bincode")]
    // pub fn partial_sign_unchecked<T: Signers + ?Sized>(
    //     &mut self,
    //     keypairs: &T,
    //     positions: Vec<usize>,
    //     recent_blockhash: Hash,
    // ) {
    //     if let Err(e) = self.try_partial_sign_unchecked(keypairs, positions, recent_blockhash) {
    //         panic!("Transaction::partial_sign_unchecked failed with error {e:?}");
    //     }
    // }

    // #[cfg(feature = "bincode")]
    // pub fn try_sign<T: Signers + ?Sized>(
    //     &mut self,
    //     keypairs: &T,
    //     recent_blockhash: Hash,
    // ) -> result::Result<(), SignerError> {
    //     self.try_partial_sign(keypairs, recent_blockhash)?;

    //     if !self.is_signed() {
    //         Err(SignerError::NotEnoughSigners)
    //     } else {
    //         Ok(())
    //     }
    // }

    // #[cfg(feature = "bincode")]
    // pub fn try_partial_sign<T: Signers + ?Sized>(
    //     &mut self,
    //     keypairs: &T,
    //     recent_blockhash: Hash,
    // ) -> result::Result<(), SignerError> {
    //     let positions: Vec<usize> = self
    //         .get_signing_keypair_positions(&keypairs.pubkeys())?
    //         .into_iter()
    //         .collect::<Option<_>>()
    //         .ok_or(SignerError::KeypairPubkeyMismatch)?;
    //     self.try_partial_sign_unchecked(keypairs, positions, recent_blockhash)
    // }

    // /// Sign the transaction with a subset of required keys, returning any
    // /// errors.
    // ///
    // /// This places each of the signatures created from `keypairs` in the
    // /// corresponding position, as specified in the `positions` vector, in the
    // /// transactions [`signatures`] field. It does not verify that the signature
    // /// positions are correct.
    // ///
    // /// [`signatures`]: Transaction::signatures
    // ///
    // /// # Errors
    // ///
    // /// Returns an error if signing fails.
    // #[cfg(feature = "bincode")]
    // pub fn try_partial_sign_unchecked<T: Signers + ?Sized>(
    //     &mut self,
    //     keypairs: &T,
    //     positions: Vec<usize>,
    //     recent_blockhash: Hash,
    // ) -> result::Result<(), SignerError> {
    //     // if you change the blockhash, you're re-signing...
    //     if recent_blockhash != self.message.recent_blockhash {
    //         self.message.recent_blockhash = recent_blockhash;
    //         self.signatures
    //             .iter_mut()
    //             .for_each(|signature| *signature = Signature::default());
    //     }

    //     let signatures = keypairs.try_sign_message(&self.message_data())?;
    //     for i in 0..positions.len() {
    //         self.signatures[positions[i]] = signatures[i];
    //     }
    //     Ok(())
    // }

    /// Returns a signature that is not valid for signing this transaction.
    pub fn get_invalid_signature() -> Signature {
        Signature::default()
    }

    /// Get the positions of the pubkeys in `account_keys` associated with signing keypairs.
    ///
    /// [`account_keys`]: Message::account_keys
    pub fn get_signing_keypair_positions(
        &self,
        pubkeys: &[Pubkey],
    ) -> Result<Vec<Option<usize>>, TransactionError> {
        if self.message.account_keys.len() < self.message.header.num_required_signatures as usize {
            return Err(TransactionError::InvalidAccountIndex);
        }
        let signed_keys =
            &self.message.account_keys[0..self.message.header.num_required_signatures as usize];

        Ok(pubkeys
            .iter()
            .map(|pubkey| signed_keys.iter().position(|x| x == pubkey))
            .collect())
    }

    pub fn is_signed(&self) -> bool {
        self.signatures
            .iter()
            .all(|signature| *signature != Signature::default())
    }
}

#[derive(Debug, PartialEq, Default, Eq, Clone)]
pub struct VersionedTransaction {
    /// List of signatures
    pub signatures: Vec<Signature>,
    /// Message to sign.
    pub message: VersionedMessage,
}

impl From<Transaction> for VersionedTransaction {
    fn from(transaction: Transaction) -> Self {
        Self {
            signatures: transaction.signatures,
            message: VersionedMessage::Legacy(transaction.message),
        }
    }
}

impl VersionedTransaction {
    /// Signs a versioned message and if successful, returns a signed
    /// transaction.
    #[cfg(feature = "bincode")]
    pub fn try_new<T: Signers + ?Sized>(
        message: VersionedMessage,
        keypairs: &T,
    ) -> std::result::Result<Self, SignerError> {
        let static_account_keys = message.static_account_keys();
        if static_account_keys.len() < message.header().num_required_signatures as usize {
            return Err(SignerError::InvalidInput("invalid message".to_string()));
        }

        let signer_keys = keypairs.try_pubkeys()?;
        let expected_signer_keys =
            &static_account_keys[0..message.header().num_required_signatures as usize];

        match signer_keys.len().cmp(&expected_signer_keys.len()) {
            Ordering::Greater => Err(SignerError::TooManySigners),
            Ordering::Less => Err(SignerError::NotEnoughSigners),
            Ordering::Equal => Ok(()),
        }?;

        let message_data = message.serialize();
        let signature_indexes: Vec<usize> = expected_signer_keys
            .iter()
            .map(|signer_key| {
                signer_keys
                    .iter()
                    .position(|key| key == signer_key)
                    .ok_or(SignerError::KeypairPubkeyMismatch)
            })
            .collect::<std::result::Result<_, SignerError>>()?;

        let unordered_signatures = keypairs.try_sign_message(&message_data)?;
        let signatures: Vec<Signature> = signature_indexes
            .into_iter()
            .map(|index| {
                unordered_signatures
                    .get(index)
                    .copied()
                    .ok_or_else(|| SignerError::InvalidInput("invalid keypairs".to_string()))
            })
            .collect::<std::result::Result<_, SignerError>>()?;

        Ok(Self {
            signatures,
            message,
        })
    }

    pub fn sanitize(&self) -> std::result::Result<(), SanitizeError> {
        self.message.sanitize()?;
        self.sanitize_signatures()?;
        Ok(())
    }

    pub(crate) fn sanitize_signatures(&self) -> std::result::Result<(), SanitizeError> {
        Self::sanitize_signatures_inner(
            usize::from(self.message.header().num_required_signatures),
            self.message.static_account_keys().len(),
            self.signatures.len(),
        )
    }

    pub(crate) fn sanitize_signatures_inner(
        num_required_signatures: usize,
        num_static_account_keys: usize,
        num_signatures: usize,
    ) -> std::result::Result<(), SanitizeError> {
        match num_required_signatures.cmp(&num_signatures) {
            Ordering::Greater => Err(SanitizeError::IndexOutOfBounds),
            Ordering::Less => Err(SanitizeError::InvalidValue),
            Ordering::Equal => Ok(()),
        }?;

        // Signatures are verified before message keys are loaded so all signers
        // must correspond to static account keys.
        if num_signatures > num_static_account_keys {
            return Err(SanitizeError::IndexOutOfBounds);
        }

        Ok(())
    }

    /// Returns the version of the transaction
    pub fn version(&self) -> TransactionVersion {
        match self.message {
            VersionedMessage::Legacy(_) => TransactionVersion::LEGACY,
            VersionedMessage::V0(_) => TransactionVersion::Number(0),
        }
    }

    /// Returns a legacy transaction if the transaction message is legacy.
    pub fn into_legacy_transaction(self) -> Option<Transaction> {
        match self.message {
            VersionedMessage::Legacy(message) => Some(Transaction {
                signatures: self.signatures,
                message,
            }),
            _ => None,
        }
    }

    // Returns true if transaction begins with an advance nonce instruction.
    // pub fn uses_durable_nonce(&self) -> bool {
    //     let message = &self.message;
    //     message
    //         .instructions()
    //         .get(crate::NONCED_TX_MARKER_IX_INDEX as usize)
    //         .filter(|instruction| {
    //             // Is system program
    //             matches!(
    //                 message.static_account_keys().get(instruction.program_id_index as usize),
    //                 Some(program_id) if system_program::check_id(program_id)
    //             )
    //             // Is a nonce advance instruction
    //             && matches!(
    //                 limited_deserialize(&instruction.data, crate::PACKET_DATA_SIZE as u64,),
    //                 Ok(SystemInstruction::AdvanceNonceAccount)
    //             )
    //         })
    //         .is_some()
    // }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SanitizedVersionedTransaction {
    /// List of signatures
    pub(crate) signatures: Vec<Signature>,
    /// Message to sign.
    pub(crate) message: SanitizedVersionedMessage,
}

impl TryFrom<VersionedTransaction> for SanitizedVersionedTransaction {
    type Error = SanitizeError;
    fn try_from(tx: VersionedTransaction) -> Result<Self, Self::Error> {
        Self::try_new(tx)
    }
}

impl SanitizedVersionedTransaction {
    pub fn try_new(tx: VersionedTransaction) -> Result<Self, SanitizeError> {
        tx.sanitize_signatures()?;
        Ok(Self {
            signatures: tx.signatures,
            message: SanitizedVersionedMessage::try_from(tx.message)?,
        })
    }

    pub fn get_message(&self) -> &SanitizedVersionedMessage {
        &self.message
    }

    /// Consumes the SanitizedVersionedTransaction, returning the fields individually.
    pub fn destruct(self) -> (Vec<Signature>, SanitizedVersionedMessage) {
        (self.signatures, self.message)
    }
}

impl SanitizedTransaction {
    /// Create a sanitized transaction from a sanitized versioned transaction.
    /// If the input transaction uses address tables, attempt to lookup the
    /// address for each table index.
    pub fn try_new(
        tx: SanitizedVersionedTransaction,
        message_hash: Hash,
        is_simple_vote_tx: bool,
        address_loader: impl AddressLoader,
        reserved_account_keys: &HashSet<Pubkey>,
    ) -> Result<Self, TransactionError> {
        let signatures = tx.signatures;
        let SanitizedVersionedMessage { message } = tx.message;
        let message = match message {
            VersionedMessage::Legacy(message) => {
                SanitizedMessage::Legacy(LegacyMessage::new(message, reserved_account_keys))
            }
            VersionedMessage::V0(message) => {
                let loaded_addresses =
                    address_loader.load_addresses(&message.address_table_lookups)?;
                SanitizedMessage::V0(v0::LoadedMessage::new(
                    message,
                    loaded_addresses,
                    reserved_account_keys,
                ))
            }
        };

        Ok(Self {
            message,
            message_hash,
            is_simple_vote_tx,
            signatures,
        })
    }

    pub fn try_from_legacy_transaction(
        tx: Transaction,
        reserved_account_keys: &HashSet<Pubkey>,
    ) -> Result<Self, TransactionError> {
        tx.sanitize()?;

        Ok(Self {
            message_hash: tx.message.hash(),
            message: SanitizedMessage::Legacy(LegacyMessage::new(
                tx.message,
                reserved_account_keys,
            )),
            is_simple_vote_tx: false,
            signatures: tx.signatures,
        })
    }

    /// Create a sanitized transaction from fields.
    /// Performs only basic signature sanitization.
    pub fn try_new_from_fields(
        message: SanitizedMessage,
        message_hash: Hash,
        is_simple_vote_tx: bool,
        signatures: Vec<Signature>,
    ) -> Result<Self, TransactionError> {
        VersionedTransaction::sanitize_signatures_inner(
            usize::from(message.header().num_required_signatures),
            message.static_account_keys().len(),
            signatures.len(),
        )?;

        Ok(Self {
            message,
            message_hash,
            signatures,
            is_simple_vote_tx,
        })
    }

    /// Return the first signature for this transaction.
    ///
    /// Notes:
    ///
    /// Sanitized transactions must have at least one signature because the
    /// number of signatures must be greater than or equal to the message header
    /// value `num_required_signatures` which must be greater than 0 itself.
    pub fn signature(&self) -> &Signature {
        &self.signatures[0]
    }

    /// Return the list of signatures for this transaction
    pub fn signatures(&self) -> &[Signature] {
        &self.signatures
    }

    /// Return the signed message
    pub fn message(&self) -> &SanitizedMessage {
        &self.message
    }

    /// Return the hash of the signed message
    pub fn message_hash(&self) -> &Hash {
        &self.message_hash
    }

    /// Returns true if this transaction is a simple vote
    pub fn is_simple_vote_transaction(&self) -> bool {
        self.is_simple_vote_tx
    }

    /// Convert this sanitized transaction into a versioned transaction for
    /// recording in the ledger.
    pub fn to_versioned_transaction(&self) -> VersionedTransaction {
        let signatures = self.signatures.clone();
        match &self.message {
            SanitizedMessage::V0(sanitized_msg) => VersionedTransaction {
                signatures,
                message: VersionedMessage::V0(v0::Message::clone(&sanitized_msg.message)),
            },
            SanitizedMessage::Legacy(legacy_message) => VersionedTransaction {
                signatures,
                message: VersionedMessage::Legacy(legacy::Message::clone(&legacy_message.message)),
            },
        }
    }

    /// Validate and return the account keys locked by this transaction
    pub fn get_account_locks(
        &self,
        tx_account_lock_limit: usize,
    ) -> Result<TransactionAccountLocks, TransactionError> {
        Self::validate_account_locks(self.message(), tx_account_lock_limit)?;
        Ok(self.get_account_locks_unchecked())
    }

    /// Return the list of accounts that must be locked during processing this transaction.
    pub fn get_account_locks_unchecked(&self) -> TransactionAccountLocks {
        let message = &self.message;
        let account_keys = message.account_keys();
        let num_readonly_accounts = message.num_readonly_accounts();
        let num_writable_accounts = account_keys.len().saturating_sub(num_readonly_accounts);

        let mut account_locks = TransactionAccountLocks {
            writable: Vec::with_capacity(num_writable_accounts),
            readonly: Vec::with_capacity(num_readonly_accounts),
        };

        for (i, key) in account_keys.iter().enumerate() {
            if message.is_writable(i) {
                account_locks.writable.push(key);
            } else {
                account_locks.readonly.push(key);
            }
        }

        account_locks
    }

    /// Return the list of addresses loaded from on-chain address lookup tables
    pub fn get_loaded_addresses(&self) -> v0::LoadedAddresses {
        match &self.message {
            SanitizedMessage::Legacy(_) => v0::LoadedAddresses::default(),
            SanitizedMessage::V0(message) => v0::LoadedAddresses::clone(&message.loaded_addresses),
        }
    }

    /// If the transaction uses a durable nonce, return the pubkey of the nonce account
    // pub fn get_durable_nonce(&self) -> Option<&Pubkey> {
    //     self.message.get_durable_nonce()
    // }

    /// Validate a transaction message against locked accounts
    pub fn validate_account_locks(
        message: &SanitizedMessage,
        tx_account_lock_limit: usize,
    ) -> Result<(), TransactionError> {
        if message.has_duplicates() {
            Err(TransactionError::AccountLoadedTwice)
        } else if message.account_keys().len() > tx_account_lock_limit {
            Err(TransactionError::TooManyAccountLocks)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SanitizedVersionedMessage {
    pub message: VersionedMessage,
}

impl TryFrom<VersionedMessage> for SanitizedVersionedMessage {
    type Error = SanitizeError;
    fn try_from(message: VersionedMessage) -> Result<Self, Self::Error> {
        Self::try_new(message)
    }
}

impl SanitizedVersionedMessage {
    pub fn try_new(message: VersionedMessage) -> Result<Self, SanitizeError> {
        message.sanitize()?;
        Ok(Self { message })
    }

    /// Program instructions that will be executed in sequence and committed in
    /// one atomic transaction if all succeed.
    pub fn instructions(&self) -> &[CompiledInstruction] {
        self.message.instructions()
    }

    /// Program instructions iterator which includes each instruction's program
    /// id.
    pub fn program_instructions_iter(
        &self,
    ) -> impl Iterator<Item = (&Pubkey, &CompiledInstruction)> + Clone {
        self.message.instructions().iter().map(move |ix| {
            (
                self.message
                    .static_account_keys()
                    .get(usize::from(ix.program_id_index))
                    .expect("program id index is sanitized"),
                ix,
            )
        })
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct LegacyMessage<'a> {
    /// Legacy message
    pub message: Cow<'a, legacy::Message>,
    /// List of boolean with same length as account_keys(), each boolean value indicates if
    /// corresponding account key is writable or not.
    pub is_writable_account_cache: Vec<bool>,
}

impl LegacyMessage<'_> {
    pub fn new(message: legacy::Message, reserved_account_keys: &HashSet<Pubkey>) -> Self {
        let is_writable_account_cache = message
            .account_keys
            .iter()
            .enumerate()
            .map(|(i, _key)| {
                message.is_writable_index(i)
                    && !reserved_account_keys.contains(&message.account_keys[i])
                    && !message.demote_program_id(i)
            })
            .collect::<Vec<_>>();
        Self {
            message: Cow::Owned(message),
            is_writable_account_cache,
        }
    }

    pub fn has_duplicates(&self) -> bool {
        self.message.has_duplicates()
    }

    pub fn is_key_called_as_program(&self, key_index: usize) -> bool {
        self.message.is_key_called_as_program(key_index)
    }

    /// Inspect all message keys for the bpf upgradeable loader
    pub fn is_upgradeable_loader_present(&self) -> bool {
        self.message.is_upgradeable_loader_present()
    }

    /// Returns the full list of account keys.
    pub fn account_keys(&self) -> AccountKeys {
        AccountKeys::new(&self.message.account_keys, None)
    }

    pub fn is_writable(&self, index: usize) -> bool {
        *self.is_writable_account_cache.get(index).unwrap_or(&false)
    }
}

pub trait AddressLoader: Clone {
    fn load_addresses(
        self,
        lookups: &[MessageAddressTableLookup],
    ) -> Result<v0::LoadedAddresses, AddressLoaderError>;
}

#[derive(Clone)]
pub enum SimpleAddressLoader {
    Disabled,
    Enabled(v0::LoadedAddresses),
}

impl AddressLoader for SimpleAddressLoader {
    fn load_addresses(
        self,
        _lookups: &[MessageAddressTableLookup],
    ) -> Result<v0::LoadedAddresses, AddressLoaderError> {
        match self {
            Self::Disabled => Err(AddressLoaderError::Disabled),
            Self::Enabled(loaded_addresses) => Ok(loaded_addresses),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum SanitizedMessage {
    /// Sanitized legacy message
    Legacy(LegacyMessage<'static>),
    /// Sanitized version #0 message with dynamically loaded addresses
    V0(v0::LoadedMessage<'static>),
}

impl SanitizedMessage {
    /// Create a sanitized message from a sanitized versioned message.
    /// If the input message uses address tables, attempt to look up the
    /// address for each table index.
    pub fn try_new(
        sanitized_msg: SanitizedVersionedMessage,
        address_loader: impl AddressLoader,
        reserved_account_keys: &HashSet<Pubkey>,
    ) -> Result<Self, SanitizeMessageError> {
        Ok(match sanitized_msg.message {
            VersionedMessage::Legacy(message) => {
                SanitizedMessage::Legacy(LegacyMessage::new(message, reserved_account_keys))
            }
            VersionedMessage::V0(message) => {
                let loaded_addresses =
                    address_loader.load_addresses(&message.address_table_lookups)?;
                SanitizedMessage::V0(v0::LoadedMessage::new(
                    message,
                    loaded_addresses,
                    reserved_account_keys,
                ))
            }
        })
    }

    /// Create a sanitized legacy message
    pub fn try_from_legacy_message(
        message: legacy::Message,
        reserved_account_keys: &HashSet<Pubkey>,
    ) -> Result<Self, SanitizeMessageError> {
        message.sanitize()?;
        Ok(Self::Legacy(LegacyMessage::new(
            message,
            reserved_account_keys,
        )))
    }

    /// Return true if this message contains duplicate account keys
    pub fn has_duplicates(&self) -> bool {
        match self {
            SanitizedMessage::Legacy(message) => message.has_duplicates(),
            SanitizedMessage::V0(message) => message.has_duplicates(),
        }
    }

    /// Message header which identifies the number of signer and writable or
    /// readonly accounts
    pub fn header(&self) -> &MessageHeader {
        match self {
            Self::Legacy(legacy_message) => &legacy_message.message.header,
            Self::V0(loaded_msg) => &loaded_msg.message.header,
        }
    }

    /// Returns a legacy message if this sanitized message wraps one
    pub fn legacy_message(&self) -> Option<&legacy::Message> {
        if let Self::Legacy(legacy_message) = &self {
            Some(&legacy_message.message)
        } else {
            None
        }
    }

    /// Returns the fee payer for the transaction
    pub fn fee_payer(&self) -> &Pubkey {
        self.account_keys()
            .get(0)
            .expect("sanitized messages always have a fee payer at index 0")
    }

    /// The hash of a recent block, used for timing out a transaction
    pub fn recent_blockhash(&self) -> &Hash {
        match self {
            Self::Legacy(legacy_message) => &legacy_message.message.recent_blockhash,
            Self::V0(loaded_msg) => &loaded_msg.message.recent_blockhash,
        }
    }

    /// Program instructions that will be executed in sequence and committed in
    /// one atomic transaction if all succeed.
    pub fn instructions(&self) -> &[CompiledInstruction] {
        match self {
            Self::Legacy(legacy_message) => &legacy_message.message.instructions,
            Self::V0(loaded_msg) => &loaded_msg.message.instructions,
        }
    }

    /// Program instructions iterator which includes each instruction's program
    /// id.
    pub fn program_instructions_iter(
        &self,
    ) -> impl Iterator<Item = (&Pubkey, &CompiledInstruction)> + Clone {
        self.instructions().iter().map(move |ix| {
            (
                self.account_keys()
                    .get(usize::from(ix.program_id_index))
                    .expect("program id index is sanitized"),
                ix,
            )
        })
    }

    /// Return the list of statically included account keys.
    pub fn static_account_keys(&self) -> &[Pubkey] {
        match self {
            Self::Legacy(legacy_message) => &legacy_message.message.account_keys,
            Self::V0(loaded_msg) => &loaded_msg.message.account_keys,
        }
    }

    /// Returns the list of account keys that are loaded for this message.
    pub fn account_keys(&self) -> AccountKeys {
        match self {
            Self::Legacy(message) => message.account_keys(),
            Self::V0(message) => message.account_keys(),
        }
    }

    /// Returns the list of account keys used for account lookup tables.
    pub fn message_address_table_lookups(&self) -> &[v0::MessageAddressTableLookup] {
        match self {
            Self::Legacy(_message) => &[],
            Self::V0(message) => &message.message.address_table_lookups,
        }
    }

    /// Returns true if the account at the specified index is an input to some
    /// program instruction in this message.
    #[deprecated(since = "2.0.0", note = "Please use `is_instruction_account` instead")]
    pub fn is_key_passed_to_program(&self, key_index: usize) -> bool {
        self.is_instruction_account(key_index)
    }

    /// Returns true if the account at the specified index is an input to some
    /// program instruction in this message.
    pub fn is_instruction_account(&self, key_index: usize) -> bool {
        if let Ok(key_index) = u8::try_from(key_index) {
            self.instructions()
                .iter()
                .any(|ix| ix.accounts.contains(&key_index))
        } else {
            false
        }
    }

    /// Returns true if the account at the specified index is invoked as a
    /// program in this message.
    pub fn is_invoked(&self, key_index: usize) -> bool {
        match self {
            Self::Legacy(message) => message.is_key_called_as_program(key_index),
            Self::V0(message) => message.is_key_called_as_program(key_index),
        }
    }

    /// Returns true if the account at the specified index is not invoked as a
    /// program or, if invoked, is passed to a program.
    #[deprecated(
        since = "2.0.0",
        note = "Please use `is_invoked` and `is_instruction_account` instead"
    )]
    pub fn is_non_loader_key(&self, key_index: usize) -> bool {
        !self.is_invoked(key_index) || self.is_instruction_account(key_index)
    }

    /// Returns true if the account at the specified index is writable by the
    /// instructions in this message.
    pub fn is_writable(&self, index: usize) -> bool {
        match self {
            Self::Legacy(message) => message.is_writable(index),
            Self::V0(message) => message.is_writable(index),
        }
    }

    /// Returns true if the account at the specified index signed this
    /// message.
    pub fn is_signer(&self, index: usize) -> bool {
        index < usize::from(self.header().num_required_signatures)
    }

    /// Return the resolved addresses for this message if it has any.
    fn loaded_lookup_table_addresses(&self) -> Option<&v0::LoadedAddresses> {
        match &self {
            SanitizedMessage::V0(message) => Some(&message.loaded_addresses),
            _ => None,
        }
    }

    /// Return the number of readonly accounts loaded by this message.
    pub fn num_readonly_accounts(&self) -> usize {
        let loaded_readonly_addresses = self
            .loaded_lookup_table_addresses()
            .map(|keys| keys.readonly.len())
            .unwrap_or_default();
        loaded_readonly_addresses
            .saturating_add(usize::from(self.header().num_readonly_signed_accounts))
            .saturating_add(usize::from(self.header().num_readonly_unsigned_accounts))
    }

    /// Decompile message instructions without cloning account keys
    pub fn decompile_instructions(&self) -> Vec<BorrowedInstruction> {
        let account_keys = self.account_keys();
        self.program_instructions_iter()
            .map(|(program_id, instruction)| {
                let accounts = instruction
                    .accounts
                    .iter()
                    .map(|account_index| {
                        let account_index = *account_index as usize;
                        BorrowedAccountMeta {
                            is_signer: self.is_signer(account_index),
                            is_writable: self.is_writable(account_index),
                            pubkey: account_keys.get(account_index).unwrap(),
                        }
                    })
                    .collect();

                BorrowedInstruction {
                    accounts,
                    data: &instruction.data,
                    program_id,
                }
            })
            .collect()
    }

    /// Inspect all message keys for the bpf upgradeable loader
    pub fn is_upgradeable_loader_present(&self) -> bool {
        match self {
            Self::Legacy(message) => message.is_upgradeable_loader_present(),
            Self::V0(message) => message.is_upgradeable_loader_present(),
        }
    }

    /// Get a list of signers for the instruction at the given index
    pub fn get_ix_signers(&self, ix_index: usize) -> impl Iterator<Item = &Pubkey> {
        self.instructions()
            .get(ix_index)
            .into_iter()
            .flat_map(|ix| {
                ix.accounts
                    .iter()
                    .copied()
                    .map(usize::from)
                    .filter(|index| self.is_signer(*index))
                    .filter_map(|signer_index| self.account_keys().get(signer_index))
            })
    }

    /// If the message uses a durable nonce, return the pubkey of the nonce account
    // pub fn get_durable_nonce(&self) -> Option<&Pubkey> {
    //     self.instructions()
    //         .get(NONCED_TX_MARKER_IX_INDEX as usize)
    //         .filter(
    //             |ix| match self.account_keys().get(ix.program_id_index as usize) {
    //                 Some(program_id) => system_program::check_id(program_id),
    //                 _ => false,
    //             },
    //         )
    //         .filter(|ix| {
    //             matches!(
    //                 limited_deserialize(&ix.data, 4 /* serialized size of AdvanceNonceAccount */),
    //                 Ok(SystemInstruction::AdvanceNonceAccount)
    //             )
    //         })
    //         .and_then(|ix| {
    //             ix.accounts.first().and_then(|idx| {
    //                 let idx = *idx as usize;
    //                 if !self.is_writable(idx) {
    //                     None
    //                 } else {
    //                     self.account_keys().get(idx)
    //                 }
    //             })
    //         })
    // }

    #[deprecated(
        since = "2.1.0",
        note = "Please use `SanitizedMessage::num_total_signatures` instead."
    )]
    pub fn num_signatures(&self) -> u64 {
        self.num_total_signatures()
    }

    /// Returns the total number of signatures in the message.
    /// This includes required transaction signatures as well as any
    /// pre-compile signatures that are attached in instructions.
    pub fn num_total_signatures(&self) -> u64 {
        self.get_signature_details().total_signatures()
    }

    /// Returns the number of requested write-locks in this message.
    /// This does not consider if write-locks are demoted.
    pub fn num_write_locks(&self) -> u64 {
        self.account_keys()
            .len()
            .saturating_sub(self.num_readonly_accounts()) as u64
    }

    /// return detailed signature counts
    pub fn get_signature_details(&self) -> TransactionSignatureDetails {
        let mut transaction_signature_details = TransactionSignatureDetails {
            num_transaction_signatures: u64::from(self.header().num_required_signatures),
            ..TransactionSignatureDetails::default()
        };

        // counting the number of pre-processor operations separately
        for (program_id, instruction) in self.program_instructions_iter() {
            if secp256k1_program::check_id(program_id) {
                if let Some(num_verifies) = instruction.data.first() {
                    transaction_signature_details.num_secp256k1_instruction_signatures =
                        transaction_signature_details
                            .num_secp256k1_instruction_signatures
                            .saturating_add(u64::from(*num_verifies));
                }
            } else if ed25519_program::check_id(program_id) {
                if let Some(num_verifies) = instruction.data.first() {
                    transaction_signature_details.num_ed25519_instruction_signatures =
                        transaction_signature_details
                            .num_ed25519_instruction_signatures
                            .saturating_add(u64::from(*num_verifies));
                }
            } else if secp256r1_program::check_id(program_id) {
                if let Some(num_verifies) = instruction.data.first() {
                    transaction_signature_details.num_secp256r1_instruction_signatures =
                        transaction_signature_details
                            .num_secp256r1_instruction_signatures
                            .saturating_add(u64::from(*num_verifies));
                }
            }
        }

        transaction_signature_details
    }
}

/// Borrowed version of `AccountMeta`.
///
/// This struct is used by the runtime when constructing the instructions sysvar. It is not
/// useful to Solana programs.
pub struct BorrowedAccountMeta<'a> {
    pub pubkey: &'a Pubkey,
    pub is_signer: bool,
    pub is_writable: bool,
}

/// Borrowed version of `Instruction`.
///
/// This struct is used by the runtime when constructing the instructions sysvar. It is not
/// useful to Solana programs.
pub struct BorrowedInstruction<'a> {
    pub program_id: &'a Pubkey,
    pub accounts: Vec<BorrowedAccountMeta<'a>>,
    pub data: &'a [u8],
}

/// Transaction signature details including the number of transaction signatures
/// and precompile signatures.
#[derive(Clone, Debug, Default)]
pub struct TransactionSignatureDetails {
    num_transaction_signatures: u64,
    num_secp256k1_instruction_signatures: u64,
    num_ed25519_instruction_signatures: u64,
    num_secp256r1_instruction_signatures: u64,
}

impl TransactionSignatureDetails {
    pub const fn new(
        num_transaction_signatures: u64,
        num_secp256k1_instruction_signatures: u64,
        num_ed25519_instruction_signatures: u64,
        num_secp256r1_instruction_signatures: u64,
    ) -> Self {
        Self {
            num_transaction_signatures,
            num_secp256k1_instruction_signatures,
            num_ed25519_instruction_signatures,
            num_secp256r1_instruction_signatures,
        }
    }

    /// return total number of signature, treating pre-processor operations as signature
    pub fn total_signatures(&self) -> u64 {
        self.num_transaction_signatures
            .saturating_add(self.num_secp256k1_instruction_signatures)
            .saturating_add(self.num_ed25519_instruction_signatures)
            .saturating_add(self.num_secp256r1_instruction_signatures)
    }

    /// return the number of transaction signatures
    pub fn num_transaction_signatures(&self) -> u64 {
        self.num_transaction_signatures
    }

    /// return the number of secp256k1 instruction signatures
    pub fn num_secp256k1_instruction_signatures(&self) -> u64 {
        self.num_secp256k1_instruction_signatures
    }

    /// return the number of ed25519 instruction signatures
    pub fn num_ed25519_instruction_signatures(&self) -> u64 {
        self.num_ed25519_instruction_signatures
    }

    /// return the number of secp256r1 instruction signatures
    pub fn num_secp256r1_instruction_signatures(&self) -> u64 {
        self.num_secp256r1_instruction_signatures
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum VersionedMessage {
    Legacy(legacy::Message),
    V0(v0::Message),
}

impl VersionedMessage {
    pub fn sanitize(&self) -> Result<(), SanitizeError> {
        match self {
            Self::Legacy(message) => message.sanitize(),
            Self::V0(message) => message.sanitize(),
        }
    }

    pub fn header(&self) -> &MessageHeader {
        match self {
            Self::Legacy(message) => &message.header,
            Self::V0(message) => &message.header,
        }
    }

    pub fn static_account_keys(&self) -> &[Pubkey] {
        match self {
            Self::Legacy(message) => &message.account_keys,
            Self::V0(message) => &message.account_keys,
        }
    }

    pub fn address_table_lookups(&self) -> Option<&[MessageAddressTableLookup]> {
        match self {
            Self::Legacy(_) => None,
            Self::V0(message) => Some(&message.address_table_lookups),
        }
    }

    /// Returns true if the account at the specified index signed this
    /// message.
    pub fn is_signer(&self, index: usize) -> bool {
        index < usize::from(self.header().num_required_signatures)
    }

    /// Returns true if the account at the specified index is writable by the
    /// instructions in this message. Since dynamically loaded addresses can't
    /// have write locks demoted without loading addresses, this shouldn't be
    /// used in the runtime.
    pub fn is_maybe_writable(
        &self,
        index: usize,
        reserved_account_keys: Option<&HashSet<Pubkey>>,
    ) -> bool {
        match self {
            Self::Legacy(message) => message.is_maybe_writable(index, reserved_account_keys),
            Self::V0(message) => message.is_maybe_writable(index, reserved_account_keys),
        }
    }

    #[deprecated(since = "2.0.0", note = "Please use `is_instruction_account` instead")]
    pub fn is_key_passed_to_program(&self, key_index: usize) -> bool {
        self.is_instruction_account(key_index)
    }

    /// Returns true if the account at the specified index is an input to some
    /// program instruction in this message.
    fn is_instruction_account(&self, key_index: usize) -> bool {
        if let Ok(key_index) = u8::try_from(key_index) {
            self.instructions()
                .iter()
                .any(|ix| ix.accounts.contains(&key_index))
        } else {
            false
        }
    }

    pub fn is_invoked(&self, key_index: usize) -> bool {
        match self {
            Self::Legacy(message) => message.is_key_called_as_program(key_index),
            Self::V0(message) => message.is_key_called_as_program(key_index),
        }
    }

    /// Returns true if the account at the specified index is not invoked as a
    /// program or, if invoked, is passed to a program.
    pub fn is_non_loader_key(&self, key_index: usize) -> bool {
        !self.is_invoked(key_index) || self.is_instruction_account(key_index)
    }

    pub fn recent_blockhash(&self) -> &Hash {
        match self {
            Self::Legacy(message) => &message.recent_blockhash,
            Self::V0(message) => &message.recent_blockhash,
        }
    }

    pub fn set_recent_blockhash(&mut self, recent_blockhash: Hash) {
        match self {
            Self::Legacy(message) => message.recent_blockhash = recent_blockhash,
            Self::V0(message) => message.recent_blockhash = recent_blockhash,
        }
    }

    /// Program instructions that will be executed in sequence and committed in
    /// one atomic transaction if all succeed.
    pub fn instructions(&self) -> &[CompiledInstruction] {
        match self {
            Self::Legacy(message) => &message.instructions,
            Self::V0(message) => &message.instructions,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap()
    }
}

impl Default for VersionedMessage {
    fn default() -> Self {
        Self::Legacy(legacy::Message::default())
    }
}

impl serde::Serialize for VersionedMessage {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Legacy(message) => {
                let mut seq = serializer.serialize_tuple(1)?;
                seq.serialize_element(message)?;
                seq.end()
            }
            Self::V0(message) => {
                let mut seq = serializer.serialize_tuple(2)?;
                seq.serialize_element(&MESSAGE_VERSION_PREFIX)?;
                seq.serialize_element(message)?;
                seq.end()
            }
        }
    }
}

enum MessagePrefix {
    Legacy(u8),
    Versioned(u8),
}

impl<'de> serde::Deserialize<'de> for MessagePrefix {
    fn deserialize<D>(deserializer: D) -> Result<MessagePrefix, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PrefixVisitor;

        impl Visitor<'_> for PrefixVisitor {
            type Value = MessagePrefix;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("message prefix byte")
            }

            // Serde's integer visitors bubble up to u64 so check the prefix
            // with this function instead of visit_u8. This approach is
            // necessary because serde_json directly calls visit_u64 for
            // unsigned integers.
            fn visit_u64<E: de::Error>(self, value: u64) -> Result<MessagePrefix, E> {
                if value > u8::MAX as u64 {
                    Err(de::Error::invalid_type(Unexpected::Unsigned(value), &self))?;
                }

                let byte = value as u8;
                if byte & MESSAGE_VERSION_PREFIX != 0 {
                    Ok(MessagePrefix::Versioned(byte & !MESSAGE_VERSION_PREFIX))
                } else {
                    Ok(MessagePrefix::Legacy(byte))
                }
            }
        }

        deserializer.deserialize_u8(PrefixVisitor)
    }
}

impl<'de> serde::Deserialize<'de> for VersionedMessage {
    fn deserialize<D>(deserializer: D) -> Result<VersionedMessage, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct MessageVisitor;

        impl<'de> Visitor<'de> for MessageVisitor {
            type Value = VersionedMessage;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("message bytes")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<VersionedMessage, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let prefix: MessagePrefix = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;

                match prefix {
                    MessagePrefix::Legacy(num_required_signatures) => {
                        // The remaining fields of the legacy Message struct after the first byte.
                        #[derive(Serialize, Deserialize)]
                        struct RemainingLegacyMessage {
                            pub num_readonly_signed_accounts: u8,
                            pub num_readonly_unsigned_accounts: u8,
                            pub account_keys: Vec<Pubkey>,
                            pub recent_blockhash: Hash,
                            pub instructions: Vec<CompiledInstruction>,
                        }

                        let message: RemainingLegacyMessage =
                            seq.next_element()?.ok_or_else(|| {
                                // will never happen since tuple length is always 2
                                de::Error::invalid_length(1, &self)
                            })?;

                        Ok(VersionedMessage::Legacy(legacy::Message {
                            header: MessageHeader {
                                num_required_signatures,
                                num_readonly_signed_accounts: message.num_readonly_signed_accounts,
                                num_readonly_unsigned_accounts: message
                                    .num_readonly_unsigned_accounts,
                            },
                            account_keys: message.account_keys,
                            recent_blockhash: message.recent_blockhash,
                            instructions: message.instructions,
                        }))
                    }
                    MessagePrefix::Versioned(version) => {
                        match version {
                            0 => {
                                Ok(VersionedMessage::V0(seq.next_element()?.ok_or_else(
                                    || {
                                        // will never happen since tuple length is always 2
                                        de::Error::invalid_length(1, &self)
                                    },
                                )?))
                            }
                            127 => {
                                // 0xff is used as the first byte of the off-chain messages
                                // which corresponds to version 127 of the versioned messages.
                                // This explicit check is added to prevent the usage of version 127
                                // in the runtime as a valid transaction.
                                Err(de::Error::custom("off-chain messages are not accepted"))
                            }
                            _ => Err(de::Error::invalid_value(
                                de::Unexpected::Unsigned(version as u64),
                                &"a valid transaction message version",
                            )),
                        }
                    }
                }
            }
        }

        deserializer.deserialize_tuple(2, MessageVisitor)
    }
}

pub mod legacy {
    use std::collections::HashSet;

    use builtins::{BUILTIN_PROGRAMS_KEYS, MAYBE_BUILTIN_KEY_OR_SYSVAR};
    use serde::{Deserialize, Serialize};

    use crate::{
        blake3::HASH_BYTES, bpf_loader_upgradeable, sysvar, CompiledInstruction, CompiledKeys,
        Hash, Instruction, MessageHeader, Pubkey, Sanitize, SanitizeError,
    };

    lazy_static::lazy_static! {
        // This will be deprecated and so this list shouldn't be modified
        static ref ALL_IDS: Vec<Pubkey> = vec![
            sysvar::clock::id(),
            sysvar::epoch_schedule::id(),
            sysvar::fees::id(),
            sysvar::recent_blockhashes::id(),
            sysvar::rent::id(),
            sysvar::rewards::id(),
            sysvar::slot_hashes::id(),
            sysvar::slot_history::id(),
            sysvar::stake_history::id(),
            sysvar::instructions::id(),
        ];
    }

    mod builtins {
        use {
            super::*,
            crate::{bpf_loader, bpf_loader_deprecated, system_program},
            lazy_static::lazy_static,
            std::str::FromStr,
        };

        lazy_static! {
            pub static ref BUILTIN_PROGRAMS_KEYS: [Pubkey; 10] = {
                let parse = |s| Pubkey::from_str(s).unwrap();
                [
                    parse("Config1111111111111111111111111111111111111"),
                    parse("Feature111111111111111111111111111111111111"),
                    parse("NativeLoader1111111111111111111111111111111"),
                    parse("Stake11111111111111111111111111111111111111"),
                    parse("StakeConfig11111111111111111111111111111111"),
                    parse("Vote111111111111111111111111111111111111111"),
                    system_program::id(),
                    bpf_loader::id(),
                    bpf_loader_deprecated::id(),
                    bpf_loader_upgradeable::id(),
                ]
            };
        }

        lazy_static! {
            // Each element of a key is a u8. We use key[0] as an index into this table of 256 boolean
            // elements, to store whether or not the first element of any key is present in the static
            // lists of built-in-program keys or system ids. By using this lookup table, we can very
            // quickly determine that a key under consideration cannot be in either of these lists (if
            // the value is "false"), or might be in one of these lists (if the value is "true")
            pub static ref MAYBE_BUILTIN_KEY_OR_SYSVAR: [bool; 256] = {
                let mut temp_table: [bool; 256] = [false; 256];
                BUILTIN_PROGRAMS_KEYS.iter().for_each(|key| temp_table[key.as_ref()[0] as usize] = true);
                ALL_IDS.iter().for_each(|key| temp_table[key.as_ref()[0] as usize] = true);
                temp_table
            };
        }
    }

    fn is_sysvar_id(id: &Pubkey) -> bool {
        ALL_IDS.iter().any(|key| key == id)
    }

    pub fn is_builtin_key_or_sysvar(key: &Pubkey) -> bool {
        if MAYBE_BUILTIN_KEY_OR_SYSVAR[key.as_ref()[0] as usize] {
            return is_sysvar_id(key) || BUILTIN_PROGRAMS_KEYS.contains(key);
        }
        false
    }

    fn position(keys: &[Pubkey], key: &Pubkey) -> u8 {
        keys.iter().position(|k| k == key).unwrap() as u8
    }

    fn compile_instruction(ix: &Instruction, keys: &[Pubkey]) -> CompiledInstruction {
        let accounts: Vec<_> = ix
            .accounts
            .iter()
            .map(|account_meta| position(keys, &account_meta.pubkey))
            .collect();

        CompiledInstruction {
            program_id_index: position(keys, &ix.program_id),
            data: ix.data.clone(),
            accounts,
        }
    }

    fn compile_instructions(ixs: &[Instruction], keys: &[Pubkey]) -> Vec<CompiledInstruction> {
        ixs.iter().map(|ix| compile_instruction(ix, keys)).collect()
    }

    #[derive(Default, Debug, PartialEq, Eq, Clone, Deserialize, Serialize)]
    pub struct Message {
        /// The message header, identifying signed and read-only `account_keys`.
        // NOTE: Serialization-related changes must be paired with the direct read at sigverify.
        pub header: MessageHeader,

        /// All the account keys used by this transaction.
        pub account_keys: Vec<Pubkey>,

        /// The id of a recent ledger entry.
        pub recent_blockhash: Hash,

        /// Programs that will be executed in sequence and committed in one atomic transaction if all
        /// succeed.
        pub instructions: Vec<CompiledInstruction>,
    }

    impl Sanitize for Message {
        fn sanitize(&self) -> std::result::Result<(), SanitizeError> {
            // signing area and read-only non-signing area should not overlap
            if self.header.num_required_signatures as usize
                + self.header.num_readonly_unsigned_accounts as usize
                > self.account_keys.len()
            {
                return Err(SanitizeError::IndexOutOfBounds);
            }

            // there should be at least 1 RW fee-payer account.
            if self.header.num_readonly_signed_accounts >= self.header.num_required_signatures {
                return Err(SanitizeError::IndexOutOfBounds);
            }

            for ci in &self.instructions {
                if ci.program_id_index as usize >= self.account_keys.len() {
                    return Err(SanitizeError::IndexOutOfBounds);
                }
                // A program cannot be a payer.
                if ci.program_id_index == 0 {
                    return Err(SanitizeError::IndexOutOfBounds);
                }
                for ai in &ci.accounts {
                    if *ai as usize >= self.account_keys.len() {
                        return Err(SanitizeError::IndexOutOfBounds);
                    }
                }
            }
            self.account_keys.sanitize()?;
            self.recent_blockhash.sanitize()?;
            self.instructions.sanitize()?;
            Ok(())
        }
    }

    impl Message {
        pub fn new(instructions: &[Instruction], payer: Option<&Pubkey>) -> Self {
            Self::new_with_blockhash(instructions, payer, &Hash::default())
        }

        pub fn new_with_blockhash(
            instructions: &[Instruction],
            payer: Option<&Pubkey>,
            blockhash: &Hash,
        ) -> Self {
            let compiled_keys = CompiledKeys::compile(instructions, payer.cloned());
            let (header, account_keys) = compiled_keys
                .try_into_message_components()
                .expect("overflow when compiling message keys");
            let instructions = compile_instructions(instructions, &account_keys);
            Self::new_with_compiled_instructions(
                header.num_required_signatures,
                header.num_readonly_signed_accounts,
                header.num_readonly_unsigned_accounts,
                account_keys,
                *blockhash,
                instructions,
            )
        }

        // pub fn new_with_nonce(
        //     mut instructions: Vec<Instruction>,
        //     payer: Option<&Pubkey>,
        //     nonce_account_pubkey: &Pubkey,
        //     nonce_authority_pubkey: &Pubkey,
        // ) -> Self {
        //     let nonce_ix = solana_system_interface::instruction::advance_nonce_account(
        //         nonce_account_pubkey,
        //         nonce_authority_pubkey,
        //     );
        //     instructions.insert(0, nonce_ix);
        //     Self::new(&instructions, payer)
        // }

        pub fn new_with_compiled_instructions(
            num_required_signatures: u8,
            num_readonly_signed_accounts: u8,
            num_readonly_unsigned_accounts: u8,
            account_keys: Vec<Pubkey>,
            recent_blockhash: Hash,
            instructions: Vec<CompiledInstruction>,
        ) -> Self {
            Self {
                header: MessageHeader {
                    num_required_signatures,
                    num_readonly_signed_accounts,
                    num_readonly_unsigned_accounts,
                },
                account_keys,
                recent_blockhash,
                instructions,
            }
        }

        /// Compute the blake3 hash of this transaction's message.
        pub fn hash(&self) -> Hash {
            let message_bytes = self.serialize();
            Self::hash_raw_message(&message_bytes)
        }

        /// Compute the blake3 hash of a raw transaction message.
        pub fn hash_raw_message(message_bytes: &[u8]) -> Hash {
            use blake3::traits::digest::Digest;
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"solana-tx-message-v1");
            hasher.update(message_bytes);
            let hash_bytes: [u8; HASH_BYTES] = hasher.finalize().into();
            hash_bytes.into()
        }

        pub fn compile_instruction(&self, ix: &Instruction) -> CompiledInstruction {
            compile_instruction(ix, &self.account_keys)
        }

        pub fn serialize(&self) -> Vec<u8> {
            bincode::serialize(self).unwrap()
        }

        pub fn program_id(&self, instruction_index: usize) -> Option<&Pubkey> {
            Some(
                &self.account_keys
                    [self.instructions.get(instruction_index)?.program_id_index as usize],
            )
        }

        pub fn program_index(&self, instruction_index: usize) -> Option<usize> {
            Some(self.instructions.get(instruction_index)?.program_id_index as usize)
        }

        pub fn program_ids(&self) -> Vec<&Pubkey> {
            self.instructions
                .iter()
                .map(|ix| &self.account_keys[ix.program_id_index as usize])
                .collect()
        }

        #[deprecated(since = "2.0.0", note = "Please use `is_instruction_account` instead")]
        pub fn is_key_passed_to_program(&self, key_index: usize) -> bool {
            self.is_instruction_account(key_index)
        }

        /// Returns true if the account at the specified index is an account input
        /// to some program instruction in this message.
        pub fn is_instruction_account(&self, key_index: usize) -> bool {
            if let Ok(key_index) = u8::try_from(key_index) {
                self.instructions
                    .iter()
                    .any(|ix| ix.accounts.contains(&key_index))
            } else {
                false
            }
        }

        pub fn is_key_called_as_program(&self, key_index: usize) -> bool {
            if let Ok(key_index) = u8::try_from(key_index) {
                self.instructions
                    .iter()
                    .any(|ix| ix.program_id_index == key_index)
            } else {
                false
            }
        }

        #[deprecated(
            since = "2.0.0",
            note = "Please use `is_key_called_as_program` and `is_instruction_account` directly"
        )]
        pub fn is_non_loader_key(&self, key_index: usize) -> bool {
            !self.is_key_called_as_program(key_index) || self.is_instruction_account(key_index)
        }

        pub fn program_position(&self, index: usize) -> Option<usize> {
            let program_ids = self.program_ids();
            program_ids
                .iter()
                .position(|&&pubkey| pubkey == self.account_keys[index])
        }

        pub fn maybe_executable(&self, i: usize) -> bool {
            self.program_position(i).is_some()
        }

        pub fn demote_program_id(&self, i: usize) -> bool {
            self.is_key_called_as_program(i) && !self.is_upgradeable_loader_present()
        }

        /// Returns true if the account at the specified index was requested to be
        /// writable. This method should not be used directly.
        pub(super) fn is_writable_index(&self, i: usize) -> bool {
            i < (self.header.num_required_signatures - self.header.num_readonly_signed_accounts)
                as usize
                || (i >= self.header.num_required_signatures as usize
                    && i < self.account_keys.len()
                        - self.header.num_readonly_unsigned_accounts as usize)
        }

        /// Returns true if the account at the specified index is writable by the
        /// instructions in this message. Since the dynamic set of reserved accounts
        /// isn't used here to demote write locks, this shouldn't be used in the
        /// runtime.
        #[deprecated(since = "2.0.0", note = "Please use `is_maybe_writable` instead")]
        #[allow(deprecated)]
        pub fn is_writable(&self, i: usize) -> bool {
            (self.is_writable_index(i))
                && !is_builtin_key_or_sysvar(&self.account_keys[i])
                && !self.demote_program_id(i)
        }

        /// Returns true if the account at the specified index is writable by the
        /// instructions in this message. The `reserved_account_keys` param has been
        /// optional to allow clients to approximate writability without requiring
        /// fetching the latest set of reserved account keys. If this method is
        /// called by the runtime, the latest set of reserved account keys must be
        /// passed.
        pub fn is_maybe_writable(
            &self,
            i: usize,
            reserved_account_keys: Option<&HashSet<Pubkey>>,
        ) -> bool {
            (self.is_writable_index(i))
                && !self.is_account_maybe_reserved(i, reserved_account_keys)
                && !self.demote_program_id(i)
        }

        /// Returns true if the account at the specified index is in the optional
        /// reserved account keys set.
        fn is_account_maybe_reserved(
            &self,
            key_index: usize,
            reserved_account_keys: Option<&HashSet<Pubkey>>,
        ) -> bool {
            let mut is_maybe_reserved = false;
            if let Some(reserved_account_keys) = reserved_account_keys {
                if let Some(key) = self.account_keys.get(key_index) {
                    is_maybe_reserved = reserved_account_keys.contains(key);
                }
            }
            is_maybe_reserved
        }

        pub fn is_signer(&self, i: usize) -> bool {
            i < self.header.num_required_signatures as usize
        }

        pub fn signer_keys(&self) -> Vec<&Pubkey> {
            // Clamp in case we're working on un-`sanitize()`ed input
            let last_key = self
                .account_keys
                .len()
                .min(self.header.num_required_signatures as usize);
            self.account_keys[..last_key].iter().collect()
        }

        /// Returns `true` if `account_keys` has any duplicate keys.
        pub fn has_duplicates(&self) -> bool {
            // Note: This is an O(n^2) algorithm, but requires no heap allocations. The benchmark
            // `bench_has_duplicates` in benches/message_processor.rs shows that this implementation is
            // ~50 times faster than using HashSet for very short slices.
            for i in 1..self.account_keys.len() {
                #[allow(clippy::arithmetic_side_effects)]
                if self.account_keys[i..].contains(&self.account_keys[i - 1]) {
                    return true;
                }
            }
            false
        }

        /// Returns `true` if any account is the BPF upgradeable loader.
        pub fn is_upgradeable_loader_present(&self) -> bool {
            self.account_keys
                .iter()
                .any(|&key| key == bpf_loader_upgradeable::id())
        }
    }
}

pub mod v0 {
    use std::{borrow::Cow, collections::HashSet};

    use serde::{Deserialize, Serialize};

    use crate::{
        bpf_loader_upgradeable, AccountKeys, AddressLookupTableAccount, CompileError,
        CompiledInstruction, CompiledKeys, Hash, Instruction, MessageHeader, Pubkey, SanitizeError,
    };

    use super::MESSAGE_VERSION_PREFIX;

    #[derive(Default, Debug, PartialEq, Eq, Clone, Deserialize, Serialize)]
    pub struct MessageAddressTableLookup {
        /// Address lookup table account key
        pub account_key: Pubkey,
        /// List of indexes used to load writable account addresses
        pub writable_indexes: Vec<u8>,
        /// List of indexes used to load readonly account addresses
        pub readonly_indexes: Vec<u8>,
    }

    #[derive(Clone, Default, Debug, PartialEq, Eq, Deserialize, Serialize)]
    pub struct LoadedAddresses {
        /// List of addresses for writable loaded accounts
        pub writable: Vec<Pubkey>,
        /// List of addresses for read-only loaded accounts
        pub readonly: Vec<Pubkey>,
    }

    #[derive(Default, Debug, PartialEq, Eq, Clone, Deserialize, Serialize)]
    pub struct Message {
        /// The message header, identifying signed and read-only `account_keys`.
        /// Header values only describe static `account_keys`, they do not describe
        /// any additional account keys loaded via address table lookups.
        pub header: MessageHeader,

        /// List of accounts loaded by this transaction.
        pub account_keys: Vec<Pubkey>,

        /// The blockhash of a recent block.
        pub recent_blockhash: Hash,

        /// Instructions that invoke a designated program, are executed in sequence,
        /// and committed in one atomic transaction if all succeed.
        ///
        /// # Notes
        ///
        /// Program indexes must index into the list of message `account_keys` because
        /// program id's cannot be dynamically loaded from a lookup table.
        ///
        /// Account indexes must index into the list of addresses
        /// constructed from the concatenation of three key lists:
        ///   1) message `account_keys`
        ///   2) ordered list of keys loaded from `writable` lookup table indexes
        ///   3) ordered list of keys loaded from `readable` lookup table indexes
        pub instructions: Vec<CompiledInstruction>,

        /// List of address table lookups used to load additional accounts
        /// for this transaction.
        pub address_table_lookups: Vec<MessageAddressTableLookup>,
    }

    impl Message {
        /// Sanitize message fields and compiled instruction indexes
        pub fn sanitize(&self) -> Result<(), SanitizeError> {
            let num_static_account_keys = self.account_keys.len();
            if usize::from(self.header.num_required_signatures)
                .saturating_add(usize::from(self.header.num_readonly_unsigned_accounts))
                > num_static_account_keys
            {
                return Err(SanitizeError::IndexOutOfBounds);
            }

            // there should be at least 1 RW fee-payer account.
            if self.header.num_readonly_signed_accounts >= self.header.num_required_signatures {
                return Err(SanitizeError::InvalidValue);
            }

            let num_dynamic_account_keys = {
                let mut total_lookup_keys: usize = 0;
                for lookup in &self.address_table_lookups {
                    let num_lookup_indexes = lookup
                        .writable_indexes
                        .len()
                        .saturating_add(lookup.readonly_indexes.len());

                    // each lookup table must be used to load at least one account
                    if num_lookup_indexes == 0 {
                        return Err(SanitizeError::InvalidValue);
                    }

                    total_lookup_keys = total_lookup_keys.saturating_add(num_lookup_indexes);
                }
                total_lookup_keys
            };

            // this is redundant with the above sanitization checks which require that:
            // 1) the header describes at least 1 RW account
            // 2) the header doesn't describe more account keys than the number of account keys
            if num_static_account_keys == 0 {
                return Err(SanitizeError::InvalidValue);
            }

            // the combined number of static and dynamic account keys must be <= 256
            // since account indices are encoded as `u8`
            // Note that this is different from the per-transaction account load cap
            // as defined in `Bank::get_transaction_account_lock_limit`
            let total_account_keys =
                num_static_account_keys.saturating_add(num_dynamic_account_keys);
            if total_account_keys > 256 {
                return Err(SanitizeError::IndexOutOfBounds);
            }

            // `expect` is safe because of earlier check that
            // `num_static_account_keys` is non-zero
            let max_account_ix = total_account_keys
                .checked_sub(1)
                .expect("message doesn't contain any account keys");

            // reject program ids loaded from lookup tables so that
            // static analysis on program instructions can be performed
            // without loading on-chain data from a bank
            let max_program_id_ix =
            // `expect` is safe because of earlier check that
            // `num_static_account_keys` is non-zero
            num_static_account_keys
                .checked_sub(1)
                .expect("message doesn't contain any static account keys");

            for ci in &self.instructions {
                if usize::from(ci.program_id_index) > max_program_id_ix {
                    return Err(SanitizeError::IndexOutOfBounds);
                }
                // A program cannot be a payer.
                if ci.program_id_index == 0 {
                    return Err(SanitizeError::IndexOutOfBounds);
                }
                for ai in &ci.accounts {
                    if usize::from(*ai) > max_account_ix {
                        return Err(SanitizeError::IndexOutOfBounds);
                    }
                }
            }

            Ok(())
        }
    }

    impl Message {
        pub fn try_compile(
            payer: &Pubkey,
            instructions: &[Instruction],
            address_lookup_table_accounts: &[AddressLookupTableAccount],
            recent_blockhash: Hash,
        ) -> Result<Self, CompileError> {
            let mut compiled_keys = CompiledKeys::compile(instructions, Some(*payer));

            let mut address_table_lookups = Vec::with_capacity(address_lookup_table_accounts.len());
            let mut loaded_addresses_list = Vec::with_capacity(address_lookup_table_accounts.len());
            for lookup_table_account in address_lookup_table_accounts {
                if let Some((lookup, loaded_addresses)) =
                    compiled_keys.try_extract_table_lookup(lookup_table_account)?
                {
                    address_table_lookups.push(lookup);
                    loaded_addresses_list.push(loaded_addresses);
                }
            }

            let (header, static_keys) = compiled_keys.try_into_message_components()?;
            let dynamic_keys = loaded_addresses_list.into_iter().collect();
            let account_keys = AccountKeys::new(&static_keys, Some(&dynamic_keys));
            let instructions = account_keys.try_compile_instructions(instructions)?;

            Ok(Self {
                header,
                account_keys: static_keys,
                recent_blockhash,
                instructions,
                address_table_lookups,
            })
        }

        /// Serialize this message with a version #0 prefix using bincode encoding.
        pub fn serialize(&self) -> Vec<u8> {
            bincode::serialize(&(MESSAGE_VERSION_PREFIX, self)).unwrap()
        }

        /// Returns true if the account at the specified index is called as a program by an instruction
        pub fn is_key_called_as_program(&self, key_index: usize) -> bool {
            if let Ok(key_index) = u8::try_from(key_index) {
                self.instructions
                    .iter()
                    .any(|ix| ix.program_id_index == key_index)
            } else {
                false
            }
        }

        /// Returns true if the account at the specified index was requested to be
        /// writable.  This method should not be used directly.
        fn is_writable_index(&self, key_index: usize) -> bool {
            let header = &self.header;
            let num_account_keys = self.account_keys.len();
            let num_signed_accounts = usize::from(header.num_required_signatures);
            if key_index >= num_account_keys {
                let loaded_addresses_index = key_index.saturating_sub(num_account_keys);
                let num_writable_dynamic_addresses = self
                    .address_table_lookups
                    .iter()
                    .map(|lookup| lookup.writable_indexes.len())
                    .sum();
                loaded_addresses_index < num_writable_dynamic_addresses
            } else if key_index >= num_signed_accounts {
                let num_unsigned_accounts = num_account_keys.saturating_sub(num_signed_accounts);
                let num_writable_unsigned_accounts = num_unsigned_accounts
                    .saturating_sub(usize::from(header.num_readonly_unsigned_accounts));
                let unsigned_account_index = key_index.saturating_sub(num_signed_accounts);
                unsigned_account_index < num_writable_unsigned_accounts
            } else {
                let num_writable_signed_accounts = num_signed_accounts
                    .saturating_sub(usize::from(header.num_readonly_signed_accounts));
                key_index < num_writable_signed_accounts
            }
        }

        /// Returns true if any static account key is the bpf upgradeable loader
        fn is_upgradeable_loader_in_static_keys(&self) -> bool {
            self.account_keys
                .iter()
                .any(|&key| key == bpf_loader_upgradeable::id())
        }

        /// Returns true if the account at the specified index was requested as
        /// writable. Before loading addresses, we can't demote write locks properly
        /// so this should not be used by the runtime. The `reserved_account_keys`
        /// param is optional to allow clients to approximate writability without
        /// requiring fetching the latest set of reserved account keys.
        pub fn is_maybe_writable(
            &self,
            key_index: usize,
            reserved_account_keys: Option<&HashSet<Pubkey>>,
        ) -> bool {
            self.is_writable_index(key_index)
                && !self.is_account_maybe_reserved(key_index, reserved_account_keys)
                && !{
                    // demote program ids
                    self.is_key_called_as_program(key_index)
                        && !self.is_upgradeable_loader_in_static_keys()
                }
        }

        /// Returns true if the account at the specified index is in the reserved
        /// account keys set. Before loading addresses, we can't detect reserved
        /// account keys properly so this shouldn't be used by the runtime.
        fn is_account_maybe_reserved(
            &self,
            key_index: usize,
            reserved_account_keys: Option<&HashSet<Pubkey>>,
        ) -> bool {
            let mut is_maybe_reserved = false;
            if let Some(reserved_account_keys) = reserved_account_keys {
                if let Some(key) = self.account_keys.get(key_index) {
                    is_maybe_reserved = reserved_account_keys.contains(key);
                }
            }
            is_maybe_reserved
        }
    }

    /// Combination of a version #0 message and its loaded addresses
    #[derive(Debug, Clone, Eq, PartialEq)]
    pub struct LoadedMessage<'a> {
        /// Message which loaded a collection of lookup table addresses
        pub message: Cow<'a, Message>,
        /// Addresses loaded with on-chain address lookup tables
        pub loaded_addresses: Cow<'a, LoadedAddresses>,
        /// List of boolean with same length as account_keys(), each boolean value indicates if
        /// corresponding account key is writable or not.
        pub is_writable_account_cache: Vec<bool>,
    }

    impl FromIterator<LoadedAddresses> for LoadedAddresses {
        fn from_iter<T: IntoIterator<Item = LoadedAddresses>>(iter: T) -> Self {
            let (writable, readonly): (Vec<Vec<Pubkey>>, Vec<Vec<Pubkey>>) = iter
                .into_iter()
                .map(|addresses| (addresses.writable, addresses.readonly))
                .unzip();
            LoadedAddresses {
                writable: writable.into_iter().flatten().collect(),
                readonly: readonly.into_iter().flatten().collect(),
            }
        }
    }

    impl LoadedAddresses {
        /// Checks if there are no writable or readonly addresses
        pub fn is_empty(&self) -> bool {
            self.len() == 0
        }

        /// Combined length of loaded writable and readonly addresses
        pub fn len(&self) -> usize {
            self.writable.len().saturating_add(self.readonly.len())
        }
    }

    impl<'a> LoadedMessage<'a> {
        pub fn new(
            message: Message,
            loaded_addresses: LoadedAddresses,
            reserved_account_keys: &HashSet<Pubkey>,
        ) -> Self {
            let mut loaded_message = Self {
                message: Cow::Owned(message),
                loaded_addresses: Cow::Owned(loaded_addresses),
                is_writable_account_cache: Vec::default(),
            };
            loaded_message.set_is_writable_account_cache(reserved_account_keys);
            loaded_message
        }

        pub fn new_borrowed(
            message: &'a Message,
            loaded_addresses: &'a LoadedAddresses,
            reserved_account_keys: &HashSet<Pubkey>,
        ) -> Self {
            let mut loaded_message = Self {
                message: Cow::Borrowed(message),
                loaded_addresses: Cow::Borrowed(loaded_addresses),
                is_writable_account_cache: Vec::default(),
            };
            loaded_message.set_is_writable_account_cache(reserved_account_keys);
            loaded_message
        }

        fn set_is_writable_account_cache(&mut self, reserved_account_keys: &HashSet<Pubkey>) {
            let is_writable_account_cache = self
                .account_keys()
                .iter()
                .enumerate()
                .map(|(i, _key)| self.is_writable_internal(i, reserved_account_keys))
                .collect::<Vec<_>>();
            let _ = std::mem::replace(
                &mut self.is_writable_account_cache,
                is_writable_account_cache,
            );
        }

        /// Returns the full list of static and dynamic account keys that are loaded for this message.
        pub fn account_keys(&self) -> AccountKeys {
            AccountKeys::new(&self.message.account_keys, Some(&self.loaded_addresses))
        }

        /// Returns the list of static account keys that are loaded for this message.
        pub fn static_account_keys(&self) -> &[Pubkey] {
            &self.message.account_keys
        }

        /// Returns true if any account keys are duplicates
        pub fn has_duplicates(&self) -> bool {
            let mut uniq = HashSet::new();
            self.account_keys().iter().any(|x| !uniq.insert(x))
        }

        /// Returns true if the account at the specified index was requested to be
        /// writable.  This method should not be used directly.
        fn is_writable_index(&self, key_index: usize) -> bool {
            let header = &self.message.header;
            let num_account_keys = self.message.account_keys.len();
            let num_signed_accounts = usize::from(header.num_required_signatures);
            if key_index >= num_account_keys {
                let loaded_addresses_index = key_index.saturating_sub(num_account_keys);
                loaded_addresses_index < self.loaded_addresses.writable.len()
            } else if key_index >= num_signed_accounts {
                let num_unsigned_accounts = num_account_keys.saturating_sub(num_signed_accounts);
                let num_writable_unsigned_accounts = num_unsigned_accounts
                    .saturating_sub(usize::from(header.num_readonly_unsigned_accounts));
                let unsigned_account_index = key_index.saturating_sub(num_signed_accounts);
                unsigned_account_index < num_writable_unsigned_accounts
            } else {
                let num_writable_signed_accounts = num_signed_accounts
                    .saturating_sub(usize::from(header.num_readonly_signed_accounts));
                key_index < num_writable_signed_accounts
            }
        }

        /// Returns true if the account at the specified index was loaded as writable
        fn is_writable_internal(
            &self,
            key_index: usize,
            reserved_account_keys: &HashSet<Pubkey>,
        ) -> bool {
            if self.is_writable_index(key_index) {
                if let Some(key) = self.account_keys().get(key_index) {
                    return !(reserved_account_keys.contains(key)
                        || self.demote_program_id(key_index));
                }
            }
            false
        }

        pub fn is_writable(&self, key_index: usize) -> bool {
            *self
                .is_writable_account_cache
                .get(key_index)
                .unwrap_or(&false)
        }

        pub fn is_signer(&self, i: usize) -> bool {
            i < self.message.header.num_required_signatures as usize
        }

        pub fn demote_program_id(&self, i: usize) -> bool {
            self.is_key_called_as_program(i) && !self.is_upgradeable_loader_present()
        }

        /// Returns true if the account at the specified index is called as a program by an instruction
        pub fn is_key_called_as_program(&self, key_index: usize) -> bool {
            if let Ok(key_index) = u8::try_from(key_index) {
                self.message
                    .instructions
                    .iter()
                    .any(|ix| ix.program_id_index == key_index)
            } else {
                false
            }
        }

        /// Returns true if any account is the bpf upgradeable loader
        pub fn is_upgradeable_loader_present(&self) -> bool {
            self.account_keys()
                .iter()
                .any(|&key| key == bpf_loader_upgradeable::id())
        }
    }
}
