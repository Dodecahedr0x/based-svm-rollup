mod account;
mod compute_budget;
mod environment_config;
mod feature_set;
mod instruction;
mod log_collector;
mod measure;
mod program_cache;
mod program_ids;
mod pubkey;
mod solana_ed25519_program;
mod solana_secp256k1_program;
mod solana_secp256r1_program;
mod stable_log;
mod syscall;
mod timings;
mod transaction_context;

use core::fmt;
use std::{
    cell::RefCell,
    error::Error,
    marker::PhantomData,
    mem::ManuallyDrop,
    num::Saturating,
    ops::{Index, IndexMut},
    rc::Rc,
    sync::{atomic::Ordering, Arc},
};

pub use account::*;
pub use compute_budget::*;
use enum_iterator::Sequence;
pub use environment_config::*;
pub use feature_set::*;
pub use instruction::*;
use lazy_static::lazy_static;
pub use log_collector::*;
pub use measure::*;
use num_traits::FromPrimitive;
pub use program_cache::*;
pub use program_ids::*;
pub use pubkey::*;
use solana_sbpf::{
    error::{EbpfError, ProgramResult},
    memory_region::MemoryMapping,
    program::SBPFVersion,
    vm::{Config, ContextObject, EbpfVm},
};
pub use syscall::*;
pub use timings::*;
pub use transaction_context::*;

#[repr(C)]
pub struct StableVec<T> {
    pub addr: u64,
    pub cap: u64,
    pub len: u64,
    _marker: PhantomData<T>,
}
// We shadow these slice methods of the same name to avoid going through
// `deref`, which creates an intermediate reference.
impl<T> StableVec<T> {
    #[inline]
    pub fn as_vaddr(&self) -> u64 {
        self.addr
    }

    #[inline]
    pub fn len(&self) -> u64 {
        self.len
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

// impl<T> AsRef<[T]> for StableVec<T> {
//     fn as_ref(&self) -> &[T] {
//         self.deref()
//     }
// }

// impl<T> AsMut<[T]> for StableVec<T> {
//     fn as_mut(&mut self) -> &mut [T] {
//         self.deref_mut()
//     }
// }

impl<T> std::ops::Deref for StableVec<T> {
    type Target = [T];

    #[inline]
    fn deref(&self) -> &[T] {
        unsafe { core::slice::from_raw_parts(self.addr as usize as *mut T, self.len as usize) }
    }
}

impl<T> std::ops::DerefMut for StableVec<T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut [T] {
        unsafe { core::slice::from_raw_parts_mut(self.addr as usize as *mut T, self.len as usize) }
    }
}

impl<T: std::fmt::Debug> std::fmt::Debug for StableVec<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&**self, f)
    }
}

macro_rules! impl_partial_eq {
    ([$($vars:tt)*] $lhs:ty, $rhs:ty) => {
        impl<T, U, $($vars)*> PartialEq<$rhs> for $lhs
        where
            T: PartialEq<U>,
        {
            #[inline]
            fn eq(&self, other: &$rhs) -> bool { self[..] == other[..] }
        }
    }
}
impl_partial_eq! { [] StableVec<T>, StableVec<U> }
impl_partial_eq! { [] StableVec<T>, Vec<U> }
impl_partial_eq! { [] Vec<T>, StableVec<U> }
impl_partial_eq! { [] StableVec<T>, &[U] }
impl_partial_eq! { [] StableVec<T>, &mut [U] }
impl_partial_eq! { [] &[T], StableVec<U> }
impl_partial_eq! { [] &mut [T], StableVec<U> }
impl_partial_eq! { [] StableVec<T>, [U] }
impl_partial_eq! { [] [T], StableVec<U> }
impl_partial_eq! { [const N: usize] StableVec<T>, [U; N] }
impl_partial_eq! { [const N: usize] StableVec<T>, &[U; N] }

impl<T> From<Vec<T>> for StableVec<T> {
    fn from(other: Vec<T>) -> Self {
        // NOTE: This impl is basically copied from `Vec::into_raw_parts()`.  Once that fn is
        // stabilized, use it here.
        //
        // We are going to pilfer `other`'s guts, and we don't want it to be dropped when it goes
        // out of scope.
        let mut other = ManuallyDrop::new(other);
        Self {
            // SAFETY: We have a valid Vec, so its ptr is non-null.
            addr: other.as_mut_ptr() as u64, // Problematic if other is in 32-bit physical address space
            cap: other.capacity() as u64,
            len: other.len() as u64,
            _marker: PhantomData,
        }
    }
}

impl<T> From<StableVec<T>> for Vec<T> {
    fn from(other: StableVec<T>) -> Self {
        // We are going to pilfer `other`'s guts, and we don't want it to be dropped when it goes
        // out of scope.
        let other = ManuallyDrop::new(other);
        // SAFETY: We have a valid StableVec, which we can only get from a Vec.  Therefore it is
        // safe to convert back to Vec. Assuming we're not starting with a vector in 64-bit virtual
        // address space while building the app in 32-bit, and this vector is in that 32-bit physical
        // space.
        unsafe {
            Vec::from_raw_parts(
                other.addr as usize as *mut T,
                other.len as usize,
                other.cap as usize,
            )
        }
    }
}

impl<T> Drop for StableVec<T> {
    fn drop(&mut self) {
        // We only allow creating a StableVec through creating a Vec.  To ensure we are dropped
        // correctly, convert ourselves back to a Vec and let Vec's drop handling take over.
        //
        // SAFETY: We have a valid StableVec, which we can only get from a Vec.  Therefore it is
        // safe to convert back to Vec.
        let _vec = unsafe {
            Vec::from_raw_parts(
                self.addr as usize as *mut T,
                self.len as usize,
                self.cap as usize,
            )
        };
    }
}

#[derive(Debug, PartialEq)]
#[repr(C)]
pub struct StableInstruction {
    pub accounts: StableVec<AccountMeta>,
    pub data: StableVec<u8>,
    pub program_id: Pubkey,
}

impl From<Instruction> for StableInstruction {
    fn from(other: Instruction) -> Self {
        Self {
            accounts: other.accounts.into(),
            data: other.data.into(),
            program_id: other.program_id,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Instruction {
    /// Pubkey of the program that executes this instruction.
    pub program_id: Pubkey,
    /// Metadata describing accounts that should be passed to the program.
    pub accounts: Vec<AccountMeta>,
    /// Opaque data passed to the program for its own interpretation.
    pub data: Vec<u8>,
}

/// wasm-bindgen version of the Instruction struct.
/// This duplication is required until https://github.com/rustwasm/wasm-bindgen/issues/3671
/// is fixed. This must not diverge from the regular non-wasm Instruction struct.
#[cfg(all(feature = "std", target_arch = "wasm32"))]
#[wasm_bindgen::prelude::wasm_bindgen]
#[cfg_attr(
    feature = "serde",
    derive(serde_derive::Serialize, serde_derive::Deserialize)
)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Instruction {
    #[wasm_bindgen(skip)]
    pub program_id: Pubkey,
    #[wasm_bindgen(skip)]
    pub accounts: Vec<AccountMeta>,
    #[wasm_bindgen(skip)]
    pub data: Vec<u8>,
}

#[cfg(feature = "std")]
impl Instruction {
    #[cfg(feature = "borsh")]
    /// Create a new instruction from a value, encoded with [`borsh`].
    ///
    /// [`borsh`]: https://docs.rs/borsh/latest/borsh/
    ///
    /// `program_id` is the address of the program that will execute the instruction.
    /// `accounts` contains a description of all accounts that may be accessed by the program.
    ///
    /// Borsh serialization is often preferred over bincode as it has a stable
    /// [specification] and an [implementation in JavaScript][jsb], neither of
    /// which are true of bincode.
    ///
    /// [specification]: https://borsh.io/
    /// [jsb]: https://github.com/near/borsh-js
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_pubkey::Pubkey;
    /// # use solana_instruction::{AccountMeta, Instruction};
    /// # use borsh::{BorshSerialize, BorshDeserialize};
    /// #
    /// #[derive(BorshSerialize, BorshDeserialize)]
    /// # #[borsh(crate = "borsh")]
    /// pub struct MyInstruction {
    ///     pub lamports: u64,
    /// }
    ///
    /// pub fn create_instruction(
    ///     program_id: &Pubkey,
    ///     from: &Pubkey,
    ///     to: &Pubkey,
    ///     lamports: u64,
    /// ) -> Instruction {
    ///     let instr = MyInstruction { lamports };
    ///
    ///     Instruction::new_with_borsh(
    ///         *program_id,
    ///         &instr,
    ///         vec![
    ///             AccountMeta::new(*from, true),
    ///             AccountMeta::new(*to, false),
    ///         ],
    ///    )
    /// }
    /// ```
    pub fn new_with_borsh<T: borsh::BorshSerialize>(
        program_id: Pubkey,
        data: &T,
        accounts: Vec<AccountMeta>,
    ) -> Self {
        let data = borsh::to_vec(data).unwrap();
        Self {
            program_id,
            accounts,
            data,
        }
    }

    #[cfg(feature = "bincode")]
    /// Create a new instruction from a value, encoded with [`bincode`].
    ///
    /// [`bincode`]: https://docs.rs/bincode/latest/bincode/
    ///
    /// `program_id` is the address of the program that will execute the instruction.
    /// `accounts` contains a description of all accounts that may be accessed by the program.
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_pubkey::Pubkey;
    /// # use solana_instruction::{AccountMeta, Instruction};
    /// # use serde::{Serialize, Deserialize};
    /// #
    /// #[derive(Serialize, Deserialize)]
    /// pub struct MyInstruction {
    ///     pub lamports: u64,
    /// }
    ///
    /// pub fn create_instruction(
    ///     program_id: &Pubkey,
    ///     from: &Pubkey,
    ///     to: &Pubkey,
    ///     lamports: u64,
    /// ) -> Instruction {
    ///     let instr = MyInstruction { lamports };
    ///
    ///     Instruction::new_with_bincode(
    ///         *program_id,
    ///         &instr,
    ///         vec![
    ///             AccountMeta::new(*from, true),
    ///             AccountMeta::new(*to, false),
    ///         ],
    ///    )
    /// }
    /// ```
    pub fn new_with_bincode<T: serde::Serialize>(
        program_id: Pubkey,
        data: &T,
        accounts: Vec<AccountMeta>,
    ) -> Self {
        let data = bincode::serialize(data).unwrap();
        Self {
            program_id,
            accounts,
            data,
        }
    }

    /// Create a new instruction from a byte slice.
    ///
    /// `program_id` is the address of the program that will execute the instruction.
    /// `accounts` contains a description of all accounts that may be accessed by the program.
    ///
    /// The caller is responsible for ensuring the correct encoding of `data` as expected
    /// by the callee program.
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_pubkey::Pubkey;
    /// # use solana_instruction::{AccountMeta, Instruction};
    /// #
    /// # use borsh::{io::Error, BorshSerialize, BorshDeserialize};
    /// #
    /// #[derive(BorshSerialize, BorshDeserialize)]
    /// # #[borsh(crate = "borsh")]
    /// pub struct MyInstruction {
    ///     pub lamports: u64,
    /// }
    ///
    /// pub fn create_instruction(
    ///     program_id: &Pubkey,
    ///     from: &Pubkey,
    ///     to: &Pubkey,
    ///     lamports: u64,
    /// ) -> Result<Instruction, Error> {
    ///     let instr = MyInstruction { lamports };
    ///
    ///     let mut instr_in_bytes: Vec<u8> = Vec::new();
    ///     instr.serialize(&mut instr_in_bytes)?;
    ///
    ///     Ok(Instruction::new_with_bytes(
    ///         *program_id,
    ///         &instr_in_bytes,
    ///         vec![
    ///             AccountMeta::new(*from, true),
    ///             AccountMeta::new(*to, false),
    ///         ],
    ///    ))
    /// }
    /// ```
    pub fn new_with_bytes(program_id: Pubkey, data: &[u8], accounts: Vec<AccountMeta>) -> Self {
        Self {
            program_id,
            accounts,
            data: data.to_vec(),
        }
    }
}

#[repr(C)]
#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct AccountMeta {
    /// An account's public key.
    pub pubkey: Pubkey,
    /// True if an `Instruction` requires a `Transaction` signature matching `pubkey`.
    pub is_signer: bool,
    /// True if the account data or metadata may be mutated during program execution.
    pub is_writable: bool,
}

impl AccountMeta {
    /// Construct metadata for a writable account.
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_pubkey::Pubkey;
    /// # use solana_instruction::{AccountMeta, Instruction};
    /// # use borsh::{BorshSerialize, BorshDeserialize};
    /// #
    /// # #[derive(BorshSerialize, BorshDeserialize)]
    /// # #[borsh(crate = "borsh")]
    /// # pub struct MyInstruction;
    /// #
    /// # let instruction = MyInstruction;
    /// # let from = Pubkey::new_unique();
    /// # let to = Pubkey::new_unique();
    /// # let program_id = Pubkey::new_unique();
    /// let instr = Instruction::new_with_borsh(
    ///     program_id,
    ///     &instruction,
    ///     vec![
    ///         AccountMeta::new(from, true),
    ///         AccountMeta::new(to, false),
    ///     ],
    /// );
    /// ```
    pub fn new(pubkey: Pubkey, is_signer: bool) -> Self {
        Self {
            pubkey,
            is_signer,
            is_writable: true,
        }
    }

    /// Construct metadata for a read-only account.
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_pubkey::Pubkey;
    /// # use solana_instruction::{AccountMeta, Instruction};
    /// # use borsh::{BorshSerialize, BorshDeserialize};
    /// #
    /// # #[derive(BorshSerialize, BorshDeserialize)]
    /// # #[borsh(crate = "borsh")]
    /// # pub struct MyInstruction;
    /// #
    /// # let instruction = MyInstruction;
    /// # let from = Pubkey::new_unique();
    /// # let to = Pubkey::new_unique();
    /// # let from_account_storage = Pubkey::new_unique();
    /// # let program_id = Pubkey::new_unique();
    /// let instr = Instruction::new_with_borsh(
    ///     program_id,
    ///     &instruction,
    ///     vec![
    ///         AccountMeta::new(from, true),
    ///         AccountMeta::new(to, false),
    ///         AccountMeta::new_readonly(from_account_storage, false),
    ///     ],
    /// );
    /// ```
    pub fn new_readonly(pubkey: Pubkey, is_signer: bool) -> Self {
        Self {
            pubkey,
            is_signer,
            is_writable: false,
        }
    }
}

#[derive(Debug, Sequence)]
pub enum ExecuteTimingType {
    CheckUs,
    ValidateFeesUs,
    LoadUs,
    ExecuteUs,
    StoreUs,
    UpdateStakesCacheUs,
    UpdateExecutorsUs,
    NumExecuteBatches,
    CollectLogsUs,
    TotalBatchesLen,
    UpdateTransactionStatuses,
    ProgramCacheUs,
    CheckBlockLimitsUs,
    FilterExecutableUs,
}

pub struct Metrics([Saturating<u64>; ExecuteTimingType::CARDINALITY]);

impl Index<ExecuteTimingType> for Metrics {
    type Output = Saturating<u64>;
    fn index(&self, index: ExecuteTimingType) -> &Self::Output {
        self.0.index(index as usize)
    }
}

impl IndexMut<ExecuteTimingType> for Metrics {
    fn index_mut(&mut self, index: ExecuteTimingType) -> &mut Self::Output {
        self.0.index_mut(index as usize)
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Metrics([Saturating(0); ExecuteTimingType::CARDINALITY])
    }
}

impl core::fmt::Debug for Metrics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Default, Debug)]
pub struct ExecuteAccessoryTimings {
    pub feature_set_clone_us: Saturating<u64>,
    pub get_executors_us: Saturating<u64>,
    pub process_message_us: Saturating<u64>,
    pub process_instructions: ExecuteProcessInstructionTimings,
}

impl ExecuteAccessoryTimings {
    pub fn accumulate(&mut self, other: &ExecuteAccessoryTimings) {
        self.feature_set_clone_us += other.feature_set_clone_us;
        self.get_executors_us += other.get_executors_us;
        self.process_message_us += other.process_message_us;
        self.process_instructions
            .accumulate(&other.process_instructions);
    }
}

#[derive(Default, Debug)]
pub struct ExecuteProcessInstructionTimings {
    pub total_us: Saturating<u64>,
    pub verify_caller_us: Saturating<u64>,
    pub process_executable_chain_us: Saturating<u64>,
    pub verify_callee_us: Saturating<u64>,
}

impl ExecuteProcessInstructionTimings {
    pub fn accumulate(&mut self, other: &ExecuteProcessInstructionTimings) {
        self.total_us += other.total_us;
        self.verify_caller_us += other.verify_caller_us;
        self.process_executable_chain_us += other.process_executable_chain_us;
        self.verify_callee_us += other.verify_callee_us;
    }
}

#[derive(Debug, Default)]
pub struct ExecuteTimings {
    pub metrics: Metrics,
    pub details: ExecuteDetailsTimings,
    pub execute_accessories: ExecuteAccessoryTimings,
}

impl ExecuteTimings {
    pub fn accumulate(&mut self, other: &ExecuteTimings) {
        for (t1, t2) in self.metrics.0.iter_mut().zip(other.metrics.0.iter()) {
            *t1 += *t2;
        }
        self.details.accumulate(&other.details);
        self.execute_accessories
            .accumulate(&other.execute_accessories);
    }

    pub fn saturating_add_in_place(&mut self, timing_type: ExecuteTimingType, value_to_add: u64) {
        let idx = timing_type as usize;
        match self.metrics.0.get_mut(idx) {
            Some(elem) => *elem += value_to_add,
            None => debug_assert!(idx < ExecuteTimingType::CARDINALITY, "Index out of bounds"),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct CompiledInstruction {
    /// Index into the transaction keys array indicating the program account that executes this instruction.
    pub program_id_index: u8,
    /// Ordered indices into the transaction keys array indicating which accounts to pass to the program.
    #[cfg_attr(feature = "serde", serde(with = "solana_short_vec"))]
    pub accounts: Vec<u8>,
    /// The program input data.
    #[cfg_attr(feature = "serde", serde(with = "solana_short_vec"))]
    pub data: Vec<u8>,
}

pub trait Sanitize {
    fn sanitize(&self) -> Result<(), SanitizeError> {
        Ok(())
    }
}

impl<T: Sanitize> Sanitize for Vec<T> {
    fn sanitize(&self) -> Result<(), SanitizeError> {
        for x in self.iter() {
            x.sanitize()?;
        }
        Ok(())
    }
}

#[derive(PartialEq, Debug, Eq, Clone)]
pub enum SanitizeError {
    IndexOutOfBounds,
    ValueOutOfBounds,
    InvalidValue,
}

impl Error for SanitizeError {}

impl fmt::Display for SanitizeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SanitizeError::IndexOutOfBounds => f.write_str("index out of bounds"),
            SanitizeError::ValueOutOfBounds => f.write_str("value out of bounds"),
            SanitizeError::InvalidValue => f.write_str("invalid value"),
        }
    }
}

impl Sanitize for CompiledInstruction {}

impl CompiledInstruction {
    #[cfg(feature = "bincode")]
    pub fn new<T: serde::Serialize>(program_ids_index: u8, data: &T, accounts: Vec<u8>) -> Self {
        let data = bincode::serialize(data).unwrap();
        Self {
            program_id_index: program_ids_index,
            accounts,
            data,
        }
    }

    pub fn new_from_raw_parts(program_id_index: u8, data: Vec<u8>, accounts: Vec<u8>) -> Self {
        Self {
            program_id_index,
            accounts,
            data,
        }
    }

    pub fn program_id<'a>(&self, program_ids: &'a [Pubkey]) -> &'a Pubkey {
        &program_ids[self.program_id_index as usize]
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrecompileError {
    InvalidPublicKey,
    InvalidRecoveryId,
    InvalidSignature,
    InvalidDataOffsets,
    InvalidInstructionDataSize,
}

impl num_traits::FromPrimitive for PrecompileError {
    #[inline]
    fn from_i64(n: i64) -> Option<Self> {
        if n == PrecompileError::InvalidPublicKey as i64 {
            Some(PrecompileError::InvalidPublicKey)
        } else if n == PrecompileError::InvalidRecoveryId as i64 {
            Some(PrecompileError::InvalidRecoveryId)
        } else if n == PrecompileError::InvalidSignature as i64 {
            Some(PrecompileError::InvalidSignature)
        } else if n == PrecompileError::InvalidDataOffsets as i64 {
            Some(PrecompileError::InvalidDataOffsets)
        } else if n == PrecompileError::InvalidInstructionDataSize as i64 {
            Some(PrecompileError::InvalidInstructionDataSize)
        } else {
            None
        }
    }
    #[inline]
    fn from_u64(n: u64) -> Option<Self> {
        Self::from_i64(n as i64)
    }
}

impl num_traits::ToPrimitive for PrecompileError {
    #[inline]
    fn to_i64(&self) -> Option<i64> {
        Some(match *self {
            PrecompileError::InvalidPublicKey => PrecompileError::InvalidPublicKey as i64,
            PrecompileError::InvalidRecoveryId => PrecompileError::InvalidRecoveryId as i64,
            PrecompileError::InvalidSignature => PrecompileError::InvalidSignature as i64,
            PrecompileError::InvalidDataOffsets => PrecompileError::InvalidDataOffsets as i64,
            PrecompileError::InvalidInstructionDataSize => {
                PrecompileError::InvalidInstructionDataSize as i64
            }
        })
    }
    #[inline]
    fn to_u64(&self) -> Option<u64> {
        self.to_i64().map(|x| x as u64)
    }
}

impl std::error::Error for PrecompileError {}

impl fmt::Display for PrecompileError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PrecompileError::InvalidPublicKey => f.write_str("public key is not valid"),
            PrecompileError::InvalidRecoveryId => f.write_str("id is not valid"),
            PrecompileError::InvalidSignature => f.write_str("signature is not valid"),
            PrecompileError::InvalidDataOffsets => f.write_str("offset not valid"),
            PrecompileError::InvalidInstructionDataSize => {
                f.write_str("instruction is incorrect size")
            }
        }
    }
}

pub trait DecodeError<E> {
    fn decode_custom_error_to_enum(custom: u32) -> Option<E>
    where
        E: FromPrimitive,
    {
        E::from_u32(custom)
    }
    fn type_of() -> &'static str;
}

impl<T> DecodeError<T> for PrecompileError {
    fn type_of() -> &'static str {
        "PrecompileError"
    }
}

/// All precompiled programs must implement the `Verify` function
pub type Verify = fn(&[u8], &[&[u8]], &FeatureSet) -> std::result::Result<(), PrecompileError>;

/// Information on a precompiled program
pub struct Precompile {
    /// Program id
    pub program_id: Pubkey,
    /// Feature to enable on, `None` indicates always enabled
    pub feature: Option<Pubkey>,
    /// Verification function
    pub verify_fn: Verify,
}
impl Precompile {
    /// Creates a new `Precompile`
    pub fn new(program_id: Pubkey, feature: Option<Pubkey>, verify_fn: Verify) -> Self {
        Precompile {
            program_id,
            feature,
            verify_fn,
        }
    }
    /// Check if a program id is this precompiled program
    pub fn check_id<F>(&self, program_id: &Pubkey, is_enabled: F) -> bool
    where
        F: Fn(&Pubkey) -> bool,
    {
        self.feature
            .map_or(true, |ref feature_id| is_enabled(feature_id))
            && self.program_id == *program_id
    }
    /// Verify this precompiled program
    pub fn verify(
        &self,
        data: &[u8],
        instruction_datas: &[&[u8]],
        feature_set: &FeatureSet,
    ) -> std::result::Result<(), PrecompileError> {
        (self.verify_fn)(data, instruction_datas, feature_set)
    }
}

lazy_static! {
    /// The list of all precompiled programs
    static ref PRECOMPILES: Vec<Precompile> = vec![
        Precompile::new(
            secp256k1_program::id(),
            None, // always enabled
            solana_secp256k1_program::verify,
        ),
        Precompile::new(
            ed25519_program::id(),
            None, // always enabled
            solana_ed25519_program::verify,
        ),
        Precompile::new(
            secp256r1_program::id(),
            Some(enable_secp256r1_precompile::id()),
            solana_secp256r1_program::verify,
        )
    ];
}

/// Check if a program is a precompiled program
pub fn is_precompile<F>(program_id: &Pubkey, is_enabled: F) -> bool
where
    F: Fn(&Pubkey) -> bool,
{
    PRECOMPILES
        .iter()
        .any(|precompile| precompile.check_id(program_id, |feature_id| is_enabled(feature_id)))
}

/// Find an enabled precompiled program
pub fn get_precompile<F>(program_id: &Pubkey, is_enabled: F) -> Option<&Precompile>
where
    F: Fn(&Pubkey) -> bool,
{
    PRECOMPILES
        .iter()
        .find(|precompile| precompile.check_id(program_id, |feature_id| is_enabled(feature_id)))
}

pub fn get_precompiles<'a>() -> &'a [Precompile] {
    &PRECOMPILES
}

/// Check that a program is precompiled and if so verify it
pub fn verify_if_precompile(
    program_id: &Pubkey,
    precompile_instruction: &CompiledInstruction,
    all_instructions: &[CompiledInstruction],
    feature_set: &FeatureSet,
) -> Result<(), PrecompileError> {
    for precompile in PRECOMPILES.iter() {
        if precompile.check_id(program_id, |feature_id| feature_set.is_active(feature_id)) {
            let instruction_datas: Vec<_> = all_instructions
                .iter()
                .map(|instruction| instruction.data.as_ref())
                .collect();
            return precompile.verify(
                &precompile_instruction.data,
                &instruction_datas,
                feature_set,
            );
        }
    }
    Ok(())
}

pub struct InvokeContext<'a> {
    /// Information about the currently executing transaction.
    pub transaction_context: &'a mut TransactionContext,
    /// The local program cache for the transaction batch.
    pub program_cache_for_tx_batch: &'a mut ProgramCacheForTxBatch,
    /// Runtime configurations used to provision the invocation environment.
    pub environment_config: EnvironmentConfig<'a>,
    /// The compute budget for the current invocation.
    compute_budget: ComputeBudget,
    /// Instruction compute meter, for tracking compute units consumed against
    /// the designated compute budget during program execution.
    compute_meter: RefCell<u64>,
    log_collector: Option<Rc<RefCell<LogCollector>>>,
    /// Latest measurement not yet accumulated in [ExecuteDetailsTimings::execute_us]
    pub execute_time: Option<Measure>,
    pub timings: ExecuteDetailsTimings,
    pub syscall_context: Vec<Option<SyscallContext>>,
    traces: Vec<Vec<[u64; 12]>>,
}

impl ContextObject for InvokeContext<'_> {
    fn trace(&mut self, state: [u64; 12]) {
        self.syscall_context
            .last_mut()
            .unwrap()
            .as_mut()
            .unwrap()
            .trace_log
            .push(state);
    }

    fn consume(&mut self, amount: u64) {
        // 1 to 1 instruction to compute unit mapping
        // ignore overflow, Ebpf will bail if exceeded
        let mut compute_meter = self.compute_meter.borrow_mut();
        *compute_meter = compute_meter.saturating_sub(amount);
    }

    fn get_remaining(&self) -> u64 {
        *self.compute_meter.borrow()
    }
}

impl<'a> InvokeContext<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        transaction_context: &'a mut TransactionContext,
        program_cache_for_tx_batch: &'a mut ProgramCacheForTxBatch,
        environment_config: EnvironmentConfig<'a>,
        log_collector: Option<Rc<RefCell<LogCollector>>>,
        compute_budget: ComputeBudget,
    ) -> Self {
        Self {
            transaction_context,
            program_cache_for_tx_batch,
            environment_config,
            log_collector,
            compute_budget,
            compute_meter: RefCell::new(compute_budget.compute_unit_limit),
            execute_time: None,
            timings: ExecuteDetailsTimings::default(),
            syscall_context: Vec::new(),
            traces: Vec::new(),
        }
    }

    pub fn get_environments_for_slot(
        &self,
        effective_slot: Slot,
    ) -> Result<&ProgramRuntimeEnvironments, InstructionError> {
        let epoch_schedule = self.environment_config.sysvar_cache.get_epoch_schedule()?;
        let epoch = epoch_schedule.get_epoch(effective_slot);
        Ok(self
            .program_cache_for_tx_batch
            .get_environments_for_epoch(epoch))
    }

    /// Push a stack frame onto the invocation stack
    pub fn push(&mut self) -> Result<(), InstructionError> {
        let instruction_context = self
            .transaction_context
            .get_instruction_context_at_index_in_trace(
                self.transaction_context.get_instruction_trace_length(),
            )?;
        let program_id = instruction_context
            .get_last_program_key(self.transaction_context)
            .map_err(|_| InstructionError::UnsupportedProgramId)?;
        if self
            .transaction_context
            .get_instruction_context_stack_height()
            != 0
        {
            let contains = (0..self
                .transaction_context
                .get_instruction_context_stack_height())
                .any(|level| {
                    self.transaction_context
                        .get_instruction_context_at_nesting_level(level)
                        .and_then(|instruction_context| {
                            instruction_context
                                .try_borrow_last_program_account(self.transaction_context)
                        })
                        .map(|program_account| program_account.get_key() == program_id)
                        .unwrap_or(false)
                });
            let is_last = self
                .transaction_context
                .get_current_instruction_context()
                .and_then(|instruction_context| {
                    instruction_context.try_borrow_last_program_account(self.transaction_context)
                })
                .map(|program_account| program_account.get_key() == program_id)
                .unwrap_or(false);
            if contains && !is_last {
                // Reentrancy not allowed unless caller is calling itself
                return Err(InstructionError::ReentrancyNotAllowed);
            }
        }

        self.syscall_context.push(None);
        self.transaction_context.push()
    }

    /// Pop a stack frame from the invocation stack
    fn pop(&mut self) -> Result<(), InstructionError> {
        if let Some(Some(syscall_context)) = self.syscall_context.pop() {
            self.traces.push(syscall_context.trace_log);
        }
        self.transaction_context.pop()
    }

    /// Current height of the invocation stack, top level instructions are height
    /// `solana_instruction::TRANSACTION_LEVEL_STACK_HEIGHT`
    pub fn get_stack_height(&self) -> usize {
        self.transaction_context
            .get_instruction_context_stack_height()
    }

    /// Entrypoint for a cross-program invocation from a builtin program
    pub fn native_invoke(
        &mut self,
        instruction: StableInstruction,
        signers: &[Pubkey],
    ) -> Result<(), InstructionError> {
        let (instruction_accounts, program_indices) =
            self.prepare_instruction(&instruction, signers)?;
        let mut compute_units_consumed = 0;
        self.process_instruction(
            &instruction.data,
            &instruction_accounts,
            &program_indices,
            &mut compute_units_consumed,
            &mut ExecuteTimings::default(),
        )?;
        Ok(())
    }

    /// Helper to prepare for process_instruction()
    #[allow(clippy::type_complexity)]
    pub fn prepare_instruction(
        &mut self,
        instruction: &StableInstruction,
        signers: &[Pubkey],
    ) -> Result<(Vec<InstructionAccount>, Vec<IndexOfAccount>), InstructionError> {
        // Finds the index of each account in the instruction by its pubkey.
        // Then normalizes / unifies the privileges of duplicate accounts.
        // Note: This is an O(n^2) algorithm,
        // but performed on a very small slice and requires no heap allocations.
        let instruction_context = self.transaction_context.get_current_instruction_context()?;
        let mut deduplicated_instruction_accounts: Vec<InstructionAccount> = Vec::new();
        let mut duplicate_indicies = Vec::with_capacity(instruction.accounts.len() as usize);
        for (instruction_account_index, account_meta) in instruction.accounts.iter().enumerate() {
            let index_in_transaction = self
                .transaction_context
                .find_index_of_account(&account_meta.pubkey)
                .ok_or_else(|| {
                    ic_msg!(
                        self,
                        "Instruction references an unknown account {:?}",
                        account_meta.pubkey,
                    );
                    InstructionError::MissingAccount
                })?;
            if let Some(duplicate_index) =
                deduplicated_instruction_accounts
                    .iter()
                    .position(|instruction_account| {
                        instruction_account.index_in_transaction == index_in_transaction
                    })
            {
                duplicate_indicies.push(duplicate_index);
                let instruction_account = deduplicated_instruction_accounts
                    .get_mut(duplicate_index)
                    .ok_or(InstructionError::NotEnoughAccountKeys)?;
                instruction_account.is_signer |= account_meta.is_signer;
                instruction_account.is_writable |= account_meta.is_writable;
            } else {
                let index_in_caller = instruction_context
                    .find_index_of_instruction_account(
                        self.transaction_context,
                        &account_meta.pubkey,
                    )
                    .ok_or_else(|| {
                        ic_msg!(
                            self,
                            "Instruction references an unknown account {:?}",
                            account_meta.pubkey,
                        );
                        InstructionError::MissingAccount
                    })?;
                duplicate_indicies.push(deduplicated_instruction_accounts.len());
                deduplicated_instruction_accounts.push(InstructionAccount {
                    index_in_transaction,
                    index_in_caller,
                    index_in_callee: instruction_account_index as IndexOfAccount,
                    is_signer: account_meta.is_signer,
                    is_writable: account_meta.is_writable,
                });
            }
        }
        for instruction_account in deduplicated_instruction_accounts.iter() {
            let borrowed_account = instruction_context.try_borrow_instruction_account(
                self.transaction_context,
                instruction_account.index_in_caller,
            )?;

            // Readonly in caller cannot become writable in callee
            if instruction_account.is_writable && !borrowed_account.is_writable() {
                ic_msg!(
                    self,
                    "{:?}'s writable privilege escalated",
                    borrowed_account.get_key(),
                );
                return Err(InstructionError::PrivilegeEscalation);
            }

            // To be signed in the callee,
            // it must be either signed in the caller or by the program
            if instruction_account.is_signer
                && !(borrowed_account.is_signer() || signers.contains(borrowed_account.get_key()))
            {
                ic_msg!(
                    self,
                    "{:?}'s signer privilege escalated",
                    borrowed_account.get_key()
                );
                return Err(InstructionError::PrivilegeEscalation);
            }
        }
        let instruction_accounts = duplicate_indicies
            .into_iter()
            .map(|duplicate_index| {
                deduplicated_instruction_accounts
                    .get(duplicate_index)
                    .cloned()
                    .ok_or(InstructionError::NotEnoughAccountKeys)
            })
            .collect::<Result<Vec<InstructionAccount>, InstructionError>>()?;

        // Find and validate executables / program accounts
        let callee_program_id = instruction.program_id;
        let program_account_index = if self
            .get_feature_set()
            .is_active(&lift_cpi_caller_restriction::id())
        {
            self.transaction_context
                .find_index_of_program_account(&callee_program_id)
                .ok_or_else(|| {
                    ic_msg!(self, "Unknown program {:?}", callee_program_id);
                    InstructionError::MissingAccount
                })?
        } else {
            let program_account_index = instruction_context
                .find_index_of_instruction_account(self.transaction_context, &callee_program_id)
                .ok_or_else(|| {
                    ic_msg!(self, "Unknown program {:?}", callee_program_id);
                    InstructionError::MissingAccount
                })?;
            let borrowed_program_account = instruction_context
                .try_borrow_instruction_account(self.transaction_context, program_account_index)?;
            #[allow(deprecated)]
            if !self
                .get_feature_set()
                .is_active(&remove_accounts_executable_flag_checks::id())
                && !borrowed_program_account.is_executable()
            {
                ic_msg!(self, "Account {:?} is not executable", callee_program_id);
                return Err(InstructionError::AccountNotExecutable);
            }
            borrowed_program_account.get_index_in_transaction()
        };

        Ok((instruction_accounts, vec![program_account_index]))
    }

    /// Processes an instruction and returns how many compute units were used
    pub fn process_instruction(
        &mut self,
        instruction_data: &[u8],
        instruction_accounts: &[InstructionAccount],
        program_indices: &[IndexOfAccount],
        compute_units_consumed: &mut u64,
        timings: &mut ExecuteTimings,
    ) -> Result<(), InstructionError> {
        *compute_units_consumed = 0;
        self.transaction_context
            .get_next_instruction_context()?
            .configure(program_indices, instruction_accounts, instruction_data);
        self.push()?;
        self.process_executable_chain(compute_units_consumed, timings)
            // MUST pop if and only if `push` succeeded, independent of `result`.
            // Thus, the `.and()` instead of an `.and_then()`.
            .and(self.pop())
    }

    /// Processes a precompile instruction
    pub fn process_precompile<'ix_data>(
        &mut self,
        precompile: &Precompile,
        instruction_data: &[u8],
        instruction_accounts: &[InstructionAccount],
        program_indices: &[IndexOfAccount],
        message_instruction_datas_iter: impl Iterator<Item = &'ix_data [u8]>,
    ) -> Result<(), InstructionError> {
        self.transaction_context
            .get_next_instruction_context()?
            .configure(program_indices, instruction_accounts, instruction_data);
        self.push()?;

        let feature_set = self.get_feature_set();
        let move_precompile_verification_to_svm =
            feature_set.is_active(&move_precompile_verification_to_svm::id());
        if move_precompile_verification_to_svm {
            let instruction_datas: Vec<_> = message_instruction_datas_iter.collect();
            precompile
                .verify(instruction_data, &instruction_datas, feature_set)
                .map_err(InstructionError::from)
                .and(self.pop())
        } else {
            self.pop()
        }
    }

    /// Calls the instruction's program entrypoint method
    fn process_executable_chain(
        &mut self,
        compute_units_consumed: &mut u64,
        timings: &mut ExecuteTimings,
    ) -> Result<(), InstructionError> {
        let instruction_context = self.transaction_context.get_current_instruction_context()?;
        let process_executable_chain_time = Measure::start("process_executable_chain_time");

        let builtin_id = {
            debug_assert!(instruction_context.get_number_of_program_accounts() <= 1);
            let borrowed_root_account = instruction_context
                .try_borrow_program_account(self.transaction_context, 0)
                .map_err(|_| InstructionError::UnsupportedProgramId)?;
            let owner_id = borrowed_root_account.get_owner();
            if native_loader::check_id(owner_id) {
                *borrowed_root_account.get_key()
            } else {
                *owner_id
            }
        };

        // The Murmur3 hash value (used by RBPF) of the string "entrypoint"
        const ENTRYPOINT_KEY: u32 = 0x71E3CF81;
        let entry = self
            .program_cache_for_tx_batch
            .find(&builtin_id)
            .ok_or(InstructionError::UnsupportedProgramId)?;
        let function = match &entry.program {
            ProgramCacheEntryType::Builtin(program) => program
                .get_function_registry(SBPFVersion::V0)
                .lookup_by_key(ENTRYPOINT_KEY)
                .map(|(_name, function)| function),
            _ => None,
        }
        .ok_or(InstructionError::UnsupportedProgramId)?;
        entry.ix_usage_counter.fetch_add(1, Ordering::Relaxed);

        let program_id = *instruction_context.get_last_program_key(self.transaction_context)?;
        self.transaction_context
            .set_return_data(program_id, Vec::new())?;
        let logger = self.get_log_collector();
        stable_log::program_invoke(&logger, &program_id, self.get_stack_height());
        let pre_remaining_units = self.get_remaining();
        // In program-runtime v2 we will create this VM instance only once per transaction.
        // `program_runtime_environment_v2.get_config()` will be used instead of `mock_config`.
        // For now, only built-ins are invoked from here, so the VM and its Config are irrelevant.
        let mock_config = Config::default();
        let empty_memory_mapping =
            MemoryMapping::new(Vec::new(), &mock_config, SBPFVersion::V0).unwrap();
        let mut vm = EbpfVm::new(
            self.program_cache_for_tx_batch
                .environments
                .program_runtime_v2
                .clone(),
            SBPFVersion::V0,
            // Removes lifetime tracking
            unsafe { std::mem::transmute::<&mut InvokeContext, &mut InvokeContext>(self) },
            empty_memory_mapping,
            0,
        );
        vm.invoke_function(function);
        let result = match vm.program_result {
            ProgramResult::Ok(_) => {
                stable_log::program_success(&logger, &program_id);
                Ok(())
            }
            ProgramResult::Err(ref err) => {
                if let EbpfError::SyscallError(syscall_error) = err {
                    if let Some(instruction_err) = syscall_error.downcast_ref::<InstructionError>()
                    {
                        stable_log::program_failure(&logger, &program_id, instruction_err);
                        Err(instruction_err.clone())
                    } else {
                        stable_log::program_failure(&logger, &program_id, syscall_error);
                        Err(InstructionError::ProgramFailedToComplete)
                    }
                } else {
                    stable_log::program_failure(&logger, &program_id, err);
                    Err(InstructionError::ProgramFailedToComplete)
                }
            }
        };
        let post_remaining_units = self.get_remaining();
        *compute_units_consumed = pre_remaining_units.saturating_sub(post_remaining_units);

        if builtin_id == program_id && result.is_ok() && *compute_units_consumed == 0 {
            return Err(InstructionError::BuiltinProgramsMustConsumeComputeUnits);
        }

        timings
            .execute_accessories
            .process_instructions
            .process_executable_chain_us += process_executable_chain_time.end_as_us();
        result
    }

    /// Get this invocation's LogCollector
    pub fn get_log_collector(&self) -> Option<Rc<RefCell<LogCollector>>> {
        self.log_collector.clone()
    }

    /// Consume compute units
    pub fn consume_checked(&self, amount: u64) -> Result<(), Box<dyn std::error::Error>> {
        let mut compute_meter = self.compute_meter.borrow_mut();
        let exceeded = *compute_meter < amount;
        *compute_meter = compute_meter.saturating_sub(amount);
        if exceeded {
            return Err(Box::new(InstructionError::ComputationalBudgetExceeded));
        }
        Ok(())
    }

    /// Set compute units
    ///
    /// Only use for tests and benchmarks
    pub fn mock_set_remaining(&self, remaining: u64) {
        *self.compute_meter.borrow_mut() = remaining;
    }

    /// Get this invocation's compute budget
    pub fn get_compute_budget(&self) -> &ComputeBudget {
        &self.compute_budget
    }

    /// Get the current feature set.
    pub fn get_feature_set(&self) -> &FeatureSet {
        &self.environment_config.feature_set
    }

    /// Set feature set.
    ///
    /// Only use for tests and benchmarks.
    pub fn mock_set_feature_set(&mut self, feature_set: Arc<FeatureSet>) {
        self.environment_config.feature_set = feature_set;
    }

    /// Get cached sysvars
    pub fn get_sysvar_cache(&self) -> &SysvarCache {
        self.environment_config.sysvar_cache
    }

    /// Get cached epoch total stake.
    pub fn get_epoch_total_stake(&self) -> u64 {
        self.environment_config.epoch_total_stake
    }

    /// Get cached stake for the epoch vote account.
    pub fn get_epoch_vote_account_stake(&self, pubkey: &'a Pubkey) -> u64 {
        (self
            .environment_config
            .get_epoch_vote_account_stake_callback)(pubkey)
    }

    // Should alignment be enforced during user pointer translation
    pub fn get_check_aligned(&self) -> bool {
        self.transaction_context
            .get_current_instruction_context()
            .and_then(|instruction_context| {
                let program_account =
                    instruction_context.try_borrow_last_program_account(self.transaction_context);
                debug_assert!(program_account.is_ok());
                program_account
            })
            .map(|program_account| *program_account.get_owner() != bpf_loader_deprecated::id())
            .unwrap_or(true)
    }

    // Set this instruction syscall context
    pub fn set_syscall_context(
        &mut self,
        syscall_context: SyscallContext,
    ) -> Result<(), InstructionError> {
        *self
            .syscall_context
            .last_mut()
            .ok_or(InstructionError::CallDepth)? = Some(syscall_context);
        Ok(())
    }

    // Get this instruction's SyscallContext
    pub fn get_syscall_context(&self) -> Result<&SyscallContext, InstructionError> {
        self.syscall_context
            .last()
            .and_then(std::option::Option::as_ref)
            .ok_or(InstructionError::CallDepth)
    }

    // Get this instruction's SyscallContext
    pub fn get_syscall_context_mut(&mut self) -> Result<&mut SyscallContext, InstructionError> {
        self.syscall_context
            .last_mut()
            .and_then(|syscall_context| syscall_context.as_mut())
            .ok_or(InstructionError::CallDepth)
    }

    /// Return a references to traces
    pub fn get_traces(&self) -> &Vec<Vec<[u64; 12]>> {
        &self.traces
    }
}
