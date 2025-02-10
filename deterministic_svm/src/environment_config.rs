use std::{cmp::Ordering, fmt, sync::Arc};

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    program_ids::sysvar,
    sysvar::{
        clock, epoch_rewards, epoch_schedule, fees, last_restart_slot, rent, slot_hashes,
        stake_history,
    },
    *,
};

pub const MAX_ENTRIES: usize = 512;
// inlined to avoid solana_clock dep
const DEFAULT_SLOTS_PER_EPOCH: u64 = 432_000;
/// The default number of slots before an epoch starts to calculate the leader schedule.
pub const DEFAULT_LEADER_SCHEDULE_SLOT_OFFSET: u64 = DEFAULT_SLOTS_PER_EPOCH;

/// The maximum number of slots before an epoch starts to calculate the leader schedule.
///
/// Default is an entire epoch, i.e. leader schedule for epoch X is calculated at
/// the beginning of epoch X - 1.
pub const MAX_LEADER_SCHEDULE_EPOCH_OFFSET: u64 = 3;

/// The minimum number of slots per epoch during the warmup period.
///
/// Based on `MAX_LOCKOUT_HISTORY` from `vote_program`.
pub const MINIMUM_SLOTS_PER_EPOCH: u64 = 32;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct FullInflationFeaturePair {
    pub vote_id: Pubkey, // Feature that grants the candidate the ability to enable full inflation
    pub enable_id: Pubkey, // Feature to enable full inflation by the candidate
}

#[derive(Clone, Default)]
pub struct Hasher {
    hasher: Sha256,
}

impl Hasher {
    pub fn hash(&mut self, val: &[u8]) {
        self.hasher.update(val);
    }
    pub fn hashv(&mut self, vals: &[&[u8]]) {
        for val in vals {
            self.hash(val);
        }
    }
    pub fn result(self) -> Hash {
        let bytes: [u8; 32] = self.hasher.finalize().into();
        bytes.into()
    }
}

pub type Hash = [u8; 32];

impl Sanitize for Hash {}

pub type SlotHash = (u64, Hash);

#[repr(C)]
#[derive(PartialEq, Eq, Debug, Default, Deserialize, Serialize)]
pub struct SlotHashes(Vec<SlotHash>);

pub struct EnvironmentConfig<'a> {
    pub blockhash: Hash,
    pub blockhash_lamports_per_signature: u64,
    pub epoch_total_stake: u64,
    pub get_epoch_vote_account_stake_callback: &'a dyn Fn(&'a Pubkey) -> u64,
    pub feature_set: Arc<FeatureSet>,
    pub sysvar_cache: &'a SysvarCache,
}
impl<'a> EnvironmentConfig<'a> {
    pub fn new(
        blockhash: Hash,
        blockhash_lamports_per_signature: u64,
        epoch_total_stake: u64,
        get_epoch_vote_account_stake_callback: &'a dyn Fn(&'a Pubkey) -> u64,
        feature_set: Arc<FeatureSet>,
        sysvar_cache: &'a SysvarCache,
    ) -> Self {
        Self {
            blockhash,
            blockhash_lamports_per_signature,
            epoch_total_stake,
            get_epoch_vote_account_stake_callback,
            feature_set,
            sysvar_cache,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct EpochSchedule {
    /// The maximum number of slots in each epoch.
    pub slots_per_epoch: u64,

    /// A number of slots before beginning of an epoch to calculate
    /// a leader schedule for that epoch.
    pub leader_schedule_slot_offset: u64,

    /// Whether epochs start short and grow.
    pub warmup: bool,

    /// The first epoch after the warmup period.
    ///
    /// Basically: `log2(slots_per_epoch) - log2(MINIMUM_SLOTS_PER_EPOCH)`.
    pub first_normal_epoch: u64,

    /// The first slot after the warmup period.
    ///
    /// Basically: `MINIMUM_SLOTS_PER_EPOCH * (2.pow(first_normal_epoch) - 1)`.
    pub first_normal_slot: u64,
}

impl Default for EpochSchedule {
    fn default() -> Self {
        Self::custom(
            DEFAULT_SLOTS_PER_EPOCH,
            DEFAULT_LEADER_SCHEDULE_SLOT_OFFSET,
            true,
        )
    }
}

impl EpochSchedule {
    pub fn new(slots_per_epoch: u64) -> Self {
        Self::custom(slots_per_epoch, slots_per_epoch, true)
    }
    pub fn without_warmup() -> Self {
        Self::custom(
            DEFAULT_SLOTS_PER_EPOCH,
            DEFAULT_LEADER_SCHEDULE_SLOT_OFFSET,
            false,
        )
    }
    pub fn custom(slots_per_epoch: u64, leader_schedule_slot_offset: u64, warmup: bool) -> Self {
        assert!(slots_per_epoch >= MINIMUM_SLOTS_PER_EPOCH);
        let (first_normal_epoch, first_normal_slot) = if warmup {
            let next_power_of_two = slots_per_epoch.next_power_of_two();
            let log2_slots_per_epoch = next_power_of_two
                .trailing_zeros()
                .saturating_sub(MINIMUM_SLOTS_PER_EPOCH.trailing_zeros());

            (
                u64::from(log2_slots_per_epoch),
                next_power_of_two.saturating_sub(MINIMUM_SLOTS_PER_EPOCH),
            )
        } else {
            (0, 0)
        };
        EpochSchedule {
            slots_per_epoch,
            leader_schedule_slot_offset,
            warmup,
            first_normal_epoch,
            first_normal_slot,
        }
    }

    /// get the length of the given epoch (in slots)
    pub fn get_slots_in_epoch(&self, epoch: u64) -> u64 {
        if epoch < self.first_normal_epoch {
            2u64.saturating_pow(
                (epoch as u32).saturating_add(MINIMUM_SLOTS_PER_EPOCH.trailing_zeros()),
            )
        } else {
            self.slots_per_epoch
        }
    }

    /// get the epoch for which the given slot should save off
    ///  information about stakers
    pub fn get_leader_schedule_epoch(&self, slot: u64) -> u64 {
        if slot < self.first_normal_slot {
            // until we get to normal slots, behave as if leader_schedule_slot_offset == slots_per_epoch
            self.get_epoch_and_slot_index(slot).0.saturating_add(1)
        } else {
            let new_slots_since_first_normal_slot = slot.saturating_sub(self.first_normal_slot);
            let new_first_normal_leader_schedule_slot =
                new_slots_since_first_normal_slot.saturating_add(self.leader_schedule_slot_offset);
            let new_epochs_since_first_normal_leader_schedule =
                new_first_normal_leader_schedule_slot
                    .checked_div(self.slots_per_epoch)
                    .unwrap_or(0);
            self.first_normal_epoch
                .saturating_add(new_epochs_since_first_normal_leader_schedule)
        }
    }

    /// get epoch for the given slot
    pub fn get_epoch(&self, slot: u64) -> u64 {
        self.get_epoch_and_slot_index(slot).0
    }

    /// get epoch and offset into the epoch for the given slot
    pub fn get_epoch_and_slot_index(&self, slot: u64) -> (u64, u64) {
        if slot < self.first_normal_slot {
            let epoch = slot
                .saturating_add(MINIMUM_SLOTS_PER_EPOCH)
                .saturating_add(1)
                .next_power_of_two()
                .trailing_zeros()
                .saturating_sub(MINIMUM_SLOTS_PER_EPOCH.trailing_zeros())
                .saturating_sub(1);

            let epoch_len =
                2u64.saturating_pow(epoch.saturating_add(MINIMUM_SLOTS_PER_EPOCH.trailing_zeros()));

            (
                u64::from(epoch),
                slot.saturating_sub(epoch_len.saturating_sub(MINIMUM_SLOTS_PER_EPOCH)),
            )
        } else {
            let normal_slot_index = slot.saturating_sub(self.first_normal_slot);
            let normal_epoch_index = normal_slot_index
                .checked_div(self.slots_per_epoch)
                .unwrap_or(0);
            let epoch = self.first_normal_epoch.saturating_add(normal_epoch_index);
            let slot_index = normal_slot_index
                .checked_rem(self.slots_per_epoch)
                .unwrap_or(0);
            (epoch, slot_index)
        }
    }

    pub fn get_first_slot_in_epoch(&self, epoch: u64) -> u64 {
        if epoch <= self.first_normal_epoch {
            2u64.saturating_pow(epoch as u32)
                .saturating_sub(1)
                .saturating_mul(MINIMUM_SLOTS_PER_EPOCH)
        } else {
            epoch
                .saturating_sub(self.first_normal_epoch)
                .saturating_mul(self.slots_per_epoch)
                .saturating_add(self.first_normal_slot)
        }
    }

    pub fn get_last_slot_in_epoch(&self, epoch: u64) -> u64 {
        self.get_first_slot_in_epoch(epoch)
            .saturating_add(self.get_slots_in_epoch(epoch))
            .saturating_sub(1)
    }
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq, Default, Clone, Deserialize, Serialize)]
pub struct StakeHistory(Vec<(Epoch, StakeHistoryEntry)>);

impl StakeHistory {
    pub fn get(&self, epoch: Epoch) -> Option<&StakeHistoryEntry> {
        self.0
            .binary_search_by(|probe| epoch.cmp(&probe.0))
            .ok()
            .map(|index| &self.0[index].1)
    }

    pub fn add(&mut self, epoch: Epoch, entry: StakeHistoryEntry) {
        match self.0.binary_search_by(|probe| epoch.cmp(&probe.0)) {
            Ok(index) => (self.0)[index] = (epoch, entry),
            Err(index) => (self.0).insert(index, (epoch, entry)),
        }
        (self.0).truncate(MAX_ENTRIES);
    }
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq, Default, Clone, Deserialize, Serialize)]
pub struct StakeHistoryEntry {
    pub effective: u64,    // effective stake at this epoch
    pub activating: u64,   // sum of portion of stakes not fully warmed up
    pub deactivating: u64, // requested to be cooled down, not fully deactivated yet
}

impl StakeHistoryEntry {
    pub fn with_effective(effective: u64) -> Self {
        Self {
            effective,
            ..Self::default()
        }
    }

    pub fn with_effective_and_activating(effective: u64, activating: u64) -> Self {
        Self {
            effective,
            activating,
            ..Self::default()
        }
    }

    pub fn with_deactivating(deactivating: u64) -> Self {
        Self {
            effective: deactivating,
            deactivating,
            ..Self::default()
        }
    }
}

impl std::ops::Add for StakeHistoryEntry {
    type Output = StakeHistoryEntry;
    fn add(self, rhs: StakeHistoryEntry) -> Self::Output {
        Self {
            effective: self.effective.saturating_add(rhs.effective),
            activating: self.activating.saturating_add(rhs.activating),
            deactivating: self.deactivating.saturating_add(rhs.deactivating),
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct Fees {
    pub fee_calculator: FeeCalculator,
}

impl Fees {
    pub fn new(fee_calculator: &FeeCalculator) -> Self {
        #[allow(deprecated)]
        Self {
            fee_calculator: *fee_calculator,
        }
    }
}

#[repr(C)]
#[derive(Default, PartialEq, Eq, Clone, Copy, Debug, Deserialize, Serialize)]
pub struct FeeCalculator {
    /// The current cost of a signature.
    ///
    /// This amount may increase/decrease over time based on cluster processing
    /// load.
    pub lamports_per_signature: u64,
}

impl FeeCalculator {
    pub fn new(lamports_per_signature: u64) -> Self {
        Self {
            lamports_per_signature,
        }
    }
}

#[repr(C)]
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct RecentBlockhashes(Vec<Entry>);

impl Default for RecentBlockhashes {
    fn default() -> Self {
        Self(Vec::with_capacity(MAX_ENTRIES))
    }
}

impl<'a> FromIterator<IterItem<'a>> for RecentBlockhashes {
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = IterItem<'a>>,
    {
        let mut new = Self::default();
        for i in iter {
            new.0.push(Entry::new(i.1, i.2))
        }
        new
    }
}

#[repr(C)]
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct Entry {
    pub blockhash: Hash,
    pub fee_calculator: FeeCalculator,
}
impl Entry {
    pub fn new(blockhash: &Hash, lamports_per_signature: u64) -> Self {
        Self {
            blockhash: *blockhash,
            fee_calculator: FeeCalculator::new(lamports_per_signature),
        }
    }
}

#[derive(Clone, Debug)]
pub struct IterItem<'a>(pub u64, pub &'a Hash, pub u64);

impl Eq for IterItem<'_> {}

impl PartialEq for IterItem<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Ord for IterItem<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}

impl PartialOrd for IterItem<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

pub trait SysvarId {
    /// The `Pubkey` of the sysvar.
    fn id() -> Pubkey;

    /// Returns `true` if the given pubkey is the program ID.
    fn check_id(pubkey: &Pubkey) -> bool;
}

pub type ProgramResult = std::result::Result<(), ProgramError>;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub enum ProgramError {
    /// Allows on-chain programs to implement program-specific error types and see them returned
    /// by the Solana runtime. A program-specific error may be any type that is represented as
    /// or serialized to a u32 integer.
    Custom(u32),
    InvalidArgument,
    InvalidInstructionData,
    InvalidAccountData,
    AccountDataTooSmall,
    InsufficientFunds,
    IncorrectProgramId,
    MissingRequiredSignature,
    AccountAlreadyInitialized,
    UninitializedAccount,
    NotEnoughAccountKeys,
    AccountBorrowFailed,
    MaxSeedLengthExceeded,
    InvalidSeeds,
    BorshIoError(String),
    AccountNotRentExempt,
    UnsupportedSysvar,
    IllegalOwner,
    MaxAccountsDataAllocationsExceeded,
    InvalidRealloc,
    MaxInstructionTraceLengthExceeded,
    BuiltinProgramsMustConsumeComputeUnits,
    InvalidAccountOwner,
    ArithmeticOverflow,
    Immutable,
    IncorrectAuthority,
}

impl std::error::Error for ProgramError {}

impl fmt::Display for ProgramError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ProgramError::Custom(num) => write!(f,"Custom program error: {num:#x}"),
            ProgramError::InvalidArgument
             => f.write_str("The arguments provided to a program instruction were invalid"),
            ProgramError::InvalidInstructionData
             => f.write_str("An instruction's data contents was invalid"),
            ProgramError::InvalidAccountData
             => f.write_str("An account's data contents was invalid"),
            ProgramError::AccountDataTooSmall
             => f.write_str("An account's data was too small"),
            ProgramError::InsufficientFunds
             => f.write_str("An account's balance was too small to complete the instruction"),
            ProgramError::IncorrectProgramId
             => f.write_str("The account did not have the expected program id"),
            ProgramError::MissingRequiredSignature
             => f.write_str("A signature was required but not found"),
            ProgramError::AccountAlreadyInitialized
             => f.write_str("An initialize instruction was sent to an account that has already been initialized"),
            ProgramError::UninitializedAccount
             => f.write_str("An attempt to operate on an account that hasn't been initialized"),
            ProgramError::NotEnoughAccountKeys
             => f.write_str("The instruction expected additional account keys"),
            ProgramError::AccountBorrowFailed
             => f.write_str("Failed to borrow a reference to account data, already borrowed"),
            ProgramError::MaxSeedLengthExceeded
             => f.write_str("Length of the seed is too long for address generation"),
            ProgramError::InvalidSeeds
             => f.write_str("Provided seeds do not result in a valid address"),
            ProgramError::BorshIoError(s) =>  write!(f, "IO Error: {s}"),
            ProgramError::AccountNotRentExempt
             => f.write_str("An account does not have enough lamports to be rent-exempt"),
            ProgramError::UnsupportedSysvar
             => f.write_str("Unsupported sysvar"),
            ProgramError::IllegalOwner
             => f.write_str("Provided owner is not allowed"),
            ProgramError::MaxAccountsDataAllocationsExceeded
             => f.write_str("Accounts data allocations exceeded the maximum allowed per transaction"),
            ProgramError::InvalidRealloc
             => f.write_str("Account data reallocation was invalid"),
            ProgramError::MaxInstructionTraceLengthExceeded
             => f.write_str("Instruction trace length exceeded the maximum allowed per transaction"),
            ProgramError::BuiltinProgramsMustConsumeComputeUnits
             => f.write_str("Builtin programs must consume compute units"),
            ProgramError::InvalidAccountOwner
             => f.write_str("Invalid account owner"),
            ProgramError::ArithmeticOverflow
             => f.write_str("Program arithmetic overflowed"),
            ProgramError::Immutable
             => f.write_str("Account is immutable"),
            ProgramError::IncorrectAuthority
             => f.write_str("Incorrect authority provided"),
        }
    }
}

pub trait PrintProgramError {
    fn print<E>(&self)
    where
        E: 'static + std::error::Error + DecodeError<E> + PrintProgramError + FromPrimitive;
}

impl PrintProgramError for ProgramError {
    fn print<E>(&self)
    where
        E: 'static + std::error::Error + DecodeError<E> + PrintProgramError + FromPrimitive,
    {
        match self {
            Self::Custom(error) => {
                if let Some(custom_error) = E::decode_custom_error_to_enum(*error) {
                    custom_error.print::<E>();
                } else {
                    msg!("Error: Unknown");
                }
            }
            Self::InvalidArgument => msg!("Error: InvalidArgument"),
            Self::InvalidInstructionData => msg!("Error: InvalidInstructionData"),
            Self::InvalidAccountData => msg!("Error: InvalidAccountData"),
            Self::AccountDataTooSmall => msg!("Error: AccountDataTooSmall"),
            Self::InsufficientFunds => msg!("Error: InsufficientFunds"),
            Self::IncorrectProgramId => msg!("Error: IncorrectProgramId"),
            Self::MissingRequiredSignature => msg!("Error: MissingRequiredSignature"),
            Self::AccountAlreadyInitialized => msg!("Error: AccountAlreadyInitialized"),
            Self::UninitializedAccount => msg!("Error: UninitializedAccount"),
            Self::NotEnoughAccountKeys => msg!("Error: NotEnoughAccountKeys"),
            Self::AccountBorrowFailed => msg!("Error: AccountBorrowFailed"),
            Self::MaxSeedLengthExceeded => msg!("Error: MaxSeedLengthExceeded"),
            Self::InvalidSeeds => msg!("Error: InvalidSeeds"),
            Self::BorshIoError(_) => msg!("Error: BorshIoError"),
            Self::AccountNotRentExempt => msg!("Error: AccountNotRentExempt"),
            Self::UnsupportedSysvar => msg!("Error: UnsupportedSysvar"),
            Self::IllegalOwner => msg!("Error: IllegalOwner"),
            Self::MaxAccountsDataAllocationsExceeded => {
                msg!("Error: MaxAccountsDataAllocationsExceeded")
            }
            Self::InvalidRealloc => msg!("Error: InvalidRealloc"),
            Self::MaxInstructionTraceLengthExceeded => {
                msg!("Error: MaxInstructionTraceLengthExceeded")
            }
            Self::BuiltinProgramsMustConsumeComputeUnits => {
                msg!("Error: BuiltinProgramsMustConsumeComputeUnits")
            }
            Self::InvalidAccountOwner => msg!("Error: InvalidAccountOwner"),
            Self::ArithmeticOverflow => msg!("Error: ArithmeticOverflow"),
            Self::Immutable => msg!("Error: Immutable"),
            Self::IncorrectAuthority => msg!("Error: IncorrectAuthority"),
        }
    }
}

impl From<ProgramError> for u64 {
    fn from(error: ProgramError) -> Self {
        match error {
            ProgramError::InvalidArgument => INVALID_ARGUMENT,
            ProgramError::InvalidInstructionData => INVALID_INSTRUCTION_DATA,
            ProgramError::InvalidAccountData => INVALID_ACCOUNT_DATA,
            ProgramError::AccountDataTooSmall => ACCOUNT_DATA_TOO_SMALL,
            ProgramError::InsufficientFunds => INSUFFICIENT_FUNDS,
            ProgramError::IncorrectProgramId => INCORRECT_PROGRAM_ID,
            ProgramError::MissingRequiredSignature => MISSING_REQUIRED_SIGNATURES,
            ProgramError::AccountAlreadyInitialized => ACCOUNT_ALREADY_INITIALIZED,
            ProgramError::UninitializedAccount => UNINITIALIZED_ACCOUNT,
            ProgramError::NotEnoughAccountKeys => NOT_ENOUGH_ACCOUNT_KEYS,
            ProgramError::AccountBorrowFailed => ACCOUNT_BORROW_FAILED,
            ProgramError::MaxSeedLengthExceeded => MAX_SEED_LENGTH_EXCEEDED,
            ProgramError::InvalidSeeds => INVALID_SEEDS,
            ProgramError::BorshIoError(_) => BORSH_IO_ERROR,
            ProgramError::AccountNotRentExempt => ACCOUNT_NOT_RENT_EXEMPT,
            ProgramError::UnsupportedSysvar => UNSUPPORTED_SYSVAR,
            ProgramError::IllegalOwner => ILLEGAL_OWNER,
            ProgramError::MaxAccountsDataAllocationsExceeded => {
                MAX_ACCOUNTS_DATA_ALLOCATIONS_EXCEEDED
            }
            ProgramError::InvalidRealloc => INVALID_ACCOUNT_DATA_REALLOC,
            ProgramError::MaxInstructionTraceLengthExceeded => {
                MAX_INSTRUCTION_TRACE_LENGTH_EXCEEDED
            }
            ProgramError::BuiltinProgramsMustConsumeComputeUnits => {
                BUILTIN_PROGRAMS_MUST_CONSUME_COMPUTE_UNITS
            }
            ProgramError::InvalidAccountOwner => INVALID_ACCOUNT_OWNER,
            ProgramError::ArithmeticOverflow => ARITHMETIC_OVERFLOW,
            ProgramError::Immutable => IMMUTABLE,
            ProgramError::IncorrectAuthority => INCORRECT_AUTHORITY,
            ProgramError::Custom(error) => {
                if error == 0 {
                    CUSTOM_ZERO
                } else {
                    error as u64
                }
            }
        }
    }
}

impl From<u64> for ProgramError {
    fn from(error: u64) -> Self {
        match error {
            CUSTOM_ZERO => Self::Custom(0),
            INVALID_ARGUMENT => Self::InvalidArgument,
            INVALID_INSTRUCTION_DATA => Self::InvalidInstructionData,
            INVALID_ACCOUNT_DATA => Self::InvalidAccountData,
            ACCOUNT_DATA_TOO_SMALL => Self::AccountDataTooSmall,
            INSUFFICIENT_FUNDS => Self::InsufficientFunds,
            INCORRECT_PROGRAM_ID => Self::IncorrectProgramId,
            MISSING_REQUIRED_SIGNATURES => Self::MissingRequiredSignature,
            ACCOUNT_ALREADY_INITIALIZED => Self::AccountAlreadyInitialized,
            UNINITIALIZED_ACCOUNT => Self::UninitializedAccount,
            NOT_ENOUGH_ACCOUNT_KEYS => Self::NotEnoughAccountKeys,
            ACCOUNT_BORROW_FAILED => Self::AccountBorrowFailed,
            MAX_SEED_LENGTH_EXCEEDED => Self::MaxSeedLengthExceeded,
            INVALID_SEEDS => Self::InvalidSeeds,
            BORSH_IO_ERROR => Self::BorshIoError("Unknown".to_string()),
            ACCOUNT_NOT_RENT_EXEMPT => Self::AccountNotRentExempt,
            UNSUPPORTED_SYSVAR => Self::UnsupportedSysvar,
            ILLEGAL_OWNER => Self::IllegalOwner,
            MAX_ACCOUNTS_DATA_ALLOCATIONS_EXCEEDED => Self::MaxAccountsDataAllocationsExceeded,
            INVALID_ACCOUNT_DATA_REALLOC => Self::InvalidRealloc,
            MAX_INSTRUCTION_TRACE_LENGTH_EXCEEDED => Self::MaxInstructionTraceLengthExceeded,
            BUILTIN_PROGRAMS_MUST_CONSUME_COMPUTE_UNITS => {
                Self::BuiltinProgramsMustConsumeComputeUnits
            }
            INVALID_ACCOUNT_OWNER => Self::InvalidAccountOwner,
            ARITHMETIC_OVERFLOW => Self::ArithmeticOverflow,
            IMMUTABLE => Self::Immutable,
            INCORRECT_AUTHORITY => Self::IncorrectAuthority,
            _ => Self::Custom(error as u32),
        }
    }
}

impl TryFrom<InstructionError> for ProgramError {
    type Error = InstructionError;

    fn try_from(error: InstructionError) -> Result<Self, Self::Error> {
        match error {
            Self::Error::Custom(err) => Ok(Self::Custom(err)),
            Self::Error::InvalidArgument => Ok(Self::InvalidArgument),
            Self::Error::InvalidInstructionData => Ok(Self::InvalidInstructionData),
            Self::Error::InvalidAccountData => Ok(Self::InvalidAccountData),
            Self::Error::AccountDataTooSmall => Ok(Self::AccountDataTooSmall),
            Self::Error::InsufficientFunds => Ok(Self::InsufficientFunds),
            Self::Error::IncorrectProgramId => Ok(Self::IncorrectProgramId),
            Self::Error::MissingRequiredSignature => Ok(Self::MissingRequiredSignature),
            Self::Error::AccountAlreadyInitialized => Ok(Self::AccountAlreadyInitialized),
            Self::Error::UninitializedAccount => Ok(Self::UninitializedAccount),
            Self::Error::NotEnoughAccountKeys => Ok(Self::NotEnoughAccountKeys),
            Self::Error::AccountBorrowFailed => Ok(Self::AccountBorrowFailed),
            Self::Error::MaxSeedLengthExceeded => Ok(Self::MaxSeedLengthExceeded),
            Self::Error::InvalidSeeds => Ok(Self::InvalidSeeds),
            Self::Error::BorshIoError(err) => Ok(Self::BorshIoError(err)),
            Self::Error::AccountNotRentExempt => Ok(Self::AccountNotRentExempt),
            Self::Error::UnsupportedSysvar => Ok(Self::UnsupportedSysvar),
            Self::Error::IllegalOwner => Ok(Self::IllegalOwner),
            Self::Error::MaxAccountsDataAllocationsExceeded => {
                Ok(Self::MaxAccountsDataAllocationsExceeded)
            }
            Self::Error::InvalidRealloc => Ok(Self::InvalidRealloc),
            Self::Error::MaxInstructionTraceLengthExceeded => {
                Ok(Self::MaxInstructionTraceLengthExceeded)
            }
            Self::Error::BuiltinProgramsMustConsumeComputeUnits => {
                Ok(Self::BuiltinProgramsMustConsumeComputeUnits)
            }
            Self::Error::InvalidAccountOwner => Ok(Self::InvalidAccountOwner),
            Self::Error::ArithmeticOverflow => Ok(Self::ArithmeticOverflow),
            Self::Error::Immutable => Ok(Self::Immutable),
            Self::Error::IncorrectAuthority => Ok(Self::IncorrectAuthority),
            _ => Err(error),
        }
    }
}

impl From<PubkeyError> for ProgramError {
    fn from(error: PubkeyError) -> Self {
        match error {
            PubkeyError::MaxSeedLengthExceeded => Self::MaxSeedLengthExceeded,
            PubkeyError::InvalidSeeds => Self::InvalidSeeds,
            PubkeyError::IllegalOwner => Self::IllegalOwner,
        }
    }
}

/// A type that holds sysvar data.
pub trait Sysvar:
    SysvarId + Default + Sized + serde::Serialize + serde::de::DeserializeOwned
{
    /// The size in bytes of the sysvar as serialized account data.
    fn size_of() -> usize {
        bincode::serialized_size(&Self::default()).unwrap() as usize
    }

    /// Deserializes the sysvar from its `AccountInfo`.
    ///
    /// # Errors
    ///
    /// If `account_info` does not have the same ID as the sysvar this function
    /// returns [`ProgramError::InvalidArgument`].
    fn from_account_info(account_info: &AccountInfo) -> Result<Self, ProgramError> {
        if !Self::check_id(account_info.unsigned_key()) {
            return Err(ProgramError::InvalidArgument);
        }
        bincode::deserialize(&account_info.data.borrow()).map_err(|_| ProgramError::InvalidArgument)
    }

    /// Serializes the sysvar to `AccountInfo`.
    ///
    /// # Errors
    ///
    /// Returns `None` if serialization failed.
    fn to_account_info(&self, account_info: &mut AccountInfo) -> Option<()> {
        bincode::serialize_into(&mut account_info.data.borrow_mut()[..], self).ok()
    }

    /// Load the sysvar directly from the runtime.
    ///
    /// This is the preferred way to load a sysvar. Calling this method does not
    /// incur any deserialization overhead, and does not require the sysvar
    /// account to be passed to the program.
    ///
    /// Not all sysvars support this method. If not, it returns
    /// [`ProgramError::UnsupportedSysvar`].
    fn get() -> Result<Self, ProgramError> {
        Err(ProgramError::UnsupportedSysvar)
    }
}

#[derive(Default, Clone, Debug)]
pub struct SysvarCache {
    // full account data as provided by bank, including any trailing zero bytes
    clock: Option<Vec<u8>>,
    epoch_schedule: Option<Vec<u8>>,
    epoch_rewards: Option<Vec<u8>>,
    rent: Option<Vec<u8>>,
    slot_hashes: Option<Vec<u8>>,
    stake_history: Option<Vec<u8>>,
    last_restart_slot: Option<Vec<u8>>,

    // object representations of large sysvars for convenience
    // these are used by the stake and vote builtin programs
    // these should be removed once those programs are ported to bpf
    slot_hashes_obj: Option<Arc<SlotHashes>>,
    stake_history_obj: Option<Arc<StakeHistory>>,

    // deprecated sysvars, these should be removed once practical
    #[allow(deprecated)]
    fees: Option<Fees>,
    #[allow(deprecated)]
    recent_blockhashes: Option<RecentBlockhashes>,
}

const FEES_ID: Pubkey = Pubkey::from_str_const("SysvarFees111111111111111111111111111111111");
const RECENT_BLOCKHASHES_ID: Pubkey =
    Pubkey::from_str_const("SysvarRecentB1ockHashes11111111111111111111");

impl SysvarCache {
    /// Overwrite a sysvar. For testing purposes only.
    #[allow(deprecated)]
    pub fn set_sysvar_for_tests<T: Sysvar + SysvarId>(&mut self, sysvar: &T) {
        let data = bincode::serialize(sysvar).expect("Failed to serialize sysvar.");
        let sysvar_id = T::id();
        match sysvar_id {
            sysvar::clock::ID => {
                self.clock = Some(data);
            }
            sysvar::epoch_rewards::ID => {
                self.epoch_rewards = Some(data);
            }
            sysvar::epoch_schedule::ID => {
                self.epoch_schedule = Some(data);
            }
            FEES_ID => {
                let fees: Fees =
                    bincode::deserialize(&data).expect("Failed to deserialize Fees sysvar.");
                self.fees = Some(fees);
            }
            sysvar::last_restart_slot::ID => {
                self.last_restart_slot = Some(data);
            }
            RECENT_BLOCKHASHES_ID => {
                let recent_blockhashes: RecentBlockhashes = bincode::deserialize(&data)
                    .expect("Failed to deserialize RecentBlockhashes sysvar.");
                self.recent_blockhashes = Some(recent_blockhashes);
            }
            sysvar::rent::ID => {
                self.rent = Some(data);
            }
            sysvar::slot_hashes::ID => {
                let slot_hashes: SlotHashes =
                    bincode::deserialize(&data).expect("Failed to deserialize SlotHashes sysvar.");
                self.slot_hashes = Some(data);
                self.slot_hashes_obj = Some(Arc::new(slot_hashes));
            }
            sysvar::stake_history::ID => {
                let stake_history: StakeHistory = bincode::deserialize(&data)
                    .expect("Failed to deserialize StakeHistory sysvar.");
                self.stake_history = Some(data);
                self.stake_history_obj = Some(Arc::new(stake_history));
            }
            _ => panic!("Unrecognized Sysvar ID: {sysvar_id}"),
        }
    }

    // this is exposed for SyscallGetSysvar and should not otherwise be used
    pub fn sysvar_id_to_buffer(&self, sysvar_id: &Pubkey) -> &Option<Vec<u8>> {
        if clock::check_id(sysvar_id) {
            &self.clock
        } else if epoch_schedule::check_id(sysvar_id) {
            &self.epoch_schedule
        } else if epoch_rewards::check_id(sysvar_id) {
            &self.epoch_rewards
        } else if rent::check_id(sysvar_id) {
            &self.rent
        } else if slot_hashes::check_id(sysvar_id) {
            &self.slot_hashes
        } else if stake_history::check_id(sysvar_id) {
            &self.stake_history
        } else if last_restart_slot::check_id(sysvar_id) {
            &self.last_restart_slot
        } else {
            &None
        }
    }

    // most if not all of the obj getter functions can be removed once builtins transition to bpf
    // the Arc<T> wrapper is to preserve the existing public interface
    fn get_sysvar_obj<T: DeserializeOwned>(
        &self,
        sysvar_id: &Pubkey,
    ) -> Result<Arc<T>, InstructionError> {
        if let Some(ref sysvar_buf) = self.sysvar_id_to_buffer(sysvar_id) {
            bincode::deserialize(sysvar_buf)
                .map(Arc::new)
                .map_err(|_| InstructionError::UnsupportedSysvar)
        } else {
            Err(InstructionError::UnsupportedSysvar)
        }
    }

    pub fn get_clock(&self) -> Result<Arc<Clock>, InstructionError> {
        self.get_sysvar_obj(&clock::id())
    }

    pub fn get_epoch_schedule(&self) -> Result<Arc<EpochSchedule>, InstructionError> {
        self.get_sysvar_obj(&epoch_schedule::id())
    }

    pub fn get_epoch_rewards(&self) -> Result<Arc<EpochRewards>, InstructionError> {
        self.get_sysvar_obj(&epoch_rewards::id())
    }

    pub fn get_rent(&self) -> Result<Arc<Rent>, InstructionError> {
        self.get_sysvar_obj(&rent::id())
    }

    pub fn get_last_restart_slot(&self) -> Result<Arc<LastRestartSlot>, InstructionError> {
        self.get_sysvar_obj(&last_restart_slot::id())
    }

    pub fn get_stake_history(&self) -> Result<Arc<StakeHistory>, InstructionError> {
        self.stake_history_obj
            .clone()
            .ok_or(InstructionError::UnsupportedSysvar)
    }

    pub fn get_slot_hashes(&self) -> Result<Arc<SlotHashes>, InstructionError> {
        self.slot_hashes_obj
            .clone()
            .ok_or(InstructionError::UnsupportedSysvar)
    }

    #[deprecated]
    #[allow(deprecated)]
    pub fn get_fees(&self) -> Result<Arc<Fees>, InstructionError> {
        self.fees
            .clone()
            .ok_or(InstructionError::UnsupportedSysvar)
            .map(Arc::new)
    }

    #[deprecated]
    #[allow(deprecated)]
    pub fn get_recent_blockhashes(&self) -> Result<Arc<RecentBlockhashes>, InstructionError> {
        self.recent_blockhashes
            .clone()
            .ok_or(InstructionError::UnsupportedSysvar)
            .map(Arc::new)
    }

    pub fn fill_missing_entries<F: FnMut(&Pubkey, &mut dyn FnMut(&[u8]))>(
        &mut self,
        mut get_account_data: F,
    ) {
        if self.clock.is_none() {
            get_account_data(&clock::id(), &mut |data: &[u8]| {
                if bincode::deserialize::<Clock>(data).is_ok() {
                    self.clock = Some(data.to_vec());
                }
            });
        }

        if self.epoch_schedule.is_none() {
            get_account_data(&epoch_schedule::id(), &mut |data: &[u8]| {
                if bincode::deserialize::<EpochSchedule>(data).is_ok() {
                    self.epoch_schedule = Some(data.to_vec());
                }
            });
        }

        if self.epoch_rewards.is_none() {
            get_account_data(&epoch_rewards::id(), &mut |data: &[u8]| {
                if bincode::deserialize::<EpochRewards>(data).is_ok() {
                    self.epoch_rewards = Some(data.to_vec());
                }
            });
        }

        if self.rent.is_none() {
            get_account_data(&rent::id(), &mut |data: &[u8]| {
                if bincode::deserialize::<Rent>(data).is_ok() {
                    self.rent = Some(data.to_vec());
                }
            });
        }

        if self.slot_hashes.is_none() {
            get_account_data(&slot_hashes::id(), &mut |data: &[u8]| {
                if let Ok(obj) = bincode::deserialize::<SlotHashes>(data) {
                    self.slot_hashes = Some(data.to_vec());
                    self.slot_hashes_obj = Some(Arc::new(obj));
                }
            });
        }

        if self.stake_history.is_none() {
            get_account_data(&stake_history::id(), &mut |data: &[u8]| {
                if let Ok(obj) = bincode::deserialize::<StakeHistory>(data) {
                    self.stake_history = Some(data.to_vec());
                    self.stake_history_obj = Some(Arc::new(obj));
                }
            });
        }

        if self.last_restart_slot.is_none() {
            get_account_data(&last_restart_slot::id(), &mut |data: &[u8]| {
                if bincode::deserialize::<LastRestartSlot>(data).is_ok() {
                    self.last_restart_slot = Some(data.to_vec());
                }
            });
        }

        #[allow(deprecated)]
        if self.fees.is_none() {
            get_account_data(&FEES_ID, &mut |data: &[u8]| {
                if let Ok(fees) = bincode::deserialize(data) {
                    self.fees = Some(fees);
                }
            });
        }

        #[allow(deprecated)]
        if self.recent_blockhashes.is_none() {
            get_account_data(&RECENT_BLOCKHASHES_ID, &mut |data: &[u8]| {
                if let Ok(recent_blockhashes) = bincode::deserialize(data) {
                    self.recent_blockhashes = Some(recent_blockhashes);
                }
            });
        }
    }

    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
pub struct LastRestartSlot {
    /// The last restart `Slot`.
    pub last_restart_slot: u64,
}

pub type UnixTimestamp = i64;

/// A representation of network time.
///
/// All members of `Clock` start from 0 upon network boot.
#[repr(C)]
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct Clock {
    /// The current `Slot`.
    pub slot: Slot,
    /// The timestamp of the first `Slot` in this `Epoch`.
    pub epoch_start_timestamp: UnixTimestamp,
    /// The current `Epoch`.
    pub epoch: Epoch,
    /// The future `Epoch` for which the leader schedule has
    /// most recently been calculated.
    pub leader_schedule_epoch: Epoch,
    /// The approximate real world time of the current slot.
    ///
    /// This value was originally computed from genesis creation time and
    /// network time in slots, incurring a lot of drift. Following activation of
    /// the [`timestamp_correction` and `timestamp_bounding`][tsc] features it
    /// is calculated using a [validator timestamp oracle][oracle].
    ///
    /// [tsc]: https://docs.solanalabs.com/implemented-proposals/bank-timestamp-correction
    /// [oracle]: https://docs.solanalabs.com/implemented-proposals/validator-timestamp-oracle
    pub unix_timestamp: UnixTimestamp,
}

#[repr(C)]
#[derive(PartialEq, Clone, Debug, Deserialize, Serialize)]
pub struct Rent {
    /// Rental rate in lamports/byte-year.
    pub lamports_per_byte_year: u64,

    /// Amount of time (in years) a balance must include rent for the account to
    /// be rent exempt.
    pub exemption_threshold: f64,

    /// The percentage of collected rent that is burned.
    ///
    /// Valid values are in the range [0, 100]. The remaining percentage is
    /// distributed to validators.
    pub burn_percent: u8,
}

/// Default rental rate in lamports/byte-year.
///
/// This calculation is based on:
/// - 10^9 lamports per SOL
/// - $1 per SOL
/// - $0.01 per megabyte day
/// - $3.65 per megabyte year
pub const DEFAULT_LAMPORTS_PER_BYTE_YEAR: u64 = 1_000_000_000 / 100 * 365 / (1024 * 1024);

/// Default amount of time (in years) the balance has to include rent for the
/// account to be rent exempt.
pub const DEFAULT_EXEMPTION_THRESHOLD: f64 = 2.0;

/// Default percentage of collected rent that is burned.
///
/// Valid values are in the range [0, 100]. The remaining percentage is
/// distributed to validators.
pub const DEFAULT_BURN_PERCENT: u8 = 50;

/// Account storage overhead for calculation of base rent.
///
/// This is the number of bytes required to store an account with no data. It is
/// added to an accounts data length when calculating [`Rent::minimum_balance`].
pub const ACCOUNT_STORAGE_OVERHEAD: u64 = 128;

impl Default for Rent {
    fn default() -> Self {
        Self {
            lamports_per_byte_year: DEFAULT_LAMPORTS_PER_BYTE_YEAR,
            exemption_threshold: DEFAULT_EXEMPTION_THRESHOLD,
            burn_percent: DEFAULT_BURN_PERCENT,
        }
    }
}

impl Rent {
    /// Calculate how much rent to burn from the collected rent.
    ///
    /// The first value returned is the amount burned. The second is the amount
    /// to distribute to validators.
    pub fn calculate_burn(&self, rent_collected: u64) -> (u64, u64) {
        let burned_portion = (rent_collected * u64::from(self.burn_percent)) / 100;
        (burned_portion, rent_collected - burned_portion)
    }

    /// Minimum balance due for rent-exemption of a given account data size.
    pub fn minimum_balance(&self, data_len: usize) -> u64 {
        let bytes = data_len as u64;
        (((ACCOUNT_STORAGE_OVERHEAD + bytes) * self.lamports_per_byte_year) as f64
            * self.exemption_threshold) as u64
    }

    /// Whether a given balance and data length would be exempt.
    pub fn is_exempt(&self, balance: u64, data_len: usize) -> bool {
        balance >= self.minimum_balance(data_len)
    }

    /// Rent due on account's data length with balance.
    pub fn due(&self, balance: u64, data_len: usize, years_elapsed: f64) -> RentDue {
        if self.is_exempt(balance, data_len) {
            RentDue::Exempt
        } else {
            RentDue::Paying(self.due_amount(data_len, years_elapsed))
        }
    }

    /// Rent due for account that is known to be not exempt.
    pub fn due_amount(&self, data_len: usize, years_elapsed: f64) -> u64 {
        let actual_data_len = data_len as u64 + ACCOUNT_STORAGE_OVERHEAD;
        let lamports_per_year = self.lamports_per_byte_year * actual_data_len;
        (lamports_per_year as f64 * years_elapsed) as u64
    }

    /// Creates a `Rent` that charges no lamports.
    ///
    /// This is used for testing.
    pub fn free() -> Self {
        Self {
            lamports_per_byte_year: 0,
            ..Rent::default()
        }
    }

    /// Creates a `Rent` that is scaled based on the number of slots in an epoch.
    ///
    /// This is used for testing.
    pub fn with_slots_per_epoch(slots_per_epoch: u64) -> Self {
        let ratio = slots_per_epoch as f64 / DEFAULT_SLOTS_PER_EPOCH as f64;
        let exemption_threshold = DEFAULT_EXEMPTION_THRESHOLD * ratio;
        let lamports_per_byte_year = (DEFAULT_LAMPORTS_PER_BYTE_YEAR as f64 / ratio) as u64;
        Self {
            lamports_per_byte_year,
            exemption_threshold,
            ..Self::default()
        }
    }
}

/// The return value of [`Rent::due`].
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum RentDue {
    /// Used to indicate the account is rent exempt.
    Exempt,
    /// The account owes this much rent.
    Paying(u64),
}

impl RentDue {
    /// Return the lamports due for rent.
    pub fn lamports(&self) -> u64 {
        match self {
            RentDue::Exempt => 0,
            RentDue::Paying(x) => *x,
        }
    }

    /// Return 'true' if rent exempt.
    pub fn is_exempt(&self) -> bool {
        match self {
            RentDue::Exempt => true,
            RentDue::Paying(_) => false,
        }
    }
}

#[repr(C, align(16))]
#[derive(Debug, PartialEq, Eq, Default, Clone, Deserialize, Serialize)]
pub struct EpochRewards {
    /// The starting block height of the rewards distribution in the current
    /// epoch
    pub distribution_starting_block_height: u64,

    /// Number of partitions in the rewards distribution in the current epoch,
    /// used to generate an EpochRewardsHasher
    pub num_partitions: u64,

    /// The blockhash of the parent block of the first block in the epoch, used
    /// to seed an EpochRewardsHasher
    pub parent_blockhash: Hash,

    /// The total rewards points calculated for the current epoch, where points
    /// equals the sum of (delegated stake * credits observed) for all
    /// delegations
    pub total_points: u128,

    /// The total rewards calculated for the current epoch. This may be greater
    /// than the total `distributed_rewards` at the end of the rewards period,
    /// due to rounding and inability to deliver rewards smaller than 1 lamport.
    pub total_rewards: u64,

    /// The rewards currently distributed for the current epoch, in lamports
    pub distributed_rewards: u64,

    /// Whether the rewards period (including calculation and distribution) is
    /// active
    pub active: bool,
}

impl EpochRewards {
    pub fn distribute(&mut self, amount: u64) {
        let new_distributed_rewards = self.distributed_rewards.saturating_add(amount);
        assert!(new_distributed_rewards <= self.total_rewards);
        self.distributed_rewards = new_distributed_rewards;
    }
}

use crate::impl_sysvar_get;

impl SysvarId for LastRestartSlot {
    fn id() -> Pubkey {
        last_restart_slot::id()
    }

    fn check_id(pubkey: &Pubkey) -> bool {
        last_restart_slot::check_id(pubkey)
    }
}

impl Sysvar for LastRestartSlot {
    impl_sysvar_get!(sol_get_last_restart_slot);
}

impl SysvarId for Clock {
    fn id() -> Pubkey {
        clock::id()
    }

    fn check_id(pubkey: &Pubkey) -> bool {
        clock::check_id(pubkey)
    }
}

impl Sysvar for Clock {
    impl_sysvar_get!(sol_get_clock_sysvar);
}

impl SysvarId for EpochRewards {
    fn id() -> Pubkey {
        epoch_rewards::id()
    }

    fn check_id(pubkey: &Pubkey) -> bool {
        epoch_rewards::check_id(pubkey)
    }
}

impl Sysvar for EpochRewards {
    impl_sysvar_get!(sol_get_epoch_rewards_sysvar);
}

impl SysvarId for Fees {
    fn id() -> Pubkey {
        clock::id()
    }

    fn check_id(pubkey: &Pubkey) -> bool {
        clock::check_id(pubkey)
    }
}

impl Sysvar for Fees {
    impl_sysvar_get!(sol_get_fees_sysvar);
}

impl SysvarId for Rent {
    fn id() -> Pubkey {
        fees::id()
    }

    fn check_id(pubkey: &Pubkey) -> bool {
        fees::check_id(pubkey)
    }
}

impl Sysvar for Rent {
    impl_sysvar_get!(sol_get_rent_sysvar);
}

impl SysvarId for EpochSchedule {
    fn id() -> Pubkey {
        epoch_schedule::id()
    }

    fn check_id(pubkey: &Pubkey) -> bool {
        epoch_schedule::check_id(pubkey)
    }
}

impl Sysvar for EpochSchedule {
    impl_sysvar_get!(sol_get_epoch_schedule_sysvar);
}
