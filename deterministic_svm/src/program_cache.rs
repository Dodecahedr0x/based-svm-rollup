use std::{
    collections::{hash_map::Entry, HashMap},
    fmt::{Debug, Formatter},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Condvar, Mutex, RwLock, Weak,
    },
    thread,
};

use log::{debug, error, log_enabled, trace};
use percentage::PercentageInteger;
use solana_sbpf::{
    elf::Executable,
    program::{BuiltinProgram, FunctionRegistry},
    verifier::RequisiteVerifier,
    vm::{Config, EbpfVm},
};

use crate::{Epoch, InvokeContext, Pubkey};

pub const HOST_ALIGN: usize = 16;
pub const MAX_LOADED_ENTRY_COUNT: usize = 512;
pub const DELAY_VISIBILITY_SLOT_OFFSET: Slot = 1;

pub type Slot = u64;
pub type ProgramRuntimeEnvironment = Arc<BuiltinProgram<InvokeContext<'static>>>;
pub type BuiltinFunction<C> = fn(*mut EbpfVm<C>, u64, u64, u64, u64, u64);
pub type BuiltinFunctionWithContext = BuiltinFunction<InvokeContext<'static>>;

#[derive(Clone, Debug, Default)]
pub struct ProgramCacheForTxBatch {
    /// Pubkey is the address of a program.
    /// ProgramCacheEntry is the corresponding program entry valid for the slot in which a transaction is being executed.
    entries: HashMap<Pubkey, Arc<ProgramCacheEntry>>,
    /// Program entries modified during the transaction batch.
    modified_entries: HashMap<Pubkey, Arc<ProgramCacheEntry>>,
    slot: Slot,
    pub environments: ProgramRuntimeEnvironments,
    /// Anticipated replacement for `environments` at the next epoch.
    ///
    /// This is `None` during most of an epoch, and only `Some` around the boundaries (at the end and beginning of an epoch).
    /// More precisely, it starts with the cache preparation phase a few hundred slots before the epoch boundary,
    /// and it ends with the first rerooting after the epoch boundary.
    /// Needed when a program is deployed at the last slot of an epoch, becomes effective in the next epoch.
    /// So needs to be compiled with the environment for the next epoch.
    pub upcoming_environments: Option<ProgramRuntimeEnvironments>,
    /// The epoch of the last rerooting
    pub latest_root_epoch: Epoch,
    pub hit_max_limit: bool,
    pub loaded_missing: bool,
    pub merged_modified: bool,
}

impl ProgramCacheForTxBatch {
    pub fn new(
        slot: Slot,
        environments: ProgramRuntimeEnvironments,
        upcoming_environments: Option<ProgramRuntimeEnvironments>,
        latest_root_epoch: Epoch,
    ) -> Self {
        Self {
            entries: HashMap::new(),
            modified_entries: HashMap::new(),
            slot,
            environments,
            upcoming_environments,
            latest_root_epoch,
            hit_max_limit: false,
            loaded_missing: false,
            merged_modified: false,
        }
    }

    pub fn new_from_cache<FG: ForkGraph>(
        slot: Slot,
        epoch: Epoch,
        cache: &ProgramCache<FG>,
    ) -> Self {
        Self {
            entries: HashMap::new(),
            modified_entries: HashMap::new(),
            slot,
            environments: cache.get_environments_for_epoch(epoch),
            upcoming_environments: cache.get_upcoming_environments_for_epoch(epoch),
            latest_root_epoch: cache.latest_root_epoch,
            hit_max_limit: false,
            loaded_missing: false,
            merged_modified: false,
        }
    }

    /// Returns the current environments depending on the given epoch
    pub fn get_environments_for_epoch(&self, epoch: Epoch) -> &ProgramRuntimeEnvironments {
        if epoch != self.latest_root_epoch {
            if let Some(upcoming_environments) = self.upcoming_environments.as_ref() {
                return upcoming_environments;
            }
        }
        &self.environments
    }

    /// Refill the cache with a single entry. It's typically called during transaction loading, and
    /// transaction processing (for program management instructions).
    /// It replaces the existing entry (if any) with the provided entry. The return value contains
    /// `true` if an entry existed.
    /// The function also returns the newly inserted value.
    pub fn replenish(
        &mut self,
        key: Pubkey,
        entry: Arc<ProgramCacheEntry>,
    ) -> (bool, Arc<ProgramCacheEntry>) {
        (self.entries.insert(key, entry.clone()).is_some(), entry)
    }

    /// Store an entry in `modified_entries` for a program modified during the
    /// transaction batch.
    pub fn store_modified_entry(&mut self, key: Pubkey, entry: Arc<ProgramCacheEntry>) {
        self.modified_entries.insert(key, entry);
    }

    /// Drain the program cache's modified entries, returning the owned
    /// collection.
    pub fn drain_modified_entries(&mut self) -> HashMap<Pubkey, Arc<ProgramCacheEntry>> {
        std::mem::take(&mut self.modified_entries)
    }

    pub fn find(&self, key: &Pubkey) -> Option<Arc<ProgramCacheEntry>> {
        // First lookup the cache of the programs modified by the current
        // transaction. If not found, lookup the cache of the cache of the
        // programs that are loaded for the transaction batch.
        self.modified_entries
            .get(key)
            .or(self.entries.get(key))
            .map(|entry| {
                if entry.is_implicit_delay_visibility_tombstone(self.slot) {
                    // Found a program entry on the current fork, but it's not effective
                    // yet. It indicates that the program has delayed visibility. Return
                    // the tombstone to reflect that.
                    Arc::new(ProgramCacheEntry::new_tombstone(
                        entry.deployment_slot,
                        entry.account_owner,
                        ProgramCacheEntryType::DelayVisibility,
                    ))
                } else {
                    entry.clone()
                }
            })
    }

    pub fn slot(&self) -> Slot {
        self.slot
    }

    pub fn set_slot_for_tests(&mut self, slot: Slot) {
        self.slot = slot;
    }

    pub fn merge(&mut self, modified_entries: &HashMap<Pubkey, Arc<ProgramCacheEntry>>) {
        modified_entries.iter().for_each(|(key, entry)| {
            self.merged_modified = true;
            self.replenish(*key, entry.clone());
        })
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Holds a program version at a specific address and on a specific slot / fork.
///
/// It contains the actual program in [ProgramCacheEntryType] and a bunch of meta-data.
#[derive(Debug, Default)]
pub struct ProgramCacheEntry {
    /// The program of this entry
    pub program: ProgramCacheEntryType,
    /// The loader of this entry
    pub account_owner: ProgramCacheEntryOwner,
    /// Size of account that stores the program and program data
    pub account_size: usize,
    /// Slot in which the program was (re)deployed
    pub deployment_slot: Slot,
    /// Slot in which this entry will become active (can be in the future)
    pub effective_slot: Slot,
    /// How often this entry was used by a transaction
    pub tx_usage_counter: AtomicU64,
    /// How often this entry was used by an instruction
    pub ix_usage_counter: AtomicU64,
    /// Latest slot in which the entry was used
    pub latest_access_slot: AtomicU64,
}

impl PartialEq for ProgramCacheEntry {
    fn eq(&self, other: &Self) -> bool {
        self.effective_slot == other.effective_slot
            && self.deployment_slot == other.deployment_slot
            && self.is_tombstone() == other.is_tombstone()
    }
}

impl ProgramCacheEntry {
    /// Creates a new user program
    pub fn new(
        loader_key: &Pubkey,
        program_runtime_environment: ProgramRuntimeEnvironment,
        deployment_slot: Slot,
        effective_slot: Slot,
        elf_bytes: &[u8],
        account_size: usize,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Self::new_internal(
            loader_key,
            program_runtime_environment,
            deployment_slot,
            effective_slot,
            elf_bytes,
            account_size,
            #[cfg(feature = "metrics")]
            metrics,
            false, /* reloading */
        )
    }

    /// Reloads a user program, *without* running the verifier.
    ///
    /// # Safety
    ///
    /// This method is unsafe since it assumes that the program has already been verified. Should
    /// only be called when the program was previously verified and loaded in the cache, but was
    /// unloaded due to inactivity. It should also be checked that the `program_runtime_environment`
    /// hasn't changed since it was unloaded.
    pub unsafe fn reload(
        loader_key: &Pubkey,
        program_runtime_environment: Arc<BuiltinProgram<InvokeContext<'static>>>,
        deployment_slot: Slot,
        effective_slot: Slot,
        elf_bytes: &[u8],
        account_size: usize,
        #[cfg(feature = "metrics")] metrics: &mut LoadProgramMetrics,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Self::new_internal(
            loader_key,
            program_runtime_environment,
            deployment_slot,
            effective_slot,
            elf_bytes,
            account_size,
            #[cfg(feature = "metrics")]
            metrics,
            true, /* reloading */
        )
    }

    fn new_internal(
        loader_key: &Pubkey,
        program_runtime_environment: Arc<BuiltinProgram<InvokeContext<'static>>>,
        deployment_slot: Slot,
        effective_slot: Slot,
        elf_bytes: &[u8],
        account_size: usize,
        #[cfg(feature = "metrics")] metrics: &mut LoadProgramMetrics,
        reloading: bool,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        #[cfg(feature = "metrics")]
        let load_elf_time = Measure::start("load_elf_time");
        // The following unused_mut exception is needed for architectures that do not
        // support JIT compilation.
        #[allow(unused_mut)]
        let mut executable = Executable::load(elf_bytes, program_runtime_environment.clone())?;
        #[cfg(feature = "metrics")]
        {
            metrics.load_elf_us = load_elf_time.end_as_us();
        }

        if !reloading {
            #[cfg(feature = "metrics")]
            let verify_code_time = Measure::start("verify_code_time");
            executable.verify::<RequisiteVerifier>()?;
            #[cfg(feature = "metrics")]
            {
                metrics.verify_code_us = verify_code_time.end_as_us();
            }
        }

        #[cfg(all(not(target_os = "windows"), target_arch = "x86_64"))]
        {
            #[cfg(feature = "metrics")]
            let jit_compile_time = Measure::start("jit_compile_time");
            executable.jit_compile()?;
            #[cfg(feature = "metrics")]
            {
                metrics.jit_compile_us = jit_compile_time.end_as_us();
            }
        }

        Ok(Self {
            deployment_slot,
            account_owner: ProgramCacheEntryOwner::try_from(loader_key).unwrap(),
            account_size,
            effective_slot,
            tx_usage_counter: AtomicU64::new(0),
            program: ProgramCacheEntryType::Loaded(executable),
            ix_usage_counter: AtomicU64::new(0),
            latest_access_slot: AtomicU64::new(0),
        })
    }

    pub fn to_unloaded(&self) -> Option<Self> {
        match &self.program {
            ProgramCacheEntryType::Loaded(_) => {}
            ProgramCacheEntryType::FailedVerification(_)
            | ProgramCacheEntryType::Closed
            | ProgramCacheEntryType::DelayVisibility
            | ProgramCacheEntryType::Unloaded(_)
            | ProgramCacheEntryType::Builtin(_) => {
                return None;
            }
        }
        Some(Self {
            program: ProgramCacheEntryType::Unloaded(self.program.get_environment()?.clone()),
            account_owner: self.account_owner,
            account_size: self.account_size,
            deployment_slot: self.deployment_slot,
            effective_slot: self.effective_slot,
            tx_usage_counter: AtomicU64::new(self.tx_usage_counter.load(Ordering::Relaxed)),
            ix_usage_counter: AtomicU64::new(self.ix_usage_counter.load(Ordering::Relaxed)),
            latest_access_slot: AtomicU64::new(self.latest_access_slot.load(Ordering::Relaxed)),
        })
    }

    /// Creates a new built-in program
    pub fn new_builtin(
        deployment_slot: Slot,
        account_size: usize,
        builtin_function: BuiltinFunctionWithContext,
    ) -> Self {
        let mut function_registry = FunctionRegistry::default();
        function_registry
            .register_function_hashed(*b"entrypoint", builtin_function)
            .unwrap();
        Self {
            deployment_slot,
            account_owner: ProgramCacheEntryOwner::NativeLoader,
            account_size,
            effective_slot: deployment_slot,
            tx_usage_counter: AtomicU64::new(0),
            program: ProgramCacheEntryType::Builtin(BuiltinProgram::new_builtin(function_registry)),
            ix_usage_counter: AtomicU64::new(0),
            latest_access_slot: AtomicU64::new(0),
        }
    }

    pub fn new_tombstone(
        slot: Slot,
        account_owner: ProgramCacheEntryOwner,
        reason: ProgramCacheEntryType,
    ) -> Self {
        let tombstone = Self {
            program: reason,
            account_owner,
            account_size: 0,
            deployment_slot: slot,
            effective_slot: slot,
            tx_usage_counter: AtomicU64::default(),
            ix_usage_counter: AtomicU64::default(),
            latest_access_slot: AtomicU64::new(0),
        };
        debug_assert!(tombstone.is_tombstone());
        tombstone
    }

    pub fn is_tombstone(&self) -> bool {
        matches!(
            self.program,
            ProgramCacheEntryType::FailedVerification(_)
                | ProgramCacheEntryType::Closed
                | ProgramCacheEntryType::DelayVisibility
        )
    }

    fn is_implicit_delay_visibility_tombstone(&self, slot: Slot) -> bool {
        !matches!(self.program, ProgramCacheEntryType::Builtin(_))
            && self.effective_slot.saturating_sub(self.deployment_slot)
                == DELAY_VISIBILITY_SLOT_OFFSET
            && slot >= self.deployment_slot
            && slot < self.effective_slot
    }

    pub fn update_access_slot(&self, slot: Slot) {
        let _ = self.latest_access_slot.fetch_max(slot, Ordering::Relaxed);
    }

    pub fn decayed_usage_counter(&self, now: Slot) -> u64 {
        let last_access = self.latest_access_slot.load(Ordering::Relaxed);
        // Shifting the u64 value for more than 63 will cause an overflow.
        let decaying_for = std::cmp::min(63, now.saturating_sub(last_access));
        self.tx_usage_counter.load(Ordering::Relaxed) >> decaying_for
    }

    pub fn account_owner(&self) -> Pubkey {
        self.account_owner.into()
    }
}

#[derive(Default)]
pub enum ProgramCacheEntryType {
    /// Tombstone for programs which currently do not pass the verifier but could if the feature set changed.
    FailedVerification(ProgramRuntimeEnvironment),
    /// Tombstone for programs that were either explicitly closed or never deployed.
    ///
    /// It's also used for accounts belonging to program loaders, that don't actually contain program code (e.g. buffer accounts for LoaderV3 programs).
    #[default]
    Closed,
    /// Tombstone for programs which have recently been modified but the new version is not visible yet.
    DelayVisibility,
    /// Successfully verified but not currently compiled.
    ///
    /// It continues to track usage statistics even when the compiled executable of the program is evicted from memory.
    Unloaded(ProgramRuntimeEnvironment),
    /// Verified and compiled program
    Loaded(Executable<InvokeContext<'static>>),
    /// A built-in program which is not stored on-chain but backed into and distributed with the validator
    Builtin(BuiltinProgram<InvokeContext<'static>>),
}

impl Debug for ProgramCacheEntryType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ProgramCacheEntryType::FailedVerification(_) => {
                write!(f, "ProgramCacheEntryType::FailedVerification")
            }
            ProgramCacheEntryType::Closed => write!(f, "ProgramCacheEntryType::Closed"),
            ProgramCacheEntryType::DelayVisibility => {
                write!(f, "ProgramCacheEntryType::DelayVisibility")
            }
            ProgramCacheEntryType::Unloaded(_) => write!(f, "ProgramCacheEntryType::Unloaded"),
            ProgramCacheEntryType::Loaded(_) => write!(f, "ProgramCacheEntryType::Loaded"),
            ProgramCacheEntryType::Builtin(_) => write!(f, "ProgramCacheEntryType::Builtin"),
        }
    }
}

impl ProgramCacheEntryType {
    /// Returns a reference to its environment if it has one
    pub fn get_environment(&self) -> Option<&ProgramRuntimeEnvironment> {
        match self {
            ProgramCacheEntryType::Loaded(program) => Some(program.get_loader()),
            ProgramCacheEntryType::FailedVerification(env)
            | ProgramCacheEntryType::Unloaded(env) => Some(env),
            _ => None,
        }
    }
}

#[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProgramCacheEntryOwner {
    #[default]
    NativeLoader,
    LoaderV1,
    LoaderV2,
    LoaderV3,
    LoaderV4,
}

pub mod native_loader {
    use crate::{pubkey_from_str, Pubkey};
    pub const ID: Pubkey = [
        5, 135, 132, 191, 20, 139, 164, 40, 47, 176, 18, 87, 72, 136, 169, 241, 83, 160, 125, 173,
        247, 101, 192, 69, 92, 154, 151, 3, 128, 0, 0, 0,
    ];
    pub fn id() -> Pubkey {
        pubkey_from_str("NativeLoader1111111111111111111111111111111")
    }
    pub fn check_id(pk: &Pubkey) -> bool {
        *pk == ID
    }
}

pub mod bpf_loader_deprecated {
    use crate::{pubkey_from_str, Pubkey};
    pub const ID: Pubkey = [
        2, 168, 246, 145, 78, 136, 161, 107, 189, 35, 149, 133, 95, 100, 4, 217, 180, 244, 86, 183,
        130, 27, 176, 20, 87, 73, 66, 140, 0, 0, 0, 0,
    ];
    pub fn id() -> Pubkey {
        pubkey_from_str("BPFLoader1111111111111111111111111111111111")
    }
    pub fn check_id(pk: &Pubkey) -> bool {
        *pk == ID
    }
}

pub mod bpf_loader {
    use crate::{pubkey_from_str, Pubkey};
    pub const ID: Pubkey = [
        2, 168, 246, 145, 78, 136, 161, 110, 57, 90, 225, 40, 148, 143, 250, 105, 86, 147, 55, 104,
        24, 221, 71, 67, 82, 33, 243, 198, 0, 0, 0, 0,
    ];
    pub fn id() -> Pubkey {
        pubkey_from_str("BPFLoader2111111111111111111111111111111111")
    }
    pub fn check_id(pk: &Pubkey) -> bool {
        *pk == ID
    }
}

pub mod bpf_loader_upgradeable {
    use crate::{pubkey_from_str, Pubkey};
    pub const ID: Pubkey = [
        2, 168, 246, 145, 78, 136, 161, 176, 226, 16, 21, 62, 247, 99, 174, 43, 0, 194, 185, 61,
        22, 193, 36, 210, 192, 83, 122, 16, 4, 128, 0, 0,
    ];
    pub fn id() -> Pubkey {
        pubkey_from_str("BPFLoaderUpgradeab1e11111111111111111111111")
    }
    pub fn check_id(pk: &Pubkey) -> bool {
        *pk == ID
    }
}

pub mod loader_v4 {
    use crate::{pubkey_from_str, Pubkey};
    pub const ID: Pubkey = [
        5, 18, 180, 17, 81, 81, 227, 122, 173, 10, 139, 197, 211, 136, 46, 123, 127, 218, 76, 243,
        210, 192, 40, 200, 207, 131, 54, 24, 0, 0, 0, 0,
    ];
    pub fn id() -> Pubkey {
        pubkey_from_str("LoaderV411111111111111111111111111111111111")
    }
    pub fn check_id(pk: &Pubkey) -> bool {
        *pk == ID
    }
}

impl TryFrom<&Pubkey> for ProgramCacheEntryOwner {
    type Error = ();
    fn try_from(loader_key: &Pubkey) -> Result<Self, ()> {
        if native_loader::check_id(loader_key) {
            Ok(ProgramCacheEntryOwner::NativeLoader)
        } else if bpf_loader_deprecated::check_id(loader_key) {
            Ok(ProgramCacheEntryOwner::LoaderV1)
        } else if bpf_loader::check_id(loader_key) {
            Ok(ProgramCacheEntryOwner::LoaderV2)
        } else if bpf_loader_upgradeable::check_id(loader_key) {
            Ok(ProgramCacheEntryOwner::LoaderV3)
        } else if loader_v4::check_id(loader_key) {
            Ok(ProgramCacheEntryOwner::LoaderV4)
        } else {
            Err(())
        }
    }
}

impl From<ProgramCacheEntryOwner> for Pubkey {
    fn from(program_cache_entry_owner: ProgramCacheEntryOwner) -> Self {
        match program_cache_entry_owner {
            ProgramCacheEntryOwner::NativeLoader => native_loader::id(),
            ProgramCacheEntryOwner::LoaderV1 => bpf_loader_deprecated::id(),
            ProgramCacheEntryOwner::LoaderV2 => bpf_loader::id(),
            ProgramCacheEntryOwner::LoaderV3 => bpf_loader_upgradeable::id(),
            ProgramCacheEntryOwner::LoaderV4 => loader_v4::id(),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct AlignedMemory<const ALIGN: usize> {
    max_len: usize,
    align_offset: usize,
    mem: Vec<u8>,
    zero_up_to_max_len: bool,
}

#[derive(Clone, Debug)]
pub struct ProgramRuntimeEnvironments {
    /// For program runtime V1
    pub program_runtime_v1: ProgramRuntimeEnvironment,
    /// For program runtime V2
    pub program_runtime_v2: ProgramRuntimeEnvironment,
}

impl Default for ProgramRuntimeEnvironments {
    fn default() -> Self {
        let empty_loader = Arc::new(BuiltinProgram::new_loader(
            Config::default(),
            FunctionRegistry::default(),
        ));
        Self {
            program_runtime_v1: empty_loader.clone(),
            program_runtime_v2: empty_loader,
        }
    }
}

/// Maps relationship between two slots.
pub trait ForkGraph {
    /// Returns the BlockRelation of A to B
    fn relationship(&self, a: Slot, b: Slot) -> BlockRelation;
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum BlockRelation {
    /// The slot is on the same fork and is an ancestor of the other slot
    Ancestor,
    /// The two slots are equal and are on the same fork
    Equal,
    /// The slot is on the same fork and is a descendant of the other slot
    Descendant,
    /// The slots are on two different forks and may have had a common ancestor at some point
    Unrelated,
    /// Either one or both of the slots are either older than the latest root, or are in future
    Unknown,
}

pub enum ProgramCacheMatchCriteria {
    DeployedOnOrAfterSlot(Slot),
    Tombstone,
    NoCriteria,
}

/// This structure is the global cache of loaded, verified and compiled programs.
///
/// It ...
/// - is validator global and fork graph aware, so it can optimize the commonalities across banks.
/// - handles the visibility rules of un/re/deployments.
/// - stores the usage statistics and verification status of each program.
/// - is elastic and uses a probabilistic eviction stragety based on the usage statistics.
/// - also keeps the compiled executables around, but only for the most used programs.
/// - supports various kinds of tombstones to avoid loading programs which can not be loaded.
/// - cleans up entries on orphan branches when the block store is rerooted.
/// - supports the cache preparation phase before feature activations which can change cached programs.
/// - manages the environments of the programs and upcoming environments for the next epoch.
/// - allows for cooperative loading of TX batches which hit the same missing programs simultaneously.
/// - enforces that all programs used in a batch are eagerly loaded ahead of execution.
/// - is not persisted to disk or a snapshot, so it needs to cold start and warm up first.
pub struct ProgramCache<FG: ForkGraph> {
    /// Index of the cached entries and cooperative loading tasks
    index: IndexImplementation,
    /// The slot of the last rerooting
    pub latest_root_slot: Slot,
    /// The epoch of the last rerooting
    pub latest_root_epoch: Epoch,
    /// Environments of the current epoch
    pub environments: ProgramRuntimeEnvironments,
    /// Anticipated replacement for `environments` at the next epoch
    ///
    /// This is `None` during most of an epoch, and only `Some` around the boundaries (at the end and beginning of an epoch).
    /// More precisely, it starts with the cache preparation phase a few hundred slots before the epoch boundary,
    /// and it ends with the first rerooting after the epoch boundary.
    pub upcoming_environments: Option<ProgramRuntimeEnvironments>,
    /// List of loaded programs which should be recompiled before the next epoch (but don't have to).
    pub programs_to_recompile: Vec<(Pubkey, Arc<ProgramCacheEntry>)>,
    /// Statistics counters
    pub stats: ProgramCacheStats,
    /// Reference to the block store
    pub fork_graph: Option<Weak<RwLock<FG>>>,
    /// Coordinates TX batches waiting for others to complete their task during cooperative loading
    pub loading_task_waiter: Arc<LoadingTaskWaiter>,
}

impl<FG: ForkGraph> Debug for ProgramCache<FG> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProgramCache")
            .field("root slot", &self.latest_root_slot)
            .field("root epoch", &self.latest_root_epoch)
            .field("stats", &self.stats)
            .field("index", &self.index)
            .finish()
    }
}

impl<FG: ForkGraph> ProgramCache<FG> {
    pub fn new(root_slot: Slot, root_epoch: Epoch) -> Self {
        Self {
            index: IndexImplementation::V1 {
                entries: HashMap::new(),
                loading_entries: Mutex::new(HashMap::new()),
            },
            latest_root_slot: root_slot,
            latest_root_epoch: root_epoch,
            environments: ProgramRuntimeEnvironments::default(),
            upcoming_environments: None,
            programs_to_recompile: Vec::default(),
            stats: ProgramCacheStats::default(),
            fork_graph: None,
            loading_task_waiter: Arc::new(LoadingTaskWaiter::default()),
        }
    }

    pub fn set_fork_graph(&mut self, fork_graph: Weak<RwLock<FG>>) {
        self.fork_graph = Some(fork_graph);
    }

    /// Returns the current environments depending on the given epoch
    pub fn get_environments_for_epoch(&self, epoch: Epoch) -> ProgramRuntimeEnvironments {
        if epoch != self.latest_root_epoch {
            if let Some(upcoming_environments) = self.upcoming_environments.as_ref() {
                return upcoming_environments.clone();
            }
        }
        self.environments.clone()
    }

    /// Returns the upcoming environments depending on the given epoch
    pub fn get_upcoming_environments_for_epoch(
        &self,
        epoch: Epoch,
    ) -> Option<ProgramRuntimeEnvironments> {
        if epoch == self.latest_root_epoch {
            return self.upcoming_environments.clone();
        }
        None
    }

    /// Insert a single entry. It's typically called during transaction loading,
    /// when the cache doesn't contain the entry corresponding to program `key`.
    pub fn assign_program(&mut self, key: Pubkey, entry: Arc<ProgramCacheEntry>) -> bool {
        debug_assert!(!matches!(
            &entry.program,
            ProgramCacheEntryType::DelayVisibility
        ));
        // This function always returns `true` during normal operation.
        // Only during the cache preparation phase this can return `false`
        // for entries with `upcoming_environments`.
        fn is_current_env(
            environments: &ProgramRuntimeEnvironments,
            env_opt: Option<&ProgramRuntimeEnvironment>,
        ) -> bool {
            env_opt
                .map(|env| {
                    Arc::ptr_eq(env, &environments.program_runtime_v1)
                        || Arc::ptr_eq(env, &environments.program_runtime_v2)
                })
                .unwrap_or(true)
        }
        match &mut self.index {
            IndexImplementation::V1 { entries, .. } => {
                let slot_versions = &mut entries.entry(key).or_default();
                match slot_versions.binary_search_by(|at| {
                    at.effective_slot
                        .cmp(&entry.effective_slot)
                        .then(at.deployment_slot.cmp(&entry.deployment_slot))
                        .then(
                            // This `.then()` has no effect during normal operation.
                            // Only during the cache preparation phase this does allow entries
                            // which only differ in their environment to be interleaved in `slot_versions`.
                            is_current_env(&self.environments, at.program.get_environment()).cmp(
                                &is_current_env(
                                    &self.environments,
                                    entry.program.get_environment(),
                                ),
                            ),
                        )
                }) {
                    Ok(index) => {
                        let existing = slot_versions.get_mut(index).unwrap();
                        match (&existing.program, &entry.program) {
                            (
                                ProgramCacheEntryType::Builtin(_),
                                ProgramCacheEntryType::Builtin(_),
                            )
                            | (
                                ProgramCacheEntryType::Unloaded(_),
                                ProgramCacheEntryType::Loaded(_),
                            ) => {}
                            _ => {
                                // Something is wrong, I can feel it ...
                                error!("ProgramCache::assign_program() failed key={:?} existing={:?} entry={:?}", key, slot_versions, entry);
                                debug_assert!(false, "Unexpected replacement of an entry");
                                self.stats.replacements.fetch_add(1, Ordering::Relaxed);
                                return true;
                            }
                        }
                        // Copy over the usage counter to the new entry
                        entry.tx_usage_counter.fetch_add(
                            existing.tx_usage_counter.load(Ordering::Relaxed),
                            Ordering::Relaxed,
                        );
                        entry.ix_usage_counter.fetch_add(
                            existing.ix_usage_counter.load(Ordering::Relaxed),
                            Ordering::Relaxed,
                        );
                        *existing = Arc::clone(&entry);
                        self.stats.reloads.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(index) => {
                        self.stats.insertions.fetch_add(1, Ordering::Relaxed);
                        slot_versions.insert(index, Arc::clone(&entry));
                    }
                }
            }
        }
        false
    }

    pub fn prune_by_deployment_slot(&mut self, slot: Slot) {
        match &mut self.index {
            IndexImplementation::V1 { entries, .. } => {
                for second_level in entries.values_mut() {
                    second_level.retain(|entry| entry.deployment_slot != slot);
                }
                self.remove_programs_with_no_entries();
            }
        }
    }

    /// Before rerooting the blockstore this removes all superfluous entries
    pub fn prune(&mut self, new_root_slot: Slot, new_root_epoch: Epoch) {
        let Some(fork_graph) = self.fork_graph.clone() else {
            error!("Program cache doesn't have fork graph.");
            return;
        };
        let fork_graph = fork_graph.upgrade().unwrap();
        let Ok(fork_graph) = fork_graph.read() else {
            error!("Failed to lock fork graph for reading.");
            return;
        };
        let mut preparation_phase_ends = false;
        if self.latest_root_epoch != new_root_epoch {
            self.latest_root_epoch = new_root_epoch;
            if let Some(upcoming_environments) = self.upcoming_environments.take() {
                preparation_phase_ends = true;
                self.environments = upcoming_environments;
                self.programs_to_recompile.clear();
            }
        }
        match &mut self.index {
            IndexImplementation::V1 { entries, .. } => {
                for second_level in entries.values_mut() {
                    // Remove entries un/re/deployed on orphan forks
                    let mut first_ancestor_found = false;
                    let mut first_ancestor_env = None;
                    *second_level = second_level
                        .iter()
                        .rev()
                        .filter(|entry| {
                            let relation =
                                fork_graph.relationship(entry.deployment_slot, new_root_slot);
                            if entry.deployment_slot >= new_root_slot {
                                matches!(relation, BlockRelation::Equal | BlockRelation::Descendant)
                            } else if matches!(relation, BlockRelation::Ancestor)
                                || entry.deployment_slot <= self.latest_root_slot
                            {
                                if !first_ancestor_found {
                                    first_ancestor_found = true;
                                    first_ancestor_env = entry.program.get_environment();
                                    return true;
                                }
                                // Do not prune the entry if the runtime environment of the entry is different
                                // than the entry that was previously found (stored in first_ancestor_env).
                                // Different environment indicates that this entry might belong to an older
                                // epoch that had a different environment (e.g. different feature set).
                                // Once the root moves to the new/current epoch, the entry will get pruned.
                                // But, until then the entry might still be getting used by an older slot.
                                if let Some(entry_env) = entry.program.get_environment() {
                                    if let Some(env) = first_ancestor_env {
                                        if !Arc::ptr_eq(entry_env, env) {
                                            return true;
                                        }
                                    }
                                }
                                self.stats.prunes_orphan.fetch_add(1, Ordering::Relaxed);
                                false
                            } else {
                                self.stats.prunes_orphan.fetch_add(1, Ordering::Relaxed);
                                false
                            }
                        })
                        .filter(|entry| {
                            // Remove outdated environment of previous feature set
                            if preparation_phase_ends
                                && !Self::matches_environment(entry, &self.environments)
                            {
                                self.stats
                                    .prunes_environment
                                    .fetch_add(1, Ordering::Relaxed);
                                return false;
                            }
                            true
                        })
                        .cloned()
                        .collect();
                    second_level.reverse();
                }
            }
        }
        self.remove_programs_with_no_entries();
        debug_assert!(self.latest_root_slot <= new_root_slot);
        self.latest_root_slot = new_root_slot;
    }

    fn matches_environment(
        entry: &Arc<ProgramCacheEntry>,
        environments: &ProgramRuntimeEnvironments,
    ) -> bool {
        let Some(environment) = entry.program.get_environment() else {
            return true;
        };
        Arc::ptr_eq(environment, &environments.program_runtime_v1)
            || Arc::ptr_eq(environment, &environments.program_runtime_v2)
    }

    fn matches_criteria(
        program: &Arc<ProgramCacheEntry>,
        criteria: &ProgramCacheMatchCriteria,
    ) -> bool {
        match criteria {
            ProgramCacheMatchCriteria::DeployedOnOrAfterSlot(slot) => {
                program.deployment_slot >= *slot
            }
            ProgramCacheMatchCriteria::Tombstone => program.is_tombstone(),
            ProgramCacheMatchCriteria::NoCriteria => true,
        }
    }

    /// Extracts a subset of the programs relevant to a transaction batch
    /// and returns which program accounts the accounts DB needs to load.
    pub fn extract(
        &self,
        search_for: &mut Vec<(Pubkey, (ProgramCacheMatchCriteria, u64))>,
        loaded_programs_for_tx_batch: &mut ProgramCacheForTxBatch,
        is_first_round: bool,
    ) -> Option<(Pubkey, u64)> {
        debug_assert!(self.fork_graph.is_some());
        let fork_graph = self.fork_graph.as_ref().unwrap().upgrade().unwrap();
        let locked_fork_graph = fork_graph.read().unwrap();
        let mut cooperative_loading_task = None;
        match &self.index {
            IndexImplementation::V1 {
                entries,
                loading_entries,
            } => {
                search_for.retain(|(key, (match_criteria, usage_count))| {
                    if let Some(second_level) = entries.get(key) {
                        for entry in second_level.iter().rev() {
                            if entry.deployment_slot <= self.latest_root_slot
                                || matches!(
                                    locked_fork_graph.relationship(
                                        entry.deployment_slot,
                                        loaded_programs_for_tx_batch.slot
                                    ),
                                    BlockRelation::Equal | BlockRelation::Ancestor
                                )
                            {
                                let entry_to_return = if loaded_programs_for_tx_batch.slot
                                    >= entry.effective_slot
                                    && Self::matches_environment(
                                        entry,
                                        &loaded_programs_for_tx_batch.environments,
                                    ) {
                                    if !Self::matches_criteria(entry, match_criteria) {
                                        break;
                                    }
                                    if let ProgramCacheEntryType::Unloaded(_environment) =
                                        &entry.program
                                    {
                                        break;
                                    }
                                    entry.clone()
                                } else if entry.is_implicit_delay_visibility_tombstone(
                                    loaded_programs_for_tx_batch.slot,
                                ) {
                                    // Found a program entry on the current fork, but it's not effective
                                    // yet. It indicates that the program has delayed visibility. Return
                                    // the tombstone to reflect that.
                                    Arc::new(ProgramCacheEntry::new_tombstone(
                                        entry.deployment_slot,
                                        entry.account_owner,
                                        ProgramCacheEntryType::DelayVisibility,
                                    ))
                                } else {
                                    continue;
                                };
                                entry_to_return
                                    .update_access_slot(loaded_programs_for_tx_batch.slot);
                                entry_to_return
                                    .tx_usage_counter
                                    .fetch_add(*usage_count, Ordering::Relaxed);
                                loaded_programs_for_tx_batch
                                    .entries
                                    .insert(*key, entry_to_return);
                                return false;
                            }
                        }
                    }
                    if cooperative_loading_task.is_none() {
                        let mut loading_entries = loading_entries.lock().unwrap();
                        let entry = loading_entries.entry(*key);
                        if let Entry::Vacant(entry) = entry {
                            entry.insert((
                                loaded_programs_for_tx_batch.slot,
                                thread::current().id(),
                            ));
                            cooperative_loading_task = Some((*key, *usage_count));
                        }
                    }
                    true
                });
            }
        }
        drop(locked_fork_graph);
        if is_first_round {
            self.stats
                .misses
                .fetch_add(search_for.len() as u64, Ordering::Relaxed);
            self.stats.hits.fetch_add(
                loaded_programs_for_tx_batch.entries.len() as u64,
                Ordering::Relaxed,
            );
        }
        cooperative_loading_task
    }

    /// Called by Bank::replenish_program_cache() for each program that is done loading.
    pub fn finish_cooperative_loading_task(
        &mut self,
        slot: Slot,
        key: Pubkey,
        loaded_program: Arc<ProgramCacheEntry>,
    ) -> bool {
        match &mut self.index {
            IndexImplementation::V1 {
                loading_entries, ..
            } => {
                let loading_thread = loading_entries.get_mut().unwrap().remove(&key);
                debug_assert_eq!(loading_thread, Some((slot, thread::current().id())));
                // Check that it will be visible to our own fork once inserted
                if loaded_program.deployment_slot > self.latest_root_slot
                    && !matches!(
                        self.fork_graph
                            .as_ref()
                            .unwrap()
                            .upgrade()
                            .unwrap()
                            .read()
                            .unwrap()
                            .relationship(loaded_program.deployment_slot, slot),
                        BlockRelation::Equal | BlockRelation::Ancestor
                    )
                {
                    self.stats.lost_insertions.fetch_add(1, Ordering::Relaxed);
                }
                let was_occupied = self.assign_program(key, loaded_program);
                self.loading_task_waiter.notify();
                was_occupied
            }
        }
    }

    pub fn merge(&mut self, modified_entries: &HashMap<Pubkey, Arc<ProgramCacheEntry>>) {
        modified_entries.iter().for_each(|(key, entry)| {
            self.assign_program(*key, entry.clone());
        })
    }

    /// Returns the list of entries which are verified and compiled.
    pub fn get_flattened_entries(
        &self,
        include_program_runtime_v1: bool,
        _include_program_runtime_v2: bool,
    ) -> Vec<(Pubkey, Arc<ProgramCacheEntry>)> {
        match &self.index {
            IndexImplementation::V1 { entries, .. } => entries
                .iter()
                .flat_map(|(id, second_level)| {
                    second_level
                        .iter()
                        .filter_map(move |program| match program.program {
                            ProgramCacheEntryType::Loaded(_) => {
                                if include_program_runtime_v1 {
                                    Some((*id, program.clone()))
                                } else {
                                    None
                                }
                            }
                            _ => None,
                        })
                })
                .collect(),
        }
    }

    /// Returns the list of all entries in the cache.
    pub fn get_flattened_entries_for_tests(&self) -> Vec<(Pubkey, Arc<ProgramCacheEntry>)> {
        match &self.index {
            IndexImplementation::V1 { entries, .. } => entries
                .iter()
                .flat_map(|(id, second_level)| {
                    second_level.iter().map(|program| (*id, program.clone()))
                })
                .collect(),
        }
    }

    /// Returns the slot versions for the given program id.
    pub fn get_slot_versions_for_tests(&self, key: &Pubkey) -> &[Arc<ProgramCacheEntry>] {
        match &self.index {
            IndexImplementation::V1 { entries, .. } => entries
                .get(key)
                .map(|second_level| second_level.as_ref())
                .unwrap_or(&[]),
        }
    }

    /// Unloads programs which were used infrequently
    pub fn sort_and_unload(&mut self, shrink_to: PercentageInteger) {
        let mut sorted_candidates = self.get_flattened_entries(true, true);
        sorted_candidates
            .sort_by_cached_key(|(_id, program)| program.tx_usage_counter.load(Ordering::Relaxed));
        let num_to_unload = sorted_candidates
            .len()
            .saturating_sub(shrink_to.apply_to(MAX_LOADED_ENTRY_COUNT));
        self.unload_program_entries(sorted_candidates.iter().take(num_to_unload));
    }

    /// Evicts programs using 2's random selection, choosing the least used program out of the two entries.
    /// The eviction is performed enough number of times to reduce the cache usage to the given percentage.
    pub fn evict_using_2s_random_selection(&mut self, shrink_to: PercentageInteger, now: Slot) {
        let mut candidates = self.get_flattened_entries(true, true);
        self.stats
            .water_level
            .store(candidates.len() as u64, Ordering::Relaxed);
        let num_to_unload = candidates
            .len()
            .saturating_sub(shrink_to.apply_to(MAX_LOADED_ENTRY_COUNT));
        fn random_index_and_usage_counter(
            candidates: &[(Pubkey, Arc<ProgramCacheEntry>)],
            now: Slot,
        ) -> (usize, u64) {
            // let mut rng = thread_rng();
            // let index = rng.gen_range(0..candidates.len());
            let index = 0;
            let usage_counter = candidates
                .get(index)
                .expect("Failed to get cached entry")
                .1
                .decayed_usage_counter(now);
            (index, usage_counter)
        }

        for _ in 0..num_to_unload {
            let (index1, usage_counter1) = random_index_and_usage_counter(&candidates, now);
            let (index2, usage_counter2) = random_index_and_usage_counter(&candidates, now);

            let (program, entry) = if usage_counter1 < usage_counter2 {
                candidates.swap_remove(index1)
            } else {
                candidates.swap_remove(index2)
            };
            self.unload_program_entry(&program, &entry);
        }
    }

    /// Removes all the entries at the given keys, if they exist
    pub fn remove_programs(&mut self, keys: impl Iterator<Item = Pubkey>) {
        match &mut self.index {
            IndexImplementation::V1 { entries, .. } => {
                for k in keys {
                    entries.remove(&k);
                }
            }
        }
    }

    /// This function removes the given entry for the given program from the cache.
    /// The function expects that the program and entry exists in the cache. Otherwise it'll panic.
    fn unload_program_entry(&mut self, program: &Pubkey, remove_entry: &Arc<ProgramCacheEntry>) {
        match &mut self.index {
            IndexImplementation::V1 { entries, .. } => {
                let second_level = entries.get_mut(program).expect("Cache lookup failed");
                let candidate = second_level
                    .iter_mut()
                    .find(|entry| entry == &remove_entry)
                    .expect("Program entry not found");

                // Certain entry types cannot be unloaded, such as tombstones, or already unloaded entries.
                // For such entries, `to_unloaded()` will return None.
                // These entry types do not occupy much memory.
                if let Some(unloaded) = candidate.to_unloaded() {
                    if candidate.tx_usage_counter.load(Ordering::Relaxed) == 1 {
                        self.stats.one_hit_wonders.fetch_add(1, Ordering::Relaxed);
                    }
                    self.stats
                        .evictions
                        .entry(*program)
                        .and_modify(|c| *c = c.saturating_add(1))
                        .or_insert(1);
                    *candidate = Arc::new(unloaded);
                }
            }
        }
    }

    fn unload_program_entries<'a>(
        &mut self,
        remove: impl Iterator<Item = &'a (Pubkey, Arc<ProgramCacheEntry>)>,
    ) {
        for (program, entry) in remove {
            self.unload_program_entry(program, entry);
        }
    }

    fn remove_programs_with_no_entries(&mut self) {
        match &mut self.index {
            IndexImplementation::V1 { entries, .. } => {
                let num_programs_before_removal = entries.len();
                entries.retain(|_key, second_level| !second_level.is_empty());
                if entries.len() < num_programs_before_removal {
                    self.stats.empty_entries.fetch_add(
                        num_programs_before_removal.saturating_sub(entries.len()) as u64,
                        Ordering::Relaxed,
                    );
                }
            }
        }
    }
}

#[derive(Debug)]
enum IndexImplementation {
    /// Fork-graph aware index implementation
    V1 {
        /// A two level index:
        ///
        /// - the first level is for the address at which programs are deployed
        /// - the second level for the slot (and thus also fork), sorted by slot number.
        entries: HashMap<Pubkey, Vec<Arc<ProgramCacheEntry>>>,
        /// The entries that are getting loaded and have not yet finished loading.
        ///
        /// The key is the program address, the value is a tuple of the slot in which the program is
        /// being loaded and the thread ID doing the load.
        ///
        /// It is possible that multiple TX batches from different slots need different versions of a
        /// program. The deployment slot of a program is only known after load tho,
        /// so all loads for a given program key are serialized.
        loading_entries: Mutex<HashMap<Pubkey, (Slot, thread::ThreadId)>>,
    },
}

/// Suspends the thread in case no cooprative loading task was assigned
#[derive(Debug, Default)]
pub struct LoadingTaskWaiter {
    cookie: Mutex<LoadingTaskCookie>,
    cond: Condvar,
}

impl LoadingTaskWaiter {
    pub fn new() -> Self {
        Self {
            cookie: Mutex::new(LoadingTaskCookie::new()),
            cond: Condvar::new(),
        }
    }

    pub fn cookie(&self) -> LoadingTaskCookie {
        *self.cookie.lock().unwrap()
    }

    pub fn notify(&self) {
        let mut cookie = self.cookie.lock().unwrap();
        cookie.update();
        self.cond.notify_all();
    }

    pub fn wait(&self, cookie: LoadingTaskCookie) -> LoadingTaskCookie {
        let cookie_guard = self.cookie.lock().unwrap();
        *self
            .cond
            .wait_while(cookie_guard, |current_cookie| *current_cookie == cookie)
            .unwrap()
    }
}

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct LoadingTaskCookie(u64);

impl LoadingTaskCookie {
    fn new() -> Self {
        Self(0)
    }

    fn update(&mut self) {
        let LoadingTaskCookie(cookie) = self;
        *cookie = cookie.wrapping_add(1);
    }
}

/// Global cache statistics for [ProgramCache].
#[derive(Debug, Default)]
pub struct ProgramCacheStats {
    /// a program was already in the cache
    pub hits: AtomicU64,
    /// a program was not found and loaded instead
    pub misses: AtomicU64,
    /// a compiled executable was unloaded
    pub evictions: HashMap<Pubkey, u64>,
    /// an unloaded program was loaded again (opposite of eviction)
    pub reloads: AtomicU64,
    /// a program was loaded or un/re/deployed
    pub insertions: AtomicU64,
    /// a program was loaded but can not be extracted on its own fork anymore
    pub lost_insertions: AtomicU64,
    /// a program which was already in the cache was reloaded by mistake
    pub replacements: AtomicU64,
    /// a program was only used once before being unloaded
    pub one_hit_wonders: AtomicU64,
    /// a program became unreachable in the fork graph because of rerooting
    pub prunes_orphan: AtomicU64,
    /// a program got pruned because it was not recompiled for the next epoch
    pub prunes_environment: AtomicU64,
    /// a program had no entries because all slot versions got pruned
    pub empty_entries: AtomicU64,
    /// water level of loaded entries currently cached
    pub water_level: AtomicU64,
}

impl ProgramCacheStats {
    pub fn reset(&mut self) {
        *self = ProgramCacheStats::default();
    }
    pub fn log(&self) {
        let hits = self.hits.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        let evictions: u64 = self.evictions.values().sum();
        let reloads = self.reloads.load(Ordering::Relaxed);
        let insertions = self.insertions.load(Ordering::Relaxed);
        let lost_insertions = self.lost_insertions.load(Ordering::Relaxed);
        let replacements = self.replacements.load(Ordering::Relaxed);
        let one_hit_wonders = self.one_hit_wonders.load(Ordering::Relaxed);
        let prunes_orphan = self.prunes_orphan.load(Ordering::Relaxed);
        let prunes_environment = self.prunes_environment.load(Ordering::Relaxed);
        let empty_entries = self.empty_entries.load(Ordering::Relaxed);
        let water_level = self.water_level.load(Ordering::Relaxed);
        debug!(
            "Loaded Programs Cache Stats -- Hits: {}, Misses: {}, Evictions: {}, Reloads: {}, Insertions: {}, Lost-Insertions: {}, Replacements: {}, One-Hit-Wonders: {}, Prunes-Orphan: {}, Prunes-Environment: {}, Empty: {}, Water-Level: {}",
            hits, misses, evictions, reloads, insertions, lost_insertions, replacements, one_hit_wonders, prunes_orphan, prunes_environment, empty_entries, water_level
        );
        if log_enabled!(log::Level::Trace) && !self.evictions.is_empty() {
            let mut evictions = self.evictions.iter().collect::<Vec<_>>();
            evictions.sort_by_key(|e| e.1);
            let evictions = evictions
                .into_iter()
                .rev()
                .map(|(program_id, evictions)| format!("  {:?}  {}", program_id, evictions))
                .collect::<Vec<_>>();
            let evictions = evictions.join("\n");
            trace!(
                "Eviction Details:\n  {:<44}  {}\n{}",
                "Program",
                "Count",
                evictions
            );
        }
    }
}
