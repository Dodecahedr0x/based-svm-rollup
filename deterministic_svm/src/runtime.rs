use core::slice;
use solana_sbpf::{
    declare_builtin_function,
    error::EbpfError,
    memory_region::{AccessType, MemoryMapping, MemoryRegion},
    program::{BuiltinFunction, BuiltinProgram, FunctionRegistry, SBPFVersion},
    vm::{Config, ContextObject},
};
use std::{
    alloc::Layout,
    slice::from_raw_parts_mut,
    str::{from_utf8, Utf8Error},
    sync::Arc,
};
use thiserror::Error as ThisError;

use crate::{
    blake3,
    features::{self, *},
    ic_logger_msg, is_nonoverlapping, keccak, stable_log, ComputeBudget, FeatureSet, Hash, Hasher,
    InstructionError, InvokeContext, Pubkey, PubkeyError, SerializedAccountMetadata, Sysvar,
    SysvarId, MAX_SEEDS, MAX_SEED_LEN, PUBKEY_BYTES, SUCCESS,
};

pub const BPF_ALIGN_OF_U128: usize = 8;

/// Maximum signers
pub const MAX_SIGNERS: usize = 16;

/// Error definitions
#[derive(Debug, ThisError, PartialEq, Eq)]
pub enum SyscallError {
    #[error("{0}: {1:?}")]
    InvalidString(Utf8Error, Vec<u8>),
    #[error("SBF program panicked")]
    Abort,
    #[error("SBF program Panicked in {0} at {1}:{2}")]
    Panic(String, u64, u64),
    #[error("Cannot borrow invoke context")]
    InvokeContextBorrowFailed,
    #[error("Malformed signer seed: {0}: {1:?}")]
    MalformedSignerSeed(Utf8Error, Vec<u8>),
    #[error("Could not create program address with signer seeds: {0}")]
    BadSeeds(PubkeyError),
    #[error("Program {0} not supported by inner instructions")]
    ProgramNotSupported(Pubkey),
    #[error("Unaligned pointer")]
    UnalignedPointer,
    #[error("Too many signers")]
    TooManySigners,
    #[error("Instruction passed to inner instruction is too large ({0} > {1})")]
    InstructionTooLarge(usize, usize),
    #[error("Too many accounts passed to inner instruction")]
    TooManyAccounts,
    #[error("Overlapping copy")]
    CopyOverlapping,
    #[error("Return data too large ({0} > {1})")]
    ReturnDataTooLarge(u64, u64),
    #[error("Hashing too many sequences")]
    TooManySlices,
    #[error("InvalidLength")]
    InvalidLength,
    #[error("Invoked an instruction with data that is too large ({data_len} > {max_data_len})")]
    MaxInstructionDataLenExceeded { data_len: u64, max_data_len: u64 },
    #[error("Invoked an instruction with too many accounts ({num_accounts} > {max_accounts})")]
    MaxInstructionAccountsExceeded {
        num_accounts: u64,
        max_accounts: u64,
    },
    #[error("Invoked an instruction with too many account info's ({num_account_infos} > {max_account_infos})")]
    MaxInstructionAccountInfosExceeded {
        num_account_infos: u64,
        max_account_infos: u64,
    },
    #[error("InvalidAttribute")]
    InvalidAttribute,
    #[error("Invalid pointer")]
    InvalidPointer,
    #[error("Arithmetic overflow")]
    ArithmeticOverflow,
}

type Error = Box<dyn std::error::Error>;

pub trait HasherImpl {
    const NAME: &'static str;
    type Output: AsRef<[u8]>;

    fn create_hasher() -> Self;
    fn hash(&mut self, val: &[u8]);
    fn result(self) -> Self::Output;
    fn get_base_cost(compute_budget: &ComputeBudget) -> u64;
    fn get_byte_cost(compute_budget: &ComputeBudget) -> u64;
    fn get_max_slices(compute_budget: &ComputeBudget) -> u64;
}

pub struct Sha256Hasher(Hasher);
pub struct Blake3Hasher(blake3::Hasher);
pub struct Keccak256Hasher(keccak::Hasher);

impl HasherImpl for Sha256Hasher {
    const NAME: &'static str = "Sha256";
    type Output = Hash;

    fn create_hasher() -> Self {
        Sha256Hasher(Hasher::default())
    }

    fn hash(&mut self, val: &[u8]) {
        self.0.hash(val);
    }

    fn result(self) -> Self::Output {
        self.0.result()
    }

    fn get_base_cost(compute_budget: &ComputeBudget) -> u64 {
        compute_budget.sha256_base_cost
    }
    fn get_byte_cost(compute_budget: &ComputeBudget) -> u64 {
        compute_budget.sha256_byte_cost
    }
    fn get_max_slices(compute_budget: &ComputeBudget) -> u64 {
        compute_budget.sha256_max_slices
    }
}

impl HasherImpl for Blake3Hasher {
    const NAME: &'static str = "Blake3";
    type Output = blake3::Hash;

    fn create_hasher() -> Self {
        Blake3Hasher(blake3::Hasher::default())
    }

    fn hash(&mut self, val: &[u8]) {
        self.0.hash(val);
    }

    fn result(self) -> Self::Output {
        self.0.result()
    }

    fn get_base_cost(compute_budget: &ComputeBudget) -> u64 {
        compute_budget.sha256_base_cost
    }
    fn get_byte_cost(compute_budget: &ComputeBudget) -> u64 {
        compute_budget.sha256_byte_cost
    }
    fn get_max_slices(compute_budget: &ComputeBudget) -> u64 {
        compute_budget.sha256_max_slices
    }
}

impl HasherImpl for Keccak256Hasher {
    const NAME: &'static str = "Keccak256";
    type Output = keccak::Hash;

    fn create_hasher() -> Self {
        Keccak256Hasher(keccak::Hasher::default())
    }

    fn hash(&mut self, val: &[u8]) {
        self.0.hash(val);
    }

    fn result(self) -> Self::Output {
        self.0.result()
    }

    fn get_base_cost(compute_budget: &ComputeBudget) -> u64 {
        compute_budget.sha256_base_cost
    }
    fn get_byte_cost(compute_budget: &ComputeBudget) -> u64 {
        compute_budget.sha256_byte_cost
    }
    fn get_max_slices(compute_budget: &ComputeBudget) -> u64 {
        compute_budget.sha256_max_slices
    }
}

fn consume_compute_meter(invoke_context: &InvokeContext, amount: u64) -> Result<(), Error> {
    invoke_context.consume_checked(amount)?;
    Ok(())
}

macro_rules! register_feature_gated_function {
    ($result:expr, $is_feature_active:expr, $name:expr, $call:expr $(,)?) => {
        if $is_feature_active {
            $result.register_function_hashed($name, $call)
        } else {
            Ok(0)
        }
    };
}

pub fn morph_into_deployment_environment_v1(
    from: Arc<BuiltinProgram<InvokeContext>>,
) -> Result<BuiltinProgram<InvokeContext>, Error> {
    let mut config = from.get_config().clone();
    config.reject_broken_elfs = true;

    let mut result = FunctionRegistry::<BuiltinFunction<InvokeContext>>::default();

    for (key, (name, value)) in from.get_function_registry(SBPFVersion::V0).iter() {
        // Deployment of programs with sol_alloc_free is disabled. So do not register the syscall.
        if name != *b"sol_alloc_free_" {
            result.register_function(key, name, value)?;
        }
    }

    Ok(BuiltinProgram::new_loader(config, result))
}

fn get_sysvar<T: std::fmt::Debug + Sysvar + SysvarId + Clone>(
    sysvar: Result<Arc<T>, InstructionError>,
    var_addr: u64,
    check_aligned: bool,
    memory_mapping: &mut MemoryMapping,
    invoke_context: &mut InvokeContext,
) -> Result<u64, Error> {
    consume_compute_meter(
        invoke_context,
        invoke_context
            .get_compute_budget()
            .sysvar_base_cost
            .saturating_add(size_of::<T>() as u64),
    )?;
    let var = translate_type_mut::<T>(memory_mapping, var_addr, check_aligned)?;

    // this clone looks unecessary now, but it exists to zero out trailing alignment bytes
    // it is unclear whether this should ever matter
    // but there are tests using MemoryMapping that expect to see this
    // we preserve the previous behavior out of an abundance of caution
    let sysvar: Arc<T> = sysvar?;
    *var = T::clone(sysvar.as_ref());

    Ok(SUCCESS)
}

fn mem_op_consume(invoke_context: &mut InvokeContext, n: u64) -> Result<(), Error> {
    let compute_budget = invoke_context.get_compute_budget();
    let cost = compute_budget.mem_op_base_cost.max(
        n.checked_div(compute_budget.cpi_bytes_per_unit)
            .unwrap_or(u64::MAX),
    );
    consume_compute_meter(invoke_context, cost)
}

fn memmove(
    invoke_context: &mut InvokeContext,
    dst_addr: u64,
    src_addr: u64,
    n: u64,
    memory_mapping: &MemoryMapping,
) -> Result<u64, Error> {
    if invoke_context
        .get_feature_set()
        .is_active(&features::bpf_account_data_direct_mapping::id())
    {
        let syscall_context = invoke_context.get_syscall_context()?;

        memmove_non_contiguous(
            dst_addr,
            src_addr,
            n,
            &syscall_context.accounts_metadata,
            memory_mapping,
        )
    } else {
        let dst_ptr = translate_slice_mut::<u8>(
            memory_mapping,
            dst_addr,
            n,
            invoke_context.get_check_aligned(),
        )?
        .as_mut_ptr();
        let src_ptr = translate_slice::<u8>(
            memory_mapping,
            src_addr,
            n,
            invoke_context.get_check_aligned(),
        )?
        .as_ptr();

        unsafe { std::ptr::copy(src_ptr, dst_ptr, n as usize) };
        Ok(0)
    }
}

fn memmove_non_contiguous(
    dst_addr: u64,
    src_addr: u64,
    n: u64,
    accounts: &[SerializedAccountMetadata],
    memory_mapping: &MemoryMapping,
) -> Result<u64, Error> {
    let reverse = dst_addr.wrapping_sub(src_addr) < n;
    iter_memory_pair_chunks(
        AccessType::Load,
        src_addr,
        AccessType::Store,
        dst_addr,
        n,
        accounts,
        memory_mapping,
        reverse,
        |src_host_addr, dst_host_addr, chunk_len| {
            unsafe { std::ptr::copy(src_host_addr, dst_host_addr as *mut u8, chunk_len) };
            Ok(0)
        },
    )
}

// Marked unsafe since it assumes that the slices are at least `n` bytes long.
unsafe fn memcmp(s1: &[u8], s2: &[u8], n: usize) -> i32 {
    for i in 0..n {
        let a = *s1.get_unchecked(i);
        let b = *s2.get_unchecked(i);
        if a != b {
            return (a as i32).saturating_sub(b as i32);
        };
    }

    0
}

fn memcmp_non_contiguous(
    src_addr: u64,
    dst_addr: u64,
    n: u64,
    accounts: &[SerializedAccountMetadata],
    memory_mapping: &MemoryMapping,
) -> Result<i32, Error> {
    let memcmp_chunk = |s1_addr, s2_addr, chunk_len| {
        let res = unsafe {
            let s1 = slice::from_raw_parts(s1_addr, chunk_len);
            let s2 = slice::from_raw_parts(s2_addr, chunk_len);
            // Safety:
            // memcmp is marked unsafe since it assumes that s1 and s2 are exactly chunk_len
            // long. The whole point of iter_memory_pair_chunks is to find same length chunks
            // across two memory regions.
            memcmp(s1, s2, chunk_len)
        };
        if res != 0 {
            return Err(MemcmpError::Diff(res).into());
        }
        Ok(0)
    };
    match iter_memory_pair_chunks(
        AccessType::Load,
        src_addr,
        AccessType::Load,
        dst_addr,
        n,
        accounts,
        memory_mapping,
        false,
        memcmp_chunk,
    ) {
        Ok(res) => Ok(res),
        Err(error) => match error.downcast_ref() {
            Some(MemcmpError::Diff(diff)) => Ok(*diff),
            _ => Err(error),
        },
    }
}

#[derive(Debug)]
enum MemcmpError {
    Diff(i32),
}

impl std::fmt::Display for MemcmpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MemcmpError::Diff(diff) => write!(f, "memcmp diff: {diff}"),
        }
    }
}

impl std::error::Error for MemcmpError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            MemcmpError::Diff(_) => None,
        }
    }
}

fn memset_non_contiguous(
    dst_addr: u64,
    c: u8,
    n: u64,
    accounts: &[SerializedAccountMetadata],
    memory_mapping: &MemoryMapping,
) -> Result<u64, Error> {
    let dst_chunk_iter =
        MemoryChunkIterator::new(memory_mapping, accounts, AccessType::Store, dst_addr, n)?;
    for item in dst_chunk_iter {
        let (dst_region, dst_vm_addr, dst_len) = item?;
        let dst_host_addr = Result::from(dst_region.vm_to_host(dst_vm_addr, dst_len as u64))?;
        unsafe { slice::from_raw_parts_mut(dst_host_addr as *mut u8, dst_len).fill(c) }
    }

    Ok(0)
}

fn iter_memory_pair_chunks<T, F>(
    src_access: AccessType,
    src_addr: u64,
    dst_access: AccessType,
    dst_addr: u64,
    n_bytes: u64,
    accounts: &[SerializedAccountMetadata],
    memory_mapping: &MemoryMapping,
    reverse: bool,
    mut fun: F,
) -> Result<T, Error>
where
    T: Default,
    F: FnMut(*const u8, *const u8, usize) -> Result<T, Error>,
{
    let mut src_chunk_iter =
        MemoryChunkIterator::new(memory_mapping, accounts, src_access, src_addr, n_bytes)
            .map_err(EbpfError::from)?;
    let mut dst_chunk_iter =
        MemoryChunkIterator::new(memory_mapping, accounts, dst_access, dst_addr, n_bytes)
            .map_err(EbpfError::from)?;

    let mut src_chunk = None;
    let mut dst_chunk = None;

    macro_rules! memory_chunk {
        ($chunk_iter:ident, $chunk:ident) => {
            if let Some($chunk) = &mut $chunk {
                // Keep processing the current chunk
                $chunk
            } else {
                // This is either the first call or we've processed all the bytes in the current
                // chunk. Move to the next one.
                let chunk = match if reverse {
                    $chunk_iter.next_back()
                } else {
                    $chunk_iter.next()
                } {
                    Some(item) => item?,
                    None => break,
                };
                $chunk.insert(chunk)
            }
        };
    }

    loop {
        let (src_region, src_chunk_addr, src_remaining) = memory_chunk!(src_chunk_iter, src_chunk);
        let (dst_region, dst_chunk_addr, dst_remaining) = memory_chunk!(dst_chunk_iter, dst_chunk);

        // We always process same-length pairs
        let chunk_len = *src_remaining.min(dst_remaining);

        let (src_host_addr, dst_host_addr) = {
            let (src_addr, dst_addr) = if reverse {
                // When scanning backwards not only we want to scan regions from the end,
                // we want to process the memory within regions backwards as well.
                (
                    src_chunk_addr
                        .saturating_add(*src_remaining as u64)
                        .saturating_sub(chunk_len as u64),
                    dst_chunk_addr
                        .saturating_add(*dst_remaining as u64)
                        .saturating_sub(chunk_len as u64),
                )
            } else {
                (*src_chunk_addr, *dst_chunk_addr)
            };

            (
                Result::from(src_region.vm_to_host(src_addr, chunk_len as u64))?,
                Result::from(dst_region.vm_to_host(dst_addr, chunk_len as u64))?,
            )
        };

        fun(
            src_host_addr as *const u8,
            dst_host_addr as *const u8,
            chunk_len,
        )?;

        // Update how many bytes we have left to scan in each chunk
        *src_remaining = src_remaining.saturating_sub(chunk_len);
        *dst_remaining = dst_remaining.saturating_sub(chunk_len);

        if !reverse {
            // We've scanned `chunk_len` bytes so we move the vm address forward. In reverse
            // mode we don't do this since we make progress by decreasing src_len and
            // dst_len.
            *src_chunk_addr = src_chunk_addr.saturating_add(chunk_len as u64);
            *dst_chunk_addr = dst_chunk_addr.saturating_add(chunk_len as u64);
        }

        if *src_remaining == 0 {
            src_chunk = None;
        }

        if *dst_remaining == 0 {
            dst_chunk = None;
        }
    }

    Ok(T::default())
}

struct MemoryChunkIterator<'a> {
    memory_mapping: &'a MemoryMapping<'a>,
    accounts: &'a [SerializedAccountMetadata],
    access_type: AccessType,
    initial_vm_addr: u64,
    vm_addr_start: u64,
    // exclusive end index (start + len, so one past the last valid address)
    vm_addr_end: u64,
    len: u64,
    account_index: usize,
    is_account: Option<bool>,
}

impl<'a> MemoryChunkIterator<'a> {
    fn new(
        memory_mapping: &'a MemoryMapping,
        accounts: &'a [SerializedAccountMetadata],
        access_type: AccessType,
        vm_addr: u64,
        len: u64,
    ) -> Result<MemoryChunkIterator<'a>, EbpfError> {
        let vm_addr_end = vm_addr.checked_add(len).ok_or(EbpfError::AccessViolation(
            access_type,
            vm_addr,
            len,
            "unknown",
        ))?;

        Ok(MemoryChunkIterator {
            memory_mapping,
            accounts,
            access_type,
            initial_vm_addr: vm_addr,
            len,
            vm_addr_start: vm_addr,
            vm_addr_end,
            account_index: 0,
            is_account: None,
        })
    }

    fn region(&mut self, vm_addr: u64) -> Result<&'a MemoryRegion, Error> {
        match self.memory_mapping.region(self.access_type, vm_addr) {
            Ok(region) => Ok(region),
            Err(error) => match error {
                EbpfError::AccessViolation(access_type, _vm_addr, _len, name) => Err(Box::new(
                    EbpfError::AccessViolation(access_type, self.initial_vm_addr, self.len, name),
                )),
                EbpfError::StackAccessViolation(access_type, _vm_addr, _len, frame) => {
                    Err(Box::new(EbpfError::StackAccessViolation(
                        access_type,
                        self.initial_vm_addr,
                        self.len,
                        frame,
                    )))
                }
                _ => Err(error.into()),
            },
        }
    }
}

impl<'a> Iterator for MemoryChunkIterator<'a> {
    type Item = Result<(&'a MemoryRegion, u64, usize), Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.vm_addr_start == self.vm_addr_end {
            return None;
        }

        let region = match self.region(self.vm_addr_start) {
            Ok(region) => region,
            Err(e) => {
                self.vm_addr_start = self.vm_addr_end;
                return Some(Err(e));
            }
        };

        let region_is_account;

        loop {
            if let Some(account) = self.accounts.get(self.account_index) {
                let account_addr = account.vm_data_addr;
                let resize_addr = account_addr.saturating_add(account.original_data_len as u64);

                if resize_addr < region.vm_addr {
                    // region is after this account, move on next one
                    self.account_index = self.account_index.saturating_add(1);
                } else {
                    region_is_account =
                        region.vm_addr == account_addr || region.vm_addr == resize_addr;
                    break;
                }
            } else {
                // address is after all the accounts
                region_is_account = false;
                break;
            }
        }

        if let Some(is_account) = self.is_account {
            if is_account != region_is_account {
                return Some(Err(SyscallError::InvalidLength.into()));
            }
        } else {
            self.is_account = Some(region_is_account);
        }

        let vm_addr = self.vm_addr_start;

        let chunk_len = if region.vm_addr_end <= self.vm_addr_end {
            // consume the whole region
            let len = region.vm_addr_end.saturating_sub(self.vm_addr_start);
            self.vm_addr_start = region.vm_addr_end;
            len
        } else {
            // consume part of the region
            let len = self.vm_addr_end.saturating_sub(self.vm_addr_start);
            self.vm_addr_start = self.vm_addr_end;
            len
        };

        Some(Ok((region, vm_addr, chunk_len as usize)))
    }
}

impl<'a> DoubleEndedIterator for MemoryChunkIterator<'a> {
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.vm_addr_start == self.vm_addr_end {
            return None;
        }

        let region = match self.region(self.vm_addr_end.saturating_sub(1)) {
            Ok(region) => region,
            Err(e) => {
                self.vm_addr_start = self.vm_addr_end;
                return Some(Err(e));
            }
        };

        let chunk_len = if region.vm_addr >= self.vm_addr_start {
            // consume the whole region
            let len = self.vm_addr_end.saturating_sub(region.vm_addr);
            self.vm_addr_end = region.vm_addr;
            len
        } else {
            // consume part of the region
            let len = self.vm_addr_end.saturating_sub(self.vm_addr_start);
            self.vm_addr_end = self.vm_addr_start;
            len
        };

        Some(Ok((region, self.vm_addr_end, chunk_len as usize)))
    }
}

fn translate_and_check_program_address_inputs<'a>(
    seeds_addr: u64,
    seeds_len: u64,
    program_id_addr: u64,
    memory_mapping: &mut MemoryMapping,
    check_aligned: bool,
) -> Result<(Vec<&'a [u8]>, &'a Pubkey), Error> {
    let untranslated_seeds =
        translate_slice::<&[u8]>(memory_mapping, seeds_addr, seeds_len, check_aligned)?;
    if untranslated_seeds.len() > MAX_SEEDS {
        return Err(SyscallError::BadSeeds(PubkeyError::MaxSeedLengthExceeded).into());
    }
    let seeds = untranslated_seeds
        .iter()
        .map(|untranslated_seed| {
            if untranslated_seed.len() > MAX_SEED_LEN {
                return Err(SyscallError::BadSeeds(PubkeyError::MaxSeedLengthExceeded).into());
            }
            translate_slice::<u8>(
                memory_mapping,
                untranslated_seed.as_ptr() as *const _ as u64,
                untranslated_seed.len() as u64,
                check_aligned,
            )
        })
        .collect::<Result<Vec<_>, Error>>()?;
    let program_id = translate_type::<Pubkey>(memory_mapping, program_id_addr, check_aligned)?;
    Ok((seeds, program_id))
}

pub fn create_program_runtime_environment_v1<'a>(
    feature_set: &FeatureSet,
    compute_budget: &ComputeBudget,
    reject_deployment_of_broken_elfs: bool,
    debugging_features: bool,
) -> Result<BuiltinProgram<InvokeContext<'a>>, Error> {
    let enable_alt_bn128_syscall = feature_set.is_active(&enable_alt_bn128_syscall::id());
    let enable_alt_bn128_compression_syscall =
        feature_set.is_active(&enable_alt_bn128_compression_syscall::id());
    let enable_big_mod_exp_syscall = feature_set.is_active(&enable_big_mod_exp_syscall::id());
    let blake3_syscall_enabled = feature_set.is_active(&blake3_syscall_enabled::id());
    let curve25519_syscall_enabled = feature_set.is_active(&curve25519_syscall_enabled::id());
    let disable_fees_sysvar = feature_set.is_active(&disable_fees_sysvar::id());
    let epoch_rewards_syscall_enabled = feature_set
        .is_active(&enable_partitioned_epoch_reward::id())
        || feature_set.is_active(&partitioned_epoch_rewards_superfeature::id());
    let disable_deploy_of_alloc_free_syscall = reject_deployment_of_broken_elfs
        && feature_set.is_active(&disable_deploy_of_alloc_free_syscall::id());
    let last_restart_slot_syscall_enabled = feature_set.is_active(&last_restart_slot_sysvar::id());
    let enable_poseidon_syscall = feature_set.is_active(&enable_poseidon_syscall::id());
    let remaining_compute_units_syscall_enabled =
        feature_set.is_active(&remaining_compute_units_syscall_enabled::id());
    let get_sysvar_syscall_enabled = feature_set.is_active(&get_sysvar_syscall_enabled::id());
    let enable_get_epoch_stake_syscall =
        feature_set.is_active(&enable_get_epoch_stake_syscall::id());

    let config = Config {
        max_call_depth: compute_budget.max_call_depth,
        stack_frame_size: compute_budget.stack_frame_size,
        enable_address_translation: true,
        enable_stack_frame_gaps: !feature_set.is_active(&bpf_account_data_direct_mapping::id()),
        instruction_meter_checkpoint_distance: 10000,
        enable_instruction_meter: true,
        enable_instruction_tracing: debugging_features,
        enable_symbol_and_section_labels: debugging_features,
        reject_broken_elfs: reject_deployment_of_broken_elfs,
        noop_instruction_rate: 256,
        sanitize_user_provided_values: true,
        enabled_sbpf_versions: SBPFVersion::V0..=SBPFVersion::V0,
        optimize_rodata: false,
        aligned_memory_mapping: !feature_set.is_active(&bpf_account_data_direct_mapping::id()),
        // Warning, do not use `Config::default()` so that configuration here is explicit.
    };
    let mut result = FunctionRegistry::<BuiltinFunction<InvokeContext>>::default();

    // Abort
    result.register_function_hashed(*b"abort", SyscallAbort::vm)?;

    // Panic
    result.register_function_hashed(*b"sol_panic_", SyscallPanic::vm)?;

    // Logging
    result.register_function_hashed(*b"sol_log_", SyscallLog::vm)?;
    result.register_function_hashed(*b"sol_log_64_", SyscallLogU64::vm)?;
    result.register_function_hashed(*b"sol_log_compute_units_", SyscallLogBpfComputeUnits::vm)?;
    result.register_function_hashed(*b"sol_log_pubkey", SyscallLogPubkey::vm)?;

    // Program defined addresses (PDA)
    result.register_function_hashed(
        *b"sol_create_program_address",
        SyscallCreateProgramAddress::vm,
    )?;
    result.register_function_hashed(
        *b"sol_try_find_program_address",
        SyscallTryFindProgramAddress::vm,
    )?;

    // Sha256
    result.register_function_hashed(*b"sol_sha256", SyscallHash::vm::<Sha256Hasher>)?;

    // Keccak256
    result.register_function_hashed(*b"sol_keccak256", SyscallHash::vm::<Keccak256Hasher>)?;

    // Secp256k1 Recover
    result.register_function_hashed(*b"sol_secp256k1_recover", SyscallSecp256k1Recover::vm)?;

    // Blake3
    register_feature_gated_function!(
        result,
        blake3_syscall_enabled,
        *b"sol_blake3",
        SyscallHash::vm::<Blake3Hasher>,
    )?;

    // Elliptic Curve Operations
    register_feature_gated_function!(
        result,
        curve25519_syscall_enabled,
        *b"sol_curve_validate_point",
        SyscallCurvePointValidation::vm,
    )?;
    register_feature_gated_function!(
        result,
        curve25519_syscall_enabled,
        *b"sol_curve_group_op",
        SyscallCurveGroupOps::vm,
    )?;
    register_feature_gated_function!(
        result,
        curve25519_syscall_enabled,
        *b"sol_curve_multiscalar_mul",
        SyscallCurveMultiscalarMultiplication::vm,
    )?;

    // Sysvars
    result.register_function_hashed(*b"sol_get_clock_sysvar", SyscallGetClockSysvar::vm)?;
    result.register_function_hashed(
        *b"sol_get_epoch_schedule_sysvar",
        SyscallGetEpochScheduleSysvar::vm,
    )?;
    register_feature_gated_function!(
        result,
        !disable_fees_sysvar,
        *b"sol_get_fees_sysvar",
        SyscallGetFeesSysvar::vm,
    )?;
    result.register_function_hashed(*b"sol_get_rent_sysvar", SyscallGetRentSysvar::vm)?;

    register_feature_gated_function!(
        result,
        last_restart_slot_syscall_enabled,
        *b"sol_get_last_restart_slot",
        SyscallGetLastRestartSlotSysvar::vm,
    )?;

    register_feature_gated_function!(
        result,
        epoch_rewards_syscall_enabled,
        *b"sol_get_epoch_rewards_sysvar",
        SyscallGetEpochRewardsSysvar::vm,
    )?;

    // Memory ops
    result.register_function_hashed(*b"sol_memcpy_", SyscallMemcpy::vm)?;
    result.register_function_hashed(*b"sol_memmove_", SyscallMemmove::vm)?;
    result.register_function_hashed(*b"sol_memcmp_", SyscallMemcmp::vm)?;
    result.register_function_hashed(*b"sol_memset_", SyscallMemset::vm)?;

    // Processed sibling instructions
    result.register_function_hashed(
        *b"sol_get_processed_sibling_instruction",
        SyscallGetProcessedSiblingInstruction::vm,
    )?;

    // Stack height
    result.register_function_hashed(*b"sol_get_stack_height", SyscallGetStackHeight::vm)?;

    // Return data
    result.register_function_hashed(*b"sol_set_return_data", SyscallSetReturnData::vm)?;
    result.register_function_hashed(*b"sol_get_return_data", SyscallGetReturnData::vm)?;

    // Cross-program invocation
    result.register_function_hashed(*b"sol_invoke_signed_c", SyscallInvokeSignedC::vm)?;
    result.register_function_hashed(*b"sol_invoke_signed_rust", SyscallInvokeSignedRust::vm)?;

    // Memory allocator
    register_feature_gated_function!(
        result,
        !disable_deploy_of_alloc_free_syscall,
        *b"sol_alloc_free_",
        SyscallAllocFree::vm,
    )?;

    // Alt_bn128
    register_feature_gated_function!(
        result,
        enable_alt_bn128_syscall,
        *b"sol_alt_bn128_group_op",
        SyscallAltBn128::vm,
    )?;

    // Big_mod_exp
    register_feature_gated_function!(
        result,
        enable_big_mod_exp_syscall,
        *b"sol_big_mod_exp",
        SyscallBigModExp::vm,
    )?;

    // Poseidon
    register_feature_gated_function!(
        result,
        enable_poseidon_syscall,
        *b"sol_poseidon",
        SyscallPoseidon::vm,
    )?;

    // Accessing remaining compute units
    register_feature_gated_function!(
        result,
        remaining_compute_units_syscall_enabled,
        *b"sol_remaining_compute_units",
        SyscallRemainingComputeUnits::vm
    )?;

    // Alt_bn128_compression
    register_feature_gated_function!(
        result,
        enable_alt_bn128_compression_syscall,
        *b"sol_alt_bn128_compression",
        SyscallAltBn128Compression::vm,
    )?;

    // Sysvar getter
    register_feature_gated_function!(
        result,
        get_sysvar_syscall_enabled,
        *b"sol_get_sysvar",
        SyscallGetSysvar::vm,
    )?;

    // Get Epoch Stake
    register_feature_gated_function!(
        result,
        enable_get_epoch_stake_syscall,
        *b"sol_get_epoch_stake",
        SyscallGetEpochStake::vm,
    )?;

    // Log data
    result.register_function_hashed(*b"sol_log_data", SyscallLogData::vm)?;

    Ok(BuiltinProgram::new_loader(config, result))
}

fn address_is_aligned<T>(address: u64) -> bool {
    (address as *mut T as usize)
        .checked_rem(align_of::<T>())
        .map(|rem| rem == 0)
        .expect("T to be non-zero aligned")
}

fn translate(
    memory_mapping: &MemoryMapping,
    access_type: AccessType,
    vm_addr: u64,
    len: u64,
) -> Result<u64, Error> {
    memory_mapping
        .map(access_type, vm_addr, len)
        .map_err(|err| err.into())
        .into()
}

fn translate_type_inner<'a, T>(
    memory_mapping: &MemoryMapping,
    access_type: AccessType,
    vm_addr: u64,
    check_aligned: bool,
) -> Result<&'a mut T, Error> {
    let host_addr = translate(memory_mapping, access_type, vm_addr, size_of::<T>() as u64)?;
    if !check_aligned {
        Ok(unsafe { std::mem::transmute::<u64, &mut T>(host_addr) })
    } else if !address_is_aligned::<T>(host_addr) {
        Err(SyscallError::UnalignedPointer.into())
    } else {
        Ok(unsafe { &mut *(host_addr as *mut T) })
    }
}
fn translate_type_mut<'a, T>(
    memory_mapping: &MemoryMapping,
    vm_addr: u64,
    check_aligned: bool,
) -> Result<&'a mut T, Error> {
    translate_type_inner::<T>(memory_mapping, AccessType::Store, vm_addr, check_aligned)
}
fn translate_type<'a, T>(
    memory_mapping: &MemoryMapping,
    vm_addr: u64,
    check_aligned: bool,
) -> Result<&'a T, Error> {
    translate_type_inner::<T>(memory_mapping, AccessType::Load, vm_addr, check_aligned)
        .map(|value| &*value)
}

fn translate_slice_inner<'a, T>(
    memory_mapping: &MemoryMapping,
    access_type: AccessType,
    vm_addr: u64,
    len: u64,
    check_aligned: bool,
) -> Result<&'a mut [T], Error> {
    if len == 0 {
        return Ok(&mut []);
    }

    let total_size = len.saturating_mul(size_of::<T>() as u64);
    if isize::try_from(total_size).is_err() {
        return Err(SyscallError::InvalidLength.into());
    }

    let host_addr = translate(memory_mapping, access_type, vm_addr, total_size)?;

    if check_aligned && !address_is_aligned::<T>(host_addr) {
        return Err(SyscallError::UnalignedPointer.into());
    }
    Ok(unsafe { from_raw_parts_mut(host_addr as *mut T, len as usize) })
}
fn translate_slice_mut<'a, T>(
    memory_mapping: &MemoryMapping,
    vm_addr: u64,
    len: u64,
    check_aligned: bool,
) -> Result<&'a mut [T], Error> {
    translate_slice_inner::<T>(
        memory_mapping,
        AccessType::Store,
        vm_addr,
        len,
        check_aligned,
    )
}
fn translate_slice<'a, T>(
    memory_mapping: &MemoryMapping,
    vm_addr: u64,
    len: u64,
    check_aligned: bool,
) -> Result<&'a [T], Error> {
    translate_slice_inner::<T>(
        memory_mapping,
        AccessType::Load,
        vm_addr,
        len,
        check_aligned,
    )
    .map(|value| &*value)
}

/// Take a virtual pointer to a string (points to SBF VM memory space), translate it
/// pass it to a user-defined work function
fn translate_string_and_do(
    memory_mapping: &MemoryMapping,
    addr: u64,
    len: u64,
    check_aligned: bool,
    work: &mut dyn FnMut(&str) -> Result<u64, Error>,
) -> Result<u64, Error> {
    let buf = translate_slice::<u8>(memory_mapping, addr, len, check_aligned)?;
    match from_utf8(buf) {
        Ok(message) => work(message),
        Err(err) => Err(SyscallError::InvalidString(err, buf.to_vec()).into()),
    }
}

declare_builtin_function!(
    /// Abort syscall functions, called when the SBF program calls `abort()`
    /// LLVM will insert calls to `abort()` if it detects an untenable situation,
    /// `abort()` is not intended to be called explicitly by the program.
    /// Causes the SBF program to be halted immediately
    SyscallAbort,
    fn rust(
        _invoke_context: &mut InvokeContext,
        _arg1: u64,
        _arg2: u64,
        _arg3: u64,
        _arg4: u64,
        _arg5: u64,
        _memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        Err(SyscallError::Abort.into())
    }
);

declare_builtin_function!(
    /// Panic syscall function, called when the SBF program calls 'sol_panic_()`
    /// Causes the SBF program to be halted immediately
    SyscallPanic,
    fn rust(
        invoke_context: &mut InvokeContext,
        file: u64,
        len: u64,
        line: u64,
        column: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        consume_compute_meter(invoke_context, len)?;

        translate_string_and_do(
            memory_mapping,
            file,
            len,
            invoke_context.get_check_aligned(),
            &mut |string: &str| Err(SyscallError::Panic(string.to_string(), line, column).into()),
        )
    }
);

declare_builtin_function!(
    /// Dynamic memory allocation syscall called when the SBF program calls
    /// `sol_alloc_free_()`.  The allocator is expected to allocate/free
    /// from/to a given chunk of memory and enforce size restrictions.  The
    /// memory chunk is given to the allocator during allocator creation and
    /// information about that memory (start address and size) is passed
    /// to the VM to use for enforcement.
    SyscallAllocFree,
    fn rust(
        invoke_context: &mut InvokeContext,
        size: u64,
        free_addr: u64,
        _arg3: u64,
        _arg4: u64,
        _arg5: u64,
        _memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        let align = if invoke_context.get_check_aligned() {
            BPF_ALIGN_OF_U128
        } else {
            align_of::<u8>()
        };
        let Ok(layout) = Layout::from_size_align(size as usize, align) else {
            return Ok(0);
        };
        let allocator = &mut invoke_context.get_syscall_context_mut()?.allocator;
        if free_addr == 0 {
            match allocator.alloc(layout) {
                Ok(addr) => Ok(addr),
                Err(_) => Ok(0),
            }
        } else {
            // Unimplemented
            Ok(0)
        }
    }
);

declare_builtin_function!(
    /// Log a user's info message
    SyscallLog,
    fn rust(
        invoke_context: &mut InvokeContext,
        addr: u64,
        len: u64,
        _arg3: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        let cost = invoke_context
            .get_compute_budget()
            .syscall_base_cost
            .max(len);
        consume_compute_meter(invoke_context, cost)?;

        translate_string_and_do(
            memory_mapping,
            addr,
            len,
            invoke_context.get_check_aligned(),
            &mut |string: &str| {
                stable_log::program_log(&invoke_context.get_log_collector(), string);
                Ok(0)
            },
        )?;
        Ok(0)
    }
);

declare_builtin_function!(
    /// Log 5 64-bit values
    SyscallLogU64,
    fn rust(
        invoke_context: &mut InvokeContext,
        arg1: u64,
        arg2: u64,
        arg3: u64,
        arg4: u64,
        arg5: u64,
        _memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        let cost = invoke_context.get_compute_budget().log_64_units;
        consume_compute_meter(invoke_context, cost)?;

        stable_log::program_log(
            &invoke_context.get_log_collector(),
            &format!("{arg1:#x}, {arg2:#x}, {arg3:#x}, {arg4:#x}, {arg5:#x}"),
        );
        Ok(0)
    }
);

declare_builtin_function!(
    /// Log current compute consumption
    SyscallLogBpfComputeUnits,
    fn rust(
        invoke_context: &mut InvokeContext,
        _arg1: u64,
        _arg2: u64,
        _arg3: u64,
        _arg4: u64,
        _arg5: u64,
        _memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        let cost = invoke_context.get_compute_budget().syscall_base_cost;
        consume_compute_meter(invoke_context, cost)?;

        ic_logger_msg!(
            invoke_context.get_log_collector(),
            "Program consumption: {} units remaining",
            invoke_context.get_remaining(),
        );
        Ok(0)
    }
);

declare_builtin_function!(
    /// Log a [`Pubkey`] as a base58 string
    SyscallLogPubkey,
    fn rust(
        invoke_context: &mut InvokeContext,
        pubkey_addr: u64,
        _arg2: u64,
        _arg3: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        let cost = invoke_context.get_compute_budget().log_pubkey_units;
        consume_compute_meter(invoke_context, cost)?;

        let pubkey = translate_type::<Pubkey>(
            memory_mapping,
            pubkey_addr,
            invoke_context.get_check_aligned(),
        )?;
        stable_log::program_log(&invoke_context.get_log_collector(), &pubkey.to_string());
        Ok(0)
    }
);

declare_builtin_function!(
    /// Log data handling
    SyscallLogData,
    fn rust(
        invoke_context: &mut InvokeContext,
        addr: u64,
        len: u64,
        _arg3: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        let budget = invoke_context.get_compute_budget();

        consume_compute_meter(invoke_context, budget.syscall_base_cost)?;

        let untranslated_fields = translate_slice::<&[u8]>(
            memory_mapping,
            addr,
            len,
            invoke_context.get_check_aligned(),
        )?;

        consume_compute_meter(
            invoke_context,
            budget
                .syscall_base_cost
                .saturating_mul(untranslated_fields.len() as u64),
        )?;
        consume_compute_meter(
            invoke_context,
            untranslated_fields
                .iter()
                .fold(0, |total, e| total.saturating_add(e.len() as u64)),
        )?;

        let mut fields = Vec::with_capacity(untranslated_fields.len());

        for untranslated_field in untranslated_fields {
            fields.push(translate_slice::<u8>(
                memory_mapping,
                untranslated_field.as_ptr() as *const _ as u64,
                untranslated_field.len() as u64,
                invoke_context.get_check_aligned(),
            )?);
        }

        let log_collector = invoke_context.get_log_collector();

        stable_log::program_data(&log_collector, &fields);

        Ok(0)
    }
);

declare_builtin_function!(
    /// Create a program address
    SyscallCreateProgramAddress,
    fn rust(
        invoke_context: &mut InvokeContext,
        seeds_addr: u64,
        seeds_len: u64,
        program_id_addr: u64,
        address_addr: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        let cost = invoke_context
            .get_compute_budget()
            .create_program_address_units;
        consume_compute_meter(invoke_context, cost)?;

        let (seeds, program_id) = translate_and_check_program_address_inputs(
            seeds_addr,
            seeds_len,
            program_id_addr,
            memory_mapping,
            invoke_context.get_check_aligned(),
        )?;

        let Ok(new_address) = Pubkey::create_program_address(&seeds, program_id) else {
            return Ok(1);
        };
        let address = translate_slice_mut::<u8>(
            memory_mapping,
            address_addr,
            32,
            invoke_context.get_check_aligned(),
        )?;
        address.copy_from_slice(new_address.as_ref());
        Ok(0)
    }
);

declare_builtin_function!(
    /// Create a program address
    SyscallTryFindProgramAddress,
    fn rust(
        invoke_context: &mut InvokeContext,
        seeds_addr: u64,
        seeds_len: u64,
        program_id_addr: u64,
        address_addr: u64,
        bump_seed_addr: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        let cost = invoke_context
            .get_compute_budget()
            .create_program_address_units;
        consume_compute_meter(invoke_context, cost)?;

        let (seeds, program_id) = translate_and_check_program_address_inputs(
            seeds_addr,
            seeds_len,
            program_id_addr,
            memory_mapping,
            invoke_context.get_check_aligned(),
        )?;

        let mut bump_seed = [u8::MAX];
        for _ in 0..u8::MAX {
            {
                let mut seeds_with_bump = seeds.to_vec();
                seeds_with_bump.push(&bump_seed);

                if let Ok(new_address) =
                    Pubkey::create_program_address(&seeds_with_bump, program_id)
                {
                    let bump_seed_ref = translate_type_mut::<u8>(
                        memory_mapping,
                        bump_seed_addr,
                        invoke_context.get_check_aligned(),
                    )?;
                    let address = translate_slice_mut::<u8>(
                        memory_mapping,
                        address_addr,
                        std::mem::size_of::<Pubkey>() as u64,
                        invoke_context.get_check_aligned(),
                    )?;
                    if !is_nonoverlapping(
                        bump_seed_ref as *const _ as usize,
                        std::mem::size_of_val(bump_seed_ref),
                        address.as_ptr() as usize,
                        std::mem::size_of::<Pubkey>(),
                    ) {
                        return Err(SyscallError::CopyOverlapping.into());
                    }
                    *bump_seed_ref = bump_seed[0];
                    address.copy_from_slice(new_address.as_ref());
                    return Ok(0);
                }
            }
            bump_seed[0] = bump_seed[0].saturating_sub(1);
            consume_compute_meter(invoke_context, cost)?;
        }
        Ok(1)
    }
);

declare_builtin_function!(
    /// secp256k1_recover
    SyscallSecp256k1Recover,
    fn rust(
        invoke_context: &mut InvokeContext,
        hash_addr: u64,
        recovery_id_val: u64,
        signature_addr: u64,
        result_addr: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        let cost = invoke_context.get_compute_budget().secp256k1_recover_cost;
        consume_compute_meter(invoke_context, cost)?;

        let hash = translate_slice::<u8>(
            memory_mapping,
            hash_addr,
            keccak::HASH_BYTES as u64,
            invoke_context.get_check_aligned(),
        )?;
        let signature = translate_slice::<u8>(
            memory_mapping,
            signature_addr,
            SECP256K1_SIGNATURE_LENGTH as u64,
            invoke_context.get_check_aligned(),
        )?;
        let secp256k1_recover_result = translate_slice_mut::<u8>(
            memory_mapping,
            result_addr,
            SECP256K1_PUBLIC_KEY_LENGTH as u64,
            invoke_context.get_check_aligned(),
        )?;

        let Ok(message) = libsecp256k1::Message::parse_slice(hash) else {
            return Ok(Secp256k1RecoverError::InvalidHash.into());
        };
        let Ok(adjusted_recover_id_val) = recovery_id_val.try_into() else {
            return Ok(Secp256k1RecoverError::InvalidRecoveryId.into());
        };
        let Ok(recovery_id) = libsecp256k1::RecoveryId::parse(adjusted_recover_id_val) else {
            return Ok(Secp256k1RecoverError::InvalidRecoveryId.into());
        };
        let Ok(signature) = libsecp256k1::Signature::parse_standard_slice(signature) else {
            return Ok(Secp256k1RecoverError::InvalidSignature.into());
        };

        let public_key = match libsecp256k1::recover(&message, &signature, &recovery_id) {
            Ok(key) => key.serialize(),
            Err(_) => {
                return Ok(Secp256k1RecoverError::InvalidSignature.into());
            }
        };

        secp256k1_recover_result.copy_from_slice(&public_key[1..65]);
        Ok(SUCCESS)
    }
);

declare_builtin_function!(
    // Elliptic Curve Point Validation
    //
    // Currently, only curve25519 Edwards and Ristretto representations are supported
    SyscallCurvePointValidation,
    fn rust(
        invoke_context: &mut InvokeContext,
        curve_id: u64,
        point_addr: u64,
        _arg3: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        use solana_curve25519::{curve_syscall_traits::*, edwards, ristretto};
        match curve_id {
            CURVE25519_EDWARDS => {
                let cost = invoke_context
                    .get_compute_budget()
                    .curve25519_edwards_validate_point_cost;
                consume_compute_meter(invoke_context, cost)?;

                let point = translate_type::<edwards::PodEdwardsPoint>(
                    memory_mapping,
                    point_addr,
                    invoke_context.get_check_aligned(),
                )?;

                if edwards::validate_edwards(point) {
                    Ok(0)
                } else {
                    Ok(1)
                }
            }
            CURVE25519_RISTRETTO => {
                let cost = invoke_context
                    .get_compute_budget()
                    .curve25519_ristretto_validate_point_cost;
                consume_compute_meter(invoke_context, cost)?;

                let point = translate_type::<ristretto::PodRistrettoPoint>(
                    memory_mapping,
                    point_addr,
                    invoke_context.get_check_aligned(),
                )?;

                if ristretto::validate_ristretto(point) {
                    Ok(0)
                } else {
                    Ok(1)
                }
            }
            _ => {
                if invoke_context
                    .get_feature_set()
                    .is_active(&abort_on_invalid_curve::id())
                {
                    Err(SyscallError::InvalidAttribute.into())
                } else {
                    Ok(1)
                }
            }
        }
    }
);

declare_builtin_function!(
    // Elliptic Curve Group Operations
    //
    // Currently, only curve25519 Edwards and Ristretto representations are supported
    SyscallCurveGroupOps,
    fn rust(
        invoke_context: &mut InvokeContext,
        curve_id: u64,
        group_op: u64,
        left_input_addr: u64,
        right_input_addr: u64,
        result_point_addr: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        use solana_curve25519::{curve_syscall_traits::*, edwards, ristretto, scalar};
        match curve_id {
            CURVE25519_EDWARDS => match group_op {
                ADD => {
                    let cost = invoke_context
                        .get_compute_budget()
                        .curve25519_edwards_add_cost;
                    consume_compute_meter(invoke_context, cost)?;

                    let left_point = translate_type::<edwards::PodEdwardsPoint>(
                        memory_mapping,
                        left_input_addr,
                        invoke_context.get_check_aligned(),
                    )?;
                    let right_point = translate_type::<edwards::PodEdwardsPoint>(
                        memory_mapping,
                        right_input_addr,
                        invoke_context.get_check_aligned(),
                    )?;

                    if let Some(result_point) = edwards::add_edwards(left_point, right_point) {
                        *translate_type_mut::<edwards::PodEdwardsPoint>(
                            memory_mapping,
                            result_point_addr,
                            invoke_context.get_check_aligned(),
                        )? = result_point;
                        Ok(0)
                    } else {
                        Ok(1)
                    }
                }
                SUB => {
                    let cost = invoke_context
                        .get_compute_budget()
                        .curve25519_edwards_subtract_cost;
                    consume_compute_meter(invoke_context, cost)?;

                    let left_point = translate_type::<edwards::PodEdwardsPoint>(
                        memory_mapping,
                        left_input_addr,
                        invoke_context.get_check_aligned(),
                    )?;
                    let right_point = translate_type::<edwards::PodEdwardsPoint>(
                        memory_mapping,
                        right_input_addr,
                        invoke_context.get_check_aligned(),
                    )?;

                    if let Some(result_point) = edwards::subtract_edwards(left_point, right_point) {
                        *translate_type_mut::<edwards::PodEdwardsPoint>(
                            memory_mapping,
                            result_point_addr,
                            invoke_context.get_check_aligned(),
                        )? = result_point;
                        Ok(0)
                    } else {
                        Ok(1)
                    }
                }
                MUL => {
                    let cost = invoke_context
                        .get_compute_budget()
                        .curve25519_edwards_multiply_cost;
                    consume_compute_meter(invoke_context, cost)?;

                    let scalar = translate_type::<scalar::PodScalar>(
                        memory_mapping,
                        left_input_addr,
                        invoke_context.get_check_aligned(),
                    )?;
                    let input_point = translate_type::<edwards::PodEdwardsPoint>(
                        memory_mapping,
                        right_input_addr,
                        invoke_context.get_check_aligned(),
                    )?;

                    if let Some(result_point) = edwards::multiply_edwards(scalar, input_point) {
                        *translate_type_mut::<edwards::PodEdwardsPoint>(
                            memory_mapping,
                            result_point_addr,
                            invoke_context.get_check_aligned(),
                        )? = result_point;
                        Ok(0)
                    } else {
                        Ok(1)
                    }
                }
                _ => {
                    if invoke_context
                        .get_feature_set()
                        .is_active(&abort_on_invalid_curve::id())
                    {
                        Err(SyscallError::InvalidAttribute.into())
                    } else {
                        Ok(1)
                    }
                }
            },

            CURVE25519_RISTRETTO => match group_op {
                ADD => {
                    let cost = invoke_context
                        .get_compute_budget()
                        .curve25519_ristretto_add_cost;
                    consume_compute_meter(invoke_context, cost)?;

                    let left_point = translate_type::<ristretto::PodRistrettoPoint>(
                        memory_mapping,
                        left_input_addr,
                        invoke_context.get_check_aligned(),
                    )?;
                    let right_point = translate_type::<ristretto::PodRistrettoPoint>(
                        memory_mapping,
                        right_input_addr,
                        invoke_context.get_check_aligned(),
                    )?;

                    if let Some(result_point) = ristretto::add_ristretto(left_point, right_point) {
                        *translate_type_mut::<ristretto::PodRistrettoPoint>(
                            memory_mapping,
                            result_point_addr,
                            invoke_context.get_check_aligned(),
                        )? = result_point;
                        Ok(0)
                    } else {
                        Ok(1)
                    }
                }
                SUB => {
                    let cost = invoke_context
                        .get_compute_budget()
                        .curve25519_ristretto_subtract_cost;
                    consume_compute_meter(invoke_context, cost)?;

                    let left_point = translate_type::<ristretto::PodRistrettoPoint>(
                        memory_mapping,
                        left_input_addr,
                        invoke_context.get_check_aligned(),
                    )?;
                    let right_point = translate_type::<ristretto::PodRistrettoPoint>(
                        memory_mapping,
                        right_input_addr,
                        invoke_context.get_check_aligned(),
                    )?;

                    if let Some(result_point) =
                        ristretto::subtract_ristretto(left_point, right_point)
                    {
                        *translate_type_mut::<ristretto::PodRistrettoPoint>(
                            memory_mapping,
                            result_point_addr,
                            invoke_context.get_check_aligned(),
                        )? = result_point;
                        Ok(0)
                    } else {
                        Ok(1)
                    }
                }
                MUL => {
                    let cost = invoke_context
                        .get_compute_budget()
                        .curve25519_ristretto_multiply_cost;
                    consume_compute_meter(invoke_context, cost)?;

                    let scalar = translate_type::<scalar::PodScalar>(
                        memory_mapping,
                        left_input_addr,
                        invoke_context.get_check_aligned(),
                    )?;
                    let input_point = translate_type::<ristretto::PodRistrettoPoint>(
                        memory_mapping,
                        right_input_addr,
                        invoke_context.get_check_aligned(),
                    )?;

                    if let Some(result_point) = ristretto::multiply_ristretto(scalar, input_point) {
                        *translate_type_mut::<ristretto::PodRistrettoPoint>(
                            memory_mapping,
                            result_point_addr,
                            invoke_context.get_check_aligned(),
                        )? = result_point;
                        Ok(0)
                    } else {
                        Ok(1)
                    }
                }
                _ => {
                    if invoke_context
                        .get_feature_set()
                        .is_active(&abort_on_invalid_curve::id())
                    {
                        Err(SyscallError::InvalidAttribute.into())
                    } else {
                        Ok(1)
                    }
                }
            },

            _ => {
                if invoke_context
                    .get_feature_set()
                    .is_active(&abort_on_invalid_curve::id())
                {
                    Err(SyscallError::InvalidAttribute.into())
                } else {
                    Ok(1)
                }
            }
        }
    }
);

declare_builtin_function!(
    // Elliptic Curve Multiscalar Multiplication
    //
    // Currently, only curve25519 Edwards and Ristretto representations are supported
    SyscallCurveMultiscalarMultiplication,
    fn rust(
        invoke_context: &mut InvokeContext,
        curve_id: u64,
        scalars_addr: u64,
        points_addr: u64,
        points_len: u64,
        result_point_addr: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        use solana_curve25519::{curve_syscall_traits::*, edwards, ristretto, scalar};

        if points_len > 512 {
            return Err(Box::new(SyscallError::InvalidLength));
        }

        match curve_id {
            CURVE25519_EDWARDS => {
                let cost = invoke_context
                    .get_compute_budget()
                    .curve25519_edwards_msm_base_cost
                    .saturating_add(
                        invoke_context
                            .get_compute_budget()
                            .curve25519_edwards_msm_incremental_cost
                            .saturating_mul(points_len.saturating_sub(1)),
                    );
                consume_compute_meter(invoke_context, cost)?;

                let scalars = translate_slice::<scalar::PodScalar>(
                    memory_mapping,
                    scalars_addr,
                    points_len,
                    invoke_context.get_check_aligned(),
                )?;

                let points = translate_slice::<edwards::PodEdwardsPoint>(
                    memory_mapping,
                    points_addr,
                    points_len,
                    invoke_context.get_check_aligned(),
                )?;

                if let Some(result_point) = edwards::multiscalar_multiply_edwards(scalars, points) {
                    *translate_type_mut::<edwards::PodEdwardsPoint>(
                        memory_mapping,
                        result_point_addr,
                        invoke_context.get_check_aligned(),
                    )? = result_point;
                    Ok(0)
                } else {
                    Ok(1)
                }
            }

            CURVE25519_RISTRETTO => {
                let cost = invoke_context
                    .get_compute_budget()
                    .curve25519_ristretto_msm_base_cost
                    .saturating_add(
                        invoke_context
                            .get_compute_budget()
                            .curve25519_ristretto_msm_incremental_cost
                            .saturating_mul(points_len.saturating_sub(1)),
                    );
                consume_compute_meter(invoke_context, cost)?;

                let scalars = translate_slice::<scalar::PodScalar>(
                    memory_mapping,
                    scalars_addr,
                    points_len,
                    invoke_context.get_check_aligned(),
                )?;

                let points = translate_slice::<ristretto::PodRistrettoPoint>(
                    memory_mapping,
                    points_addr,
                    points_len,
                    invoke_context.get_check_aligned(),
                )?;

                if let Some(result_point) =
                    ristretto::multiscalar_multiply_ristretto(scalars, points)
                {
                    *translate_type_mut::<ristretto::PodRistrettoPoint>(
                        memory_mapping,
                        result_point_addr,
                        invoke_context.get_check_aligned(),
                    )? = result_point;
                    Ok(0)
                } else {
                    Ok(1)
                }
            }

            _ => {
                if invoke_context
                    .get_feature_set()
                    .is_active(&abort_on_invalid_curve::id())
                {
                    Err(SyscallError::InvalidAttribute.into())
                } else {
                    Ok(1)
                }
            }
        }
    }
);

declare_builtin_function!(
    /// Set return data
    SyscallSetReturnData,
    fn rust(
        invoke_context: &mut InvokeContext,
        addr: u64,
        len: u64,
        _arg3: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        let budget = invoke_context.get_compute_budget();

        let cost = len
            .checked_div(budget.cpi_bytes_per_unit)
            .unwrap_or(u64::MAX)
            .saturating_add(budget.syscall_base_cost);
        consume_compute_meter(invoke_context, cost)?;

        if len > MAX_RETURN_DATA as u64 {
            return Err(SyscallError::ReturnDataTooLarge(len, MAX_RETURN_DATA as u64).into());
        }

        let return_data = if len == 0 {
            Vec::new()
        } else {
            translate_slice::<u8>(
                memory_mapping,
                addr,
                len,
                invoke_context.get_check_aligned(),
            )?
            .to_vec()
        };
        let transaction_context = &mut invoke_context.transaction_context;
        let program_id = *transaction_context
            .get_current_instruction_context()
            .and_then(|instruction_context| {
                instruction_context.get_last_program_key(transaction_context)
            })?;

        transaction_context.set_return_data(program_id, return_data)?;

        Ok(0)
    }
);

declare_builtin_function!(
    /// Get return data
    SyscallGetReturnData,
    fn rust(
        invoke_context: &mut InvokeContext,
        return_data_addr: u64,
        length: u64,
        program_id_addr: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        let budget = invoke_context.get_compute_budget();

        consume_compute_meter(invoke_context, budget.syscall_base_cost)?;

        let (program_id, return_data) = invoke_context.transaction_context.get_return_data();
        let length = length.min(return_data.len() as u64);
        if length != 0 {
            let cost = length
                .saturating_add(size_of::<Pubkey>() as u64)
                .checked_div(budget.cpi_bytes_per_unit)
                .unwrap_or(u64::MAX);
            consume_compute_meter(invoke_context, cost)?;

            let return_data_result = translate_slice_mut::<u8>(
                memory_mapping,
                return_data_addr,
                length,
                invoke_context.get_check_aligned(),
            )?;

            let to_slice = return_data_result;
            let from_slice = return_data
                .get(..length as usize)
                .ok_or(SyscallError::InvokeContextBorrowFailed)?;
            if to_slice.len() != from_slice.len() {
                return Err(SyscallError::InvalidLength.into());
            }
            to_slice.copy_from_slice(from_slice);

            let program_id_result = translate_type_mut::<Pubkey>(
                memory_mapping,
                program_id_addr,
                invoke_context.get_check_aligned(),
            )?;

            if !is_nonoverlapping(
                to_slice.as_ptr() as usize,
                length as usize,
                program_id_result as *const _ as usize,
                std::mem::size_of::<Pubkey>(),
            ) {
                return Err(SyscallError::CopyOverlapping.into());
            }

            *program_id_result = *program_id;
        }

        // Return the actual length, rather the length returned
        Ok(return_data.len() as u64)
    }
);

declare_builtin_function!(
    /// Get a processed sigling instruction
    SyscallGetProcessedSiblingInstruction,
    fn rust(
        invoke_context: &mut InvokeContext,
        index: u64,
        meta_addr: u64,
        program_id_addr: u64,
        data_addr: u64,
        accounts_addr: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        let budget = invoke_context.get_compute_budget();

        consume_compute_meter(invoke_context, budget.syscall_base_cost)?;

        // Reverse iterate through the instruction trace,
        // ignoring anything except instructions on the same level
        let stack_height = invoke_context.get_stack_height();
        let instruction_trace_length = invoke_context
            .transaction_context
            .get_instruction_trace_length();
        let mut reverse_index_at_stack_height = 0;
        let mut found_instruction_context = None;
        for index_in_trace in (0..instruction_trace_length).rev() {
            let instruction_context = invoke_context
                .transaction_context
                .get_instruction_context_at_index_in_trace(index_in_trace)?;
            if instruction_context.get_stack_height() < stack_height {
                break;
            }
            if instruction_context.get_stack_height() == stack_height {
                if index.saturating_add(1) == reverse_index_at_stack_height {
                    found_instruction_context = Some(instruction_context);
                    break;
                }
                reverse_index_at_stack_height = reverse_index_at_stack_height.saturating_add(1);
            }
        }

        if let Some(instruction_context) = found_instruction_context {
            let result_header = translate_type_mut::<ProcessedSiblingInstruction>(
                memory_mapping,
                meta_addr,
                invoke_context.get_check_aligned(),
            )?;

            if result_header.data_len == (instruction_context.get_instruction_data().len() as u64)
                && result_header.accounts_len
                    == (instruction_context.get_number_of_instruction_accounts() as u64)
            {
                let program_id = translate_type_mut::<Pubkey>(
                    memory_mapping,
                    program_id_addr,
                    invoke_context.get_check_aligned(),
                )?;
                let data = translate_slice_mut::<u8>(
                    memory_mapping,
                    data_addr,
                    result_header.data_len,
                    invoke_context.get_check_aligned(),
                )?;
                let accounts = translate_slice_mut::<AccountMeta>(
                    memory_mapping,
                    accounts_addr,
                    result_header.accounts_len,
                    invoke_context.get_check_aligned(),
                )?;

                if !is_nonoverlapping(
                    result_header as *const _ as usize,
                    std::mem::size_of::<ProcessedSiblingInstruction>(),
                    program_id as *const _ as usize,
                    std::mem::size_of::<Pubkey>(),
                ) || !is_nonoverlapping(
                    result_header as *const _ as usize,
                    std::mem::size_of::<ProcessedSiblingInstruction>(),
                    accounts.as_ptr() as usize,
                    std::mem::size_of::<AccountMeta>()
                        .saturating_mul(result_header.accounts_len as usize),
                ) || !is_nonoverlapping(
                    result_header as *const _ as usize,
                    std::mem::size_of::<ProcessedSiblingInstruction>(),
                    data.as_ptr() as usize,
                    result_header.data_len as usize,
                ) || !is_nonoverlapping(
                    program_id as *const _ as usize,
                    std::mem::size_of::<Pubkey>(),
                    data.as_ptr() as usize,
                    result_header.data_len as usize,
                ) || !is_nonoverlapping(
                    program_id as *const _ as usize,
                    std::mem::size_of::<Pubkey>(),
                    accounts.as_ptr() as usize,
                    std::mem::size_of::<AccountMeta>()
                        .saturating_mul(result_header.accounts_len as usize),
                ) || !is_nonoverlapping(
                    data.as_ptr() as usize,
                    result_header.data_len as usize,
                    accounts.as_ptr() as usize,
                    std::mem::size_of::<AccountMeta>()
                        .saturating_mul(result_header.accounts_len as usize),
                ) {
                    return Err(SyscallError::CopyOverlapping.into());
                }

                *program_id = *instruction_context
                    .get_last_program_key(invoke_context.transaction_context)?;
                data.clone_from_slice(instruction_context.get_instruction_data());
                let account_metas = (0..instruction_context.get_number_of_instruction_accounts())
                    .map(|instruction_account_index| {
                        Ok(AccountMeta {
                            pubkey: *invoke_context
                                .transaction_context
                                .get_key_of_account_at_index(
                                    instruction_context
                                        .get_index_of_instruction_account_in_transaction(
                                            instruction_account_index,
                                        )?,
                                )?,
                            is_signer: instruction_context
                                .is_instruction_account_signer(instruction_account_index)?,
                            is_writable: instruction_context
                                .is_instruction_account_writable(instruction_account_index)?,
                        })
                    })
                    .collect::<Result<Vec<_>, InstructionError>>()?;
                accounts.clone_from_slice(account_metas.as_slice());
            }
            result_header.data_len = instruction_context.get_instruction_data().len() as u64;
            result_header.accounts_len =
                instruction_context.get_number_of_instruction_accounts() as u64;
            return Ok(true as u64);
        }
        Ok(false as u64)
    }
);

declare_builtin_function!(
    /// Get current call stack height
    SyscallGetStackHeight,
    fn rust(
        invoke_context: &mut InvokeContext,
        _arg1: u64,
        _arg2: u64,
        _arg3: u64,
        _arg4: u64,
        _arg5: u64,
        _memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        let budget = invoke_context.get_compute_budget();

        consume_compute_meter(invoke_context, budget.syscall_base_cost)?;

        Ok(invoke_context.get_stack_height() as u64)
    }
);

declare_builtin_function!(
    /// alt_bn128 group operations
    SyscallAltBn128,
    fn rust(
        invoke_context: &mut InvokeContext,
        group_op: u64,
        input_addr: u64,
        input_size: u64,
        result_addr: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        use solana_bn254::prelude::{ALT_BN128_ADD, ALT_BN128_MUL, ALT_BN128_PAIRING};
        let budget = invoke_context.get_compute_budget();
        let (cost, output): (u64, usize) = match group_op {
            ALT_BN128_ADD => (
                budget.alt_bn128_addition_cost,
                ALT_BN128_ADDITION_OUTPUT_LEN,
            ),
            ALT_BN128_MUL => (
                budget.alt_bn128_multiplication_cost,
                ALT_BN128_MULTIPLICATION_OUTPUT_LEN,
            ),
            ALT_BN128_PAIRING => {
                let ele_len = input_size
                    .checked_div(ALT_BN128_PAIRING_ELEMENT_LEN as u64)
                    .expect("div by non-zero constant");
                let cost = budget
                    .alt_bn128_pairing_one_pair_cost_first
                    .saturating_add(
                        budget
                            .alt_bn128_pairing_one_pair_cost_other
                            .saturating_mul(ele_len.saturating_sub(1)),
                    )
                    .saturating_add(budget.sha256_base_cost)
                    .saturating_add(input_size)
                    .saturating_add(ALT_BN128_PAIRING_OUTPUT_LEN as u64);
                (cost, ALT_BN128_PAIRING_OUTPUT_LEN)
            }
            _ => {
                return Err(SyscallError::InvalidAttribute.into());
            }
        };

        consume_compute_meter(invoke_context, cost)?;

        let input = translate_slice::<u8>(
            memory_mapping,
            input_addr,
            input_size,
            invoke_context.get_check_aligned(),
        )?;

        let call_result = translate_slice_mut::<u8>(
            memory_mapping,
            result_addr,
            output as u64,
            invoke_context.get_check_aligned(),
        )?;

        let calculation = match group_op {
            ALT_BN128_ADD => alt_bn128_addition,
            ALT_BN128_MUL => alt_bn128_multiplication,
            ALT_BN128_PAIRING => alt_bn128_pairing,
            _ => {
                return Err(SyscallError::InvalidAttribute.into());
            }
        };

        let simplify_alt_bn128_syscall_error_codes = invoke_context
            .get_feature_set()
            .is_active(&feature_set::simplify_alt_bn128_syscall_error_codes::id());

        let result_point = match calculation(input) {
            Ok(result_point) => result_point,
            Err(e) => {
                return if simplify_alt_bn128_syscall_error_codes {
                    Ok(1)
                } else {
                    Ok(e.into())
                };
            }
        };

        // This can never happen and should be removed when the
        // simplify_alt_bn128_syscall_error_codes feature gets activated
        if result_point.len() != output && !simplify_alt_bn128_syscall_error_codes {
            return Ok(AltBn128Error::SliceOutOfBounds.into());
        }

        call_result.copy_from_slice(&result_point);
        Ok(SUCCESS)
    }
);

declare_builtin_function!(
    /// Big integer modular exponentiation
    SyscallBigModExp,
    fn rust(
        invoke_context: &mut InvokeContext,
        params: u64,
        return_value: u64,
        _arg3: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        let params = &translate_slice::<BigModExpParams>(
            memory_mapping,
            params,
            1,
            invoke_context.get_check_aligned(),
        )?
        .first()
        .ok_or(SyscallError::InvalidLength)?;

        if params.base_len > 512 || params.exponent_len > 512 || params.modulus_len > 512 {
            return Err(Box::new(SyscallError::InvalidLength));
        }

        let input_len: u64 = std::cmp::max(params.base_len, params.exponent_len);
        let input_len: u64 = std::cmp::max(input_len, params.modulus_len);

        let budget = invoke_context.get_compute_budget();
        // the compute units are calculated by the quadratic equation `0.5 input_len^2 + 190`
        consume_compute_meter(
            invoke_context,
            budget.syscall_base_cost.saturating_add(
                input_len
                    .saturating_mul(input_len)
                    .checked_div(budget.big_modular_exponentiation_cost_divisor)
                    .unwrap_or(u64::MAX)
                    .saturating_add(budget.big_modular_exponentiation_base_cost),
            ),
        )?;

        let base = translate_slice::<u8>(
            memory_mapping,
            params.base as *const _ as u64,
            params.base_len,
            invoke_context.get_check_aligned(),
        )?;

        let exponent = translate_slice::<u8>(
            memory_mapping,
            params.exponent as *const _ as u64,
            params.exponent_len,
            invoke_context.get_check_aligned(),
        )?;

        let modulus = translate_slice::<u8>(
            memory_mapping,
            params.modulus as *const _ as u64,
            params.modulus_len,
            invoke_context.get_check_aligned(),
        )?;

        let value = big_mod_exp(base, exponent, modulus);

        let return_value = translate_slice_mut::<u8>(
            memory_mapping,
            return_value,
            params.modulus_len,
            invoke_context.get_check_aligned(),
        )?;
        return_value.copy_from_slice(value.as_slice());

        Ok(0)
    }
);

declare_builtin_function!(
    // Poseidon
    SyscallPoseidon,
    fn rust(
        invoke_context: &mut InvokeContext,
        parameters: u64,
        endianness: u64,
        vals_addr: u64,
        vals_len: u64,
        result_addr: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        let parameters: poseidon::Parameters = parameters.try_into()?;
        let endianness: poseidon::Endianness = endianness.try_into()?;

        if vals_len > 12 {
            ic_msg!(
                invoke_context,
                "Poseidon hashing {} sequences is not supported",
                vals_len,
            );
            return Err(SyscallError::InvalidLength.into());
        }

        let budget = invoke_context.get_compute_budget();
        let Some(cost) = budget.poseidon_cost(vals_len) else {
            ic_msg!(
                invoke_context,
                "Overflow while calculating the compute cost"
            );
            return Err(SyscallError::ArithmeticOverflow.into());
        };
        consume_compute_meter(invoke_context, cost.to_owned())?;

        let hash_result = translate_slice_mut::<u8>(
            memory_mapping,
            result_addr,
            poseidon::HASH_BYTES as u64,
            invoke_context.get_check_aligned(),
        )?;
        let inputs = translate_slice::<&[u8]>(
            memory_mapping,
            vals_addr,
            vals_len,
            invoke_context.get_check_aligned(),
        )?;
        let inputs = inputs
            .iter()
            .map(|input| {
                translate_slice::<u8>(
                    memory_mapping,
                    input.as_ptr() as *const _ as u64,
                    input.len() as u64,
                    invoke_context.get_check_aligned(),
                )
            })
            .collect::<Result<Vec<_>, Error>>()?;

        let simplify_alt_bn128_syscall_error_codes = invoke_context
            .get_feature_set()
            .is_active(&feature_set::simplify_alt_bn128_syscall_error_codes::id());

        let hash = match poseidon::hashv(parameters, endianness, inputs.as_slice()) {
            Ok(hash) => hash,
            Err(e) => {
                return if simplify_alt_bn128_syscall_error_codes {
                    Ok(1)
                } else {
                    Ok(e.into())
                };
            }
        };
        hash_result.copy_from_slice(&hash.to_bytes());

        Ok(SUCCESS)
    }
);

declare_builtin_function!(
    /// Read remaining compute units
    SyscallRemainingComputeUnits,
    fn rust(
        invoke_context: &mut InvokeContext,
        _arg1: u64,
        _arg2: u64,
        _arg3: u64,
        _arg4: u64,
        _arg5: u64,
        _memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        let budget = invoke_context.get_compute_budget();
        consume_compute_meter(invoke_context, budget.syscall_base_cost)?;

        use solana_rbpf::vm::ContextObject;
        Ok(invoke_context.get_remaining())
    }
);

declare_builtin_function!(
    /// alt_bn128 g1 and g2 compression and decompression
    SyscallAltBn128Compression,
    fn rust(
        invoke_context: &mut InvokeContext,
        op: u64,
        input_addr: u64,
        input_size: u64,
        result_addr: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        use solana_bn254::compression::prelude::{
            alt_bn128_g1_compress, alt_bn128_g1_decompress, alt_bn128_g2_compress,
            alt_bn128_g2_decompress, ALT_BN128_G1_COMPRESS, ALT_BN128_G1_DECOMPRESS,
            ALT_BN128_G2_COMPRESS, ALT_BN128_G2_DECOMPRESS, G1, G1_COMPRESSED, G2, G2_COMPRESSED,
        };
        let budget = invoke_context.get_compute_budget();
        let base_cost = budget.syscall_base_cost;
        let (cost, output): (u64, usize) = match op {
            ALT_BN128_G1_COMPRESS => (
                base_cost.saturating_add(budget.alt_bn128_g1_compress),
                G1_COMPRESSED,
            ),
            ALT_BN128_G1_DECOMPRESS => {
                (base_cost.saturating_add(budget.alt_bn128_g1_decompress), G1)
            }
            ALT_BN128_G2_COMPRESS => (
                base_cost.saturating_add(budget.alt_bn128_g2_compress),
                G2_COMPRESSED,
            ),
            ALT_BN128_G2_DECOMPRESS => {
                (base_cost.saturating_add(budget.alt_bn128_g2_decompress), G2)
            }
            _ => {
                return Err(SyscallError::InvalidAttribute.into());
            }
        };

        consume_compute_meter(invoke_context, cost)?;

        let input = translate_slice::<u8>(
            memory_mapping,
            input_addr,
            input_size,
            invoke_context.get_check_aligned(),
        )?;

        let call_result = translate_slice_mut::<u8>(
            memory_mapping,
            result_addr,
            output as u64,
            invoke_context.get_check_aligned(),
        )?;

        let simplify_alt_bn128_syscall_error_codes = invoke_context
            .get_feature_set()
            .is_active(&feature_set::simplify_alt_bn128_syscall_error_codes::id());

        match op {
            ALT_BN128_G1_COMPRESS => {
                let result_point = match alt_bn128_g1_compress(input) {
                    Ok(result_point) => result_point,
                    Err(e) => {
                        return if simplify_alt_bn128_syscall_error_codes {
                            Ok(1)
                        } else {
                            Ok(e.into())
                        };
                    }
                };
                call_result.copy_from_slice(&result_point);
                Ok(SUCCESS)
            }
            ALT_BN128_G1_DECOMPRESS => {
                let result_point = match alt_bn128_g1_decompress(input) {
                    Ok(result_point) => result_point,
                    Err(e) => {
                        return if simplify_alt_bn128_syscall_error_codes {
                            Ok(1)
                        } else {
                            Ok(e.into())
                        };
                    }
                };
                call_result.copy_from_slice(&result_point);
                Ok(SUCCESS)
            }
            ALT_BN128_G2_COMPRESS => {
                let result_point = match alt_bn128_g2_compress(input) {
                    Ok(result_point) => result_point,
                    Err(e) => {
                        return if simplify_alt_bn128_syscall_error_codes {
                            Ok(1)
                        } else {
                            Ok(e.into())
                        };
                    }
                };
                call_result.copy_from_slice(&result_point);
                Ok(SUCCESS)
            }
            ALT_BN128_G2_DECOMPRESS => {
                let result_point = match alt_bn128_g2_decompress(input) {
                    Ok(result_point) => result_point,
                    Err(e) => {
                        return if simplify_alt_bn128_syscall_error_codes {
                            Ok(1)
                        } else {
                            Ok(e.into())
                        };
                    }
                };
                call_result.copy_from_slice(&result_point);
                Ok(SUCCESS)
            }
            _ => Err(SyscallError::InvalidAttribute.into()),
        }
    }
);

declare_builtin_function!(
    // Generic Hashing Syscall
    SyscallHash<H: HasherImpl>,
    fn rust(
        invoke_context: &mut InvokeContext,
        vals_addr: u64,
        vals_len: u64,
        result_addr: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        let compute_budget = invoke_context.get_compute_budget();
        let hash_base_cost = H::get_base_cost(compute_budget);
        let hash_byte_cost = H::get_byte_cost(compute_budget);
        let hash_max_slices = H::get_max_slices(compute_budget);
        if hash_max_slices < vals_len {
            ic_msg!(
                invoke_context,
                "{} Hashing {} sequences in one syscall is over the limit {}",
                H::NAME,
                vals_len,
                hash_max_slices,
            );
            return Err(SyscallError::TooManySlices.into());
        }

        consume_compute_meter(invoke_context, hash_base_cost)?;

        let hash_result = translate_slice_mut::<u8>(
            memory_mapping,
            result_addr,
            std::mem::size_of::<H::Output>() as u64,
            invoke_context.get_check_aligned(),
        )?;
        let mut hasher = H::create_hasher();
        if vals_len > 0 {
            let vals = translate_slice::<&[u8]>(
                memory_mapping,
                vals_addr,
                vals_len,
                invoke_context.get_check_aligned(),
            )?;
            for val in vals.iter() {
                let bytes = translate_slice::<u8>(
                    memory_mapping,
                    val.as_ptr() as u64,
                    val.len() as u64,
                    invoke_context.get_check_aligned(),
                )?;
                let cost = compute_budget.mem_op_base_cost.max(
                    hash_byte_cost.saturating_mul(
                        (val.len() as u64)
                            .checked_div(2)
                            .expect("div by non-zero literal"),
                    ),
                );
                consume_compute_meter(invoke_context, cost)?;
                hasher.hash(bytes);
            }
        }
        hash_result.copy_from_slice(hasher.result().as_ref());
        Ok(0)
    }
);

declare_builtin_function!(
    // Get Epoch Stake Syscall
    SyscallGetEpochStake,
    fn rust(
        invoke_context: &mut InvokeContext,
        var_addr: u64,
        _arg2: u64,
        _arg3: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        let compute_budget = invoke_context.get_compute_budget();

        if var_addr == 0 {
            // As specified by SIMD-0133: If `var_addr` is a null pointer:
            //
            // Compute units:
            //
            // ```
            // syscall_base
            // ```
            let compute_units = compute_budget.syscall_base_cost;
            consume_compute_meter(invoke_context, compute_units)?;
            //
            // Control flow:
            //
            // - The syscall aborts the virtual machine if:
            //     - Compute budget is exceeded.
            // - Otherwise, the syscall returns a `u64` integer representing the total active
            //   stake on the cluster for the current epoch.
            Ok(invoke_context.get_epoch_total_stake().unwrap_or(0))
        } else {
            // As specified by SIMD-0133: If `var_addr` is _not_ a null pointer:
            //
            // Compute units:
            //
            // ```
            // syscall_base + floor(PUBKEY_BYTES/cpi_bytes_per_unit) + mem_op_base
            // ```
            let compute_units = compute_budget
                .syscall_base_cost
                .saturating_add(
                    (PUBKEY_BYTES as u64)
                        .checked_div(compute_budget.cpi_bytes_per_unit)
                        .unwrap_or(u64::MAX),
                )
                .saturating_add(compute_budget.mem_op_base_cost);
            consume_compute_meter(invoke_context, compute_units)?;
            //
            // Control flow:
            //
            // - The syscall aborts the virtual machine if:
            //     - Not all bytes in VM memory range `[vote_addr, vote_addr + 32)` are
            //       readable.
            //     - Compute budget is exceeded.
            // - Otherwise, the syscall returns a `u64` integer representing the total active
            //   stake delegated to the vote account at the provided address.
            //   If the provided vote address corresponds to an account that is not a vote
            //   account or does not exist, the syscall will return `0` for active stake.
            let check_aligned = invoke_context.get_check_aligned();
            let vote_address = translate_type::<Pubkey>(memory_mapping, var_addr, check_aligned)?;

            Ok(
                if let Some(vote_accounts) = invoke_context.get_epoch_vote_accounts() {
                    vote_accounts
                        .get(vote_address)
                        .map(|(stake, _)| *stake)
                        .unwrap_or(0)
                } else {
                    0
                },
            )
        }
    }
);

declare_builtin_function!(
    /// Get a Clock sysvar
    SyscallGetClockSysvar,
    fn rust(
        invoke_context: &mut InvokeContext,
        var_addr: u64,
        _arg2: u64,
        _arg3: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        get_sysvar(
            invoke_context.get_sysvar_cache().get_clock(),
            var_addr,
            invoke_context.get_check_aligned(),
            memory_mapping,
            invoke_context,
        )
    }
);

declare_builtin_function!(
    /// Get a EpochSchedule sysvar
    SyscallGetEpochScheduleSysvar,
    fn rust(
        invoke_context: &mut InvokeContext,
        var_addr: u64,
        _arg2: u64,
        _arg3: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        get_sysvar(
            invoke_context.get_sysvar_cache().get_epoch_schedule(),
            var_addr,
            invoke_context.get_check_aligned(),
            memory_mapping,
            invoke_context,
        )
    }
);

declare_builtin_function!(
    /// Get a EpochRewards sysvar
    SyscallGetEpochRewardsSysvar,
    fn rust(
        invoke_context: &mut InvokeContext,
        var_addr: u64,
        _arg2: u64,
        _arg3: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        get_sysvar(
            invoke_context.get_sysvar_cache().get_epoch_rewards(),
            var_addr,
            invoke_context.get_check_aligned(),
            memory_mapping,
            invoke_context,
        )
    }
);

declare_builtin_function!(
    /// Get a Fees sysvar
    SyscallGetFeesSysvar,
    fn rust(
        invoke_context: &mut InvokeContext,
        var_addr: u64,
        _arg2: u64,
        _arg3: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        #[allow(deprecated)]
        {
            get_sysvar(
                invoke_context.get_sysvar_cache().get_fees(),
                var_addr,
                invoke_context.get_check_aligned(),
                memory_mapping,
                invoke_context,
            )
        }
    }
);

declare_builtin_function!(
    /// Get a Rent sysvar
    SyscallGetRentSysvar,
    fn rust(
        invoke_context: &mut InvokeContext,
        var_addr: u64,
        _arg2: u64,
        _arg3: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        get_sysvar(
            invoke_context.get_sysvar_cache().get_rent(),
            var_addr,
            invoke_context.get_check_aligned(),
            memory_mapping,
            invoke_context,
        )
    }
);

declare_builtin_function!(
    /// Get a Last Restart Slot sysvar
    SyscallGetLastRestartSlotSysvar,
    fn rust(
        invoke_context: &mut InvokeContext,
        var_addr: u64,
        _arg2: u64,
        _arg3: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        get_sysvar(
            invoke_context.get_sysvar_cache().get_last_restart_slot(),
            var_addr,
            invoke_context.get_check_aligned(),
            memory_mapping,
            invoke_context,
        )
    }
);

const SYSVAR_NOT_FOUND: u64 = 2;
const OFFSET_LENGTH_EXCEEDS_SYSVAR: u64 = 1;

// quoted language from SIMD0127
// because this syscall can both return error codes and abort, well-ordered error checking is crucial
declare_builtin_function!(
    /// Get a slice of a Sysvar in-memory representation
    SyscallGetSysvar,
    fn rust(
        invoke_context: &mut InvokeContext,
        sysvar_id_addr: u64,
        var_addr: u64,
        offset: u64,
        length: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        let check_aligned = invoke_context.get_check_aligned();
        let ComputeBudget {
            sysvar_base_cost,
            cpi_bytes_per_unit,
            mem_op_base_cost,
            ..
        } = *invoke_context.get_compute_budget();

        // Abort: "Compute budget is exceeded."
        let sysvar_id_cost = 32_u64.checked_div(cpi_bytes_per_unit).unwrap_or(0);
        let sysvar_buf_cost = length.checked_div(cpi_bytes_per_unit).unwrap_or(0);
        consume_compute_meter(
            invoke_context,
            sysvar_base_cost
                .saturating_add(sysvar_id_cost)
                .saturating_add(std::cmp::max(sysvar_buf_cost, mem_op_base_cost)),
        )?;

        // Abort: "Not all bytes in VM memory range `[sysvar_id, sysvar_id + 32)` are readable."
        let sysvar_id = translate_type::<Pubkey>(memory_mapping, sysvar_id_addr, check_aligned)?;

        // Abort: "Not all bytes in VM memory range `[var_addr, var_addr + length)` are writable."
        let var = translate_slice_mut::<u8>(memory_mapping, var_addr, length, check_aligned)?;

        // Abort: "`offset + length` is not in `[0, 2^64)`."
        let offset_length = offset
            .checked_add(length)
            .ok_or(InstructionError::ArithmeticOverflow)?;

        // Abort: "`var_addr + length` is not in `[0, 2^64)`."
        let _ = var_addr
            .checked_add(length)
            .ok_or(InstructionError::ArithmeticOverflow)?;

        let cache = invoke_context.get_sysvar_cache();

        // "`2` if the sysvar data is not present in the Sysvar Cache."
        let sysvar_buf = match cache.sysvar_id_to_buffer(sysvar_id) {
            None => return Ok(SYSVAR_NOT_FOUND),
            Some(ref sysvar_buf) => sysvar_buf,
        };

        // "`1` if `offset + length` is greater than the length of the sysvar data."
        if let Some(sysvar_slice) = sysvar_buf.get(offset as usize..offset_length as usize) {
            var.copy_from_slice(sysvar_slice);
        } else {
            return Ok(OFFSET_LENGTH_EXCEEDS_SYSVAR);
        }

        Ok(SUCCESS)
    }
);

declare_builtin_function!(
    /// memcpy
    SyscallMemcpy,
    fn rust(
        invoke_context: &mut InvokeContext,
        dst_addr: u64,
        src_addr: u64,
        n: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        mem_op_consume(invoke_context, n)?;

        if !is_nonoverlapping(src_addr, n, dst_addr, n) {
            return Err(SyscallError::CopyOverlapping.into());
        }

        // host addresses can overlap so we always invoke memmove
        memmove(invoke_context, dst_addr, src_addr, n, memory_mapping)
    }
);

declare_builtin_function!(
    /// memmove
    SyscallMemmove,
    fn rust(
        invoke_context: &mut InvokeContext,
        dst_addr: u64,
        src_addr: u64,
        n: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        mem_op_consume(invoke_context, n)?;

        memmove(invoke_context, dst_addr, src_addr, n, memory_mapping)
    }
);

declare_builtin_function!(
    /// memcmp
    SyscallMemcmp,
    fn rust(
        invoke_context: &mut InvokeContext,
        s1_addr: u64,
        s2_addr: u64,
        n: u64,
        cmp_result_addr: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        mem_op_consume(invoke_context, n)?;

        if invoke_context
            .get_feature_set()
            .is_active(&features::bpf_account_data_direct_mapping::id())
        {
            let cmp_result = translate_type_mut::<i32>(
                memory_mapping,
                cmp_result_addr,
                invoke_context.get_check_aligned(),
            )?;
            let syscall_context = invoke_context.get_syscall_context()?;

            *cmp_result = memcmp_non_contiguous(s1_addr, s2_addr, n, &syscall_context.accounts_metadata, memory_mapping)?;
        } else {
            let s1 = translate_slice::<u8>(
                memory_mapping,
                s1_addr,
                n,
                invoke_context.get_check_aligned(),
            )?;
            let s2 = translate_slice::<u8>(
                memory_mapping,
                s2_addr,
                n,
                invoke_context.get_check_aligned(),
            )?;
            let cmp_result = translate_type_mut::<i32>(
                memory_mapping,
                cmp_result_addr,
                invoke_context.get_check_aligned(),
            )?;

            debug_assert_eq!(s1.len(), n as usize);
            debug_assert_eq!(s2.len(), n as usize);
            // Safety:
            // memcmp is marked unsafe since it assumes that the inputs are at least
            // `n` bytes long. `s1` and `s2` are guaranteed to be exactly `n` bytes
            // long because `translate_slice` would have failed otherwise.
            *cmp_result = unsafe { memcmp(s1, s2, n as usize) };
        }

        Ok(0)
    }
);

declare_builtin_function!(
    /// memset
    SyscallMemset,
    fn rust(
        invoke_context: &mut InvokeContext,
        dst_addr: u64,
        c: u64,
        n: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        mem_op_consume(invoke_context, n)?;

        if invoke_context
            .get_feature_set()
            .is_active(&features::bpf_account_data_direct_mapping::id())
        {
            let syscall_context = invoke_context.get_syscall_context()?;

            memset_non_contiguous(dst_addr, c as u8, n, &syscall_context.accounts_metadata, memory_mapping)
        } else {
            let s = translate_slice_mut::<u8>(
                memory_mapping,
                dst_addr,
                n,
                invoke_context.get_check_aligned(),
            )?;
            s.fill(c as u8);
            Ok(0)
        }
    }
);

declare_builtin_function!(
    /// Cross-program invocation called from C
    SyscallInvokeSignedC,
    fn rust(
        invoke_context: &mut InvokeContext,
        instruction_addr: u64,
        account_infos_addr: u64,
        account_infos_len: u64,
        signers_seeds_addr: u64,
        signers_seeds_len: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        cpi_common::<Self>(
            invoke_context,
            instruction_addr,
            account_infos_addr,
            account_infos_len,
            signers_seeds_addr,
            signers_seeds_len,
            memory_mapping,
        )
    }
);

declare_builtin_function!(
    /// Cross-program invocation called from Rust
    SyscallInvokeSignedRust,
    fn rust(
        invoke_context: &mut InvokeContext,
        instruction_addr: u64,
        account_infos_addr: u64,
        account_infos_len: u64,
        signers_seeds_addr: u64,
        signers_seeds_len: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        cpi_common::<Self>(
            invoke_context,
            instruction_addr,
            account_infos_addr,
            account_infos_len,
            signers_seeds_addr,
            signers_seeds_len,
            memory_mapping,
        )
    }
);
