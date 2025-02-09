use std::{mem, ptr};

use scopeguard::defer;
use solana_sbpf::{
    declare_builtin_function, ebpf,
    memory_region::{AccessType, MemoryMapping, MemoryRegion, MemoryState},
};

use crate::{
    bpf_loader, bpf_loader_deprecated, bpf_loader_upgradeable,
    features::{self, enable_bpf_loader_set_authority_checked_ix},
    ic_msg, native_loader, translate, translate_slice, translate_slice_mut, translate_type,
    translate_type_mut, AccountInfo, AccountMeta, BorrowedAccount, IndexOfAccount,
    InstructionAccount, InstructionError, InvokeContext, Measure, Pubkey,
    SerializedAccountMetadata, StableInstruction, SyscallError, BPF_ALIGN_OF_U128,
    MAX_CPI_ACCOUNT_INFOS, MAX_CPI_INSTRUCTION_ACCOUNTS, MAX_CPI_INSTRUCTION_DATA_LEN,
    MAX_PERMITTED_DATA_INCREASE, MAX_SEEDS, MAX_SIGNERS, PRECOMPILES, SUCCESS,
};

type Error = Box<dyn std::error::Error>;

fn consume_compute_meter(invoke_context: &InvokeContext, amount: u64) -> Result<(), Error> {
    invoke_context.consume_checked(amount)?;
    Ok(())
}

fn check_account_info_pointer(
    invoke_context: &InvokeContext,
    vm_addr: u64,
    expected_vm_addr: u64,
    field: &str,
) -> Result<(), Error> {
    if vm_addr != expected_vm_addr {
        ic_msg!(
            invoke_context,
            "Invalid account info pointer `{}': {:#x} != {:#x}",
            field,
            vm_addr,
            expected_vm_addr
        );
        return Err(SyscallError::InvalidPointer.into());
    }
    Ok(())
}

enum VmValue<'a, 'b, T> {
    VmAddress {
        vm_addr: u64,
        memory_mapping: &'b MemoryMapping<'a>,
        check_aligned: bool,
    },
    // Once direct mapping is activated, this variant can be removed and the
    // enum can be made a struct.
    Translated(&'a mut T),
}

impl<T> VmValue<'_, '_, T> {
    fn get(&self) -> Result<&T, Error> {
        match self {
            VmValue::VmAddress {
                vm_addr,
                memory_mapping,
                check_aligned,
            } => translate_type(memory_mapping, *vm_addr, *check_aligned),
            VmValue::Translated(addr) => Ok(*addr),
        }
    }

    fn get_mut(&mut self) -> Result<&mut T, Error> {
        match self {
            VmValue::VmAddress {
                vm_addr,
                memory_mapping,
                check_aligned,
            } => translate_type_mut(memory_mapping, *vm_addr, *check_aligned),
            VmValue::Translated(addr) => Ok(*addr),
        }
    }
}

/// Host side representation of AccountInfo or SolAccountInfo passed to the CPI syscall.
///
/// At the start of a CPI, this can be different from the data stored in the
/// corresponding BorrowedAccount, and needs to be synched.
struct CallerAccount<'a, 'b> {
    lamports: &'a mut u64,
    owner: &'a mut Pubkey,
    // The original data length of the account at the start of the current
    // instruction. We use this to determine wether an account was shrunk or
    // grown before or after CPI, and to derive the vm address of the realloc
    // region.
    original_data_len: usize,
    // This points to the data section for this account, as serialized and
    // mapped inside the vm (see serialize_parameters() in
    // BpfExecutor::execute).
    //
    // This is only set when direct mapping is off (see the relevant comment in
    // CallerAccount::from_account_info).
    serialized_data: &'a mut [u8],
    // Given the corresponding input AccountInfo::data, vm_data_addr points to
    // the pointer field and ref_to_len_in_vm points to the length field.
    vm_data_addr: u64,
    ref_to_len_in_vm: VmValue<'b, 'a, u64>,
}

impl<'a, 'b> CallerAccount<'a, 'b> {
    // Create a CallerAccount given an AccountInfo.
    fn from_account_info(
        invoke_context: &InvokeContext,
        memory_mapping: &'b MemoryMapping<'a>,
        _vm_addr: u64,
        account_info: &AccountInfo,
        account_metadata: &SerializedAccountMetadata,
    ) -> Result<CallerAccount<'a, 'b>, Error> {
        let direct_mapping = invoke_context
            .get_feature_set()
            .is_active(&features::bpf_account_data_direct_mapping::id());

        if direct_mapping {
            check_account_info_pointer(
                invoke_context,
                account_info.key as *const _ as u64,
                account_metadata.vm_key_addr,
                "key",
            )?;
            check_account_info_pointer(
                invoke_context,
                account_info.owner as *const _ as u64,
                account_metadata.vm_owner_addr,
                "owner",
            )?;
        }

        // account_info points to host memory. The addresses used internally are
        // in vm space so they need to be translated.
        let lamports = {
            // Double translate lamports out of RefCell
            let ptr = translate_type::<u64>(
                memory_mapping,
                account_info.lamports.as_ptr() as u64,
                invoke_context.get_check_aligned(),
            )?;
            if direct_mapping {
                if account_info.lamports.as_ptr() as u64 >= ebpf::MM_INPUT_START {
                    return Err(SyscallError::InvalidPointer.into());
                }

                check_account_info_pointer(
                    invoke_context,
                    *ptr,
                    account_metadata.vm_lamports_addr,
                    "lamports",
                )?;
            }
            translate_type_mut::<u64>(memory_mapping, *ptr, invoke_context.get_check_aligned())?
        };

        let owner = translate_type_mut::<Pubkey>(
            memory_mapping,
            account_info.owner as *const _ as u64,
            invoke_context.get_check_aligned(),
        )?;

        let (serialized_data, vm_data_addr, ref_to_len_in_vm) = {
            if direct_mapping && account_info.data.as_ptr() as u64 >= ebpf::MM_INPUT_START {
                return Err(SyscallError::InvalidPointer.into());
            }

            // Double translate data out of RefCell
            let data = *translate_type::<&[u8]>(
                memory_mapping,
                account_info.data.as_ptr() as *const _ as u64,
                invoke_context.get_check_aligned(),
            )?;
            if direct_mapping {
                check_account_info_pointer(
                    invoke_context,
                    data.as_ptr() as u64,
                    account_metadata.vm_data_addr,
                    "data",
                )?;
            }

            consume_compute_meter(
                invoke_context,
                (data.len() as u64)
                    .checked_div(invoke_context.get_compute_budget().cpi_bytes_per_unit)
                    .unwrap_or(u64::MAX),
            )?;

            let ref_to_len_in_vm = if direct_mapping {
                let vm_addr = (account_info.data.as_ptr() as *const u64 as u64)
                    .saturating_add(size_of::<u64>() as u64);
                // In the same vein as the other check_account_info_pointer() checks, we don't lock
                // this pointer to a specific address but we don't want it to be inside accounts, or
                // callees might be able to write to the pointed memory.
                if vm_addr >= ebpf::MM_INPUT_START {
                    return Err(SyscallError::InvalidPointer.into());
                }
                VmValue::VmAddress {
                    vm_addr,
                    memory_mapping,
                    check_aligned: invoke_context.get_check_aligned(),
                }
            } else {
                let translated = translate(
                    memory_mapping,
                    AccessType::Store,
                    (account_info.data.as_ptr() as *const u64 as u64)
                        .saturating_add(size_of::<u64>() as u64),
                    8,
                )? as *mut u64;
                VmValue::Translated(unsafe { &mut *translated })
            };
            let vm_data_addr = data.as_ptr() as u64;

            let serialized_data = if direct_mapping {
                // when direct mapping is enabled, the permissions on the
                // realloc region can change during CPI so we must delay
                // translating until when we know whether we're going to mutate
                // the realloc region or not. Consider this case:
                //
                // [caller can't write to an account] <- we are here
                // [callee grows and assigns account to the caller]
                // [caller can now write to the account]
                //
                // If we always translated the realloc area here, we'd get a
                // memory access violation since we can't write to the account
                // _yet_, but we will be able to once the caller returns.
                &mut []
            } else {
                translate_slice_mut::<u8>(
                    memory_mapping,
                    vm_data_addr,
                    data.len() as u64,
                    invoke_context.get_check_aligned(),
                )?
            };
            (serialized_data, vm_data_addr, ref_to_len_in_vm)
        };

        Ok(CallerAccount {
            lamports,
            owner,
            original_data_len: account_metadata.original_data_len,
            serialized_data,
            vm_data_addr,
            ref_to_len_in_vm,
        })
    }

    // Create a CallerAccount given a SolAccountInfo.
    fn from_sol_account_info(
        invoke_context: &InvokeContext,
        memory_mapping: &'b MemoryMapping<'a>,
        vm_addr: u64,
        account_info: &SolAccountInfo,
        account_metadata: &SerializedAccountMetadata,
    ) -> Result<CallerAccount<'a, 'b>, Error> {
        let direct_mapping = invoke_context
            .get_feature_set()
            .is_active(&features::bpf_account_data_direct_mapping::id());

        if direct_mapping {
            check_account_info_pointer(
                invoke_context,
                account_info.key_addr,
                account_metadata.vm_key_addr,
                "key",
            )?;

            check_account_info_pointer(
                invoke_context,
                account_info.owner_addr,
                account_metadata.vm_owner_addr,
                "owner",
            )?;

            check_account_info_pointer(
                invoke_context,
                account_info.lamports_addr,
                account_metadata.vm_lamports_addr,
                "lamports",
            )?;

            check_account_info_pointer(
                invoke_context,
                account_info.data_addr,
                account_metadata.vm_data_addr,
                "data",
            )?;
        }

        // account_info points to host memory. The addresses used internally are
        // in vm space so they need to be translated.
        let lamports = translate_type_mut::<u64>(
            memory_mapping,
            account_info.lamports_addr,
            invoke_context.get_check_aligned(),
        )?;
        let owner = translate_type_mut::<Pubkey>(
            memory_mapping,
            account_info.owner_addr,
            invoke_context.get_check_aligned(),
        )?;

        consume_compute_meter(
            invoke_context,
            account_info
                .data_len
                .checked_div(invoke_context.get_compute_budget().cpi_bytes_per_unit)
                .unwrap_or(u64::MAX),
        )?;

        let serialized_data = if direct_mapping {
            // See comment in CallerAccount::from_account_info()
            &mut []
        } else {
            translate_slice_mut::<u8>(
                memory_mapping,
                account_info.data_addr,
                account_info.data_len,
                invoke_context.get_check_aligned(),
            )?
        };

        // we already have the host addr we want: &mut account_info.data_len.
        // The account info might be read only in the vm though, so we translate
        // to ensure we can write. This is tested by programs/sbf/rust/ro_modify
        // which puts SolAccountInfo in rodata.
        let data_len_vm_addr = vm_addr
            .saturating_add(&account_info.data_len as *const u64 as u64)
            .saturating_sub(account_info as *const _ as *const u64 as u64);

        let ref_to_len_in_vm = if direct_mapping {
            VmValue::VmAddress {
                vm_addr: data_len_vm_addr,
                memory_mapping,
                check_aligned: invoke_context.get_check_aligned(),
            }
        } else {
            let data_len_addr = translate(
                memory_mapping,
                AccessType::Store,
                data_len_vm_addr,
                size_of::<u64>() as u64,
            )?;
            VmValue::Translated(unsafe { &mut *(data_len_addr as *mut u64) })
        };

        Ok(CallerAccount {
            lamports,
            owner,
            original_data_len: account_metadata.original_data_len,
            serialized_data,
            vm_data_addr: account_info.data_addr,
            ref_to_len_in_vm,
        })
    }

    fn realloc_region(
        &self,
        memory_mapping: &'b MemoryMapping<'_>,
        is_loader_deprecated: bool,
    ) -> Result<Option<&'a MemoryRegion>, Error> {
        account_realloc_region(
            memory_mapping,
            self.vm_data_addr,
            self.original_data_len,
            is_loader_deprecated,
        )
    }
}

type TranslatedAccounts<'a, 'b> = Vec<(IndexOfAccount, Option<CallerAccount<'a, 'b>>)>;

/// Implemented by language specific data structure translators
trait SyscallInvokeSigned {
    fn translate_instruction(
        addr: u64,
        memory_mapping: &MemoryMapping,
        invoke_context: &mut InvokeContext,
    ) -> Result<StableInstruction, Error>;
    fn translate_accounts<'a, 'b>(
        instruction_accounts: &[InstructionAccount],
        program_indices: &[IndexOfAccount],
        account_infos_addr: u64,
        account_infos_len: u64,
        is_loader_deprecated: bool,
        memory_mapping: &'b MemoryMapping<'a>,
        invoke_context: &mut InvokeContext,
    ) -> Result<TranslatedAccounts<'a, 'b>, Error>;
    fn translate_signers(
        program_id: &Pubkey,
        signers_seeds_addr: u64,
        signers_seeds_len: u64,
        memory_mapping: &MemoryMapping,
        invoke_context: &InvokeContext,
    ) -> Result<Vec<Pubkey>, Error>;
}

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

impl SyscallInvokeSigned for SyscallInvokeSignedRust {
    fn translate_instruction(
        addr: u64,
        memory_mapping: &MemoryMapping,
        invoke_context: &mut InvokeContext,
    ) -> Result<StableInstruction, Error> {
        let ix = translate_type::<StableInstruction>(
            memory_mapping,
            addr,
            invoke_context.get_check_aligned(),
        )?;
        let account_metas = translate_slice::<AccountMeta>(
            memory_mapping,
            ix.accounts.as_vaddr(),
            ix.accounts.len(),
            invoke_context.get_check_aligned(),
        )?;
        let data = translate_slice::<u8>(
            memory_mapping,
            ix.data.as_vaddr(),
            ix.data.len(),
            invoke_context.get_check_aligned(),
        )?
        .to_vec();

        check_instruction_size(account_metas.len(), data.len(), invoke_context)?;

        if invoke_context
            .get_feature_set()
            .is_active(&features::loosen_cpi_size_restriction::id())
        {
            consume_compute_meter(
                invoke_context,
                (data.len() as u64)
                    .checked_div(invoke_context.get_compute_budget().cpi_bytes_per_unit)
                    .unwrap_or(u64::MAX),
            )?;
        }

        let mut accounts = Vec::with_capacity(account_metas.len());
        #[allow(clippy::needless_range_loop)]
        for account_index in 0..account_metas.len() {
            #[allow(clippy::indexing_slicing)]
            let account_meta = &account_metas[account_index];
            if unsafe {
                std::ptr::read_volatile(&account_meta.is_signer as *const _ as *const u8) > 1
                    || std::ptr::read_volatile(&account_meta.is_writable as *const _ as *const u8)
                        > 1
            } {
                return Err(Box::new(InstructionError::InvalidArgument));
            }
            accounts.push(account_meta.clone());
        }

        Ok(StableInstruction {
            accounts: accounts.into(),
            data: data.into(),
            program_id: ix.program_id,
        })
    }

    fn translate_accounts<'a, 'b>(
        instruction_accounts: &[InstructionAccount],
        program_indices: &[IndexOfAccount],
        account_infos_addr: u64,
        account_infos_len: u64,
        is_loader_deprecated: bool,
        memory_mapping: &'b MemoryMapping<'a>,
        invoke_context: &mut InvokeContext,
    ) -> Result<TranslatedAccounts<'a, 'b>, Error> {
        let (account_infos, account_info_keys) = translate_account_infos(
            account_infos_addr,
            account_infos_len,
            |account_info: &AccountInfo| account_info.key as *const _ as u64,
            memory_mapping,
            invoke_context,
        )?;

        translate_and_update_accounts(
            instruction_accounts,
            program_indices,
            &account_info_keys,
            account_infos,
            account_infos_addr,
            is_loader_deprecated,
            invoke_context,
            memory_mapping,
            CallerAccount::from_account_info,
        )
    }

    fn translate_signers(
        program_id: &Pubkey,
        signers_seeds_addr: u64,
        signers_seeds_len: u64,
        memory_mapping: &MemoryMapping,
        invoke_context: &InvokeContext,
    ) -> Result<Vec<Pubkey>, Error> {
        let mut signers = Vec::new();
        if signers_seeds_len > 0 {
            let signers_seeds = translate_slice::<&[&[u8]]>(
                memory_mapping,
                signers_seeds_addr,
                signers_seeds_len,
                invoke_context.get_check_aligned(),
            )?;
            if signers_seeds.len() > MAX_SIGNERS {
                return Err(Box::new(SyscallError::TooManySigners));
            }
            for signer_seeds in signers_seeds.iter() {
                let untranslated_seeds = translate_slice::<&[u8]>(
                    memory_mapping,
                    signer_seeds.as_ptr() as *const _ as u64,
                    signer_seeds.len() as u64,
                    invoke_context.get_check_aligned(),
                )?;
                if untranslated_seeds.len() > MAX_SEEDS {
                    return Err(Box::new(InstructionError::MaxSeedLengthExceeded));
                }
                let seeds = untranslated_seeds
                    .iter()
                    .map(|untranslated_seed| {
                        translate_slice::<u8>(
                            memory_mapping,
                            untranslated_seed.as_ptr() as *const _ as u64,
                            untranslated_seed.len() as u64,
                            invoke_context.get_check_aligned(),
                        )
                    })
                    .collect::<Result<Vec<_>, Error>>()?;
                let signer = Pubkey::create_program_address(&seeds, program_id)
                    .map_err(SyscallError::BadSeeds)?;
                signers.push(signer);
            }
            Ok(signers)
        } else {
            Ok(vec![])
        }
    }
}

/// Rust representation of C's SolInstruction
#[derive(Debug)]
#[repr(C)]
struct SolInstruction {
    program_id_addr: u64,
    accounts_addr: u64,
    accounts_len: u64,
    data_addr: u64,
    data_len: u64,
}

/// Rust representation of C's SolAccountMeta
#[derive(Debug)]
#[repr(C)]
struct SolAccountMeta {
    pubkey_addr: u64,
    is_writable: bool,
    is_signer: bool,
}

/// Rust representation of C's SolAccountInfo
#[derive(Debug)]
#[repr(C)]
struct SolAccountInfo {
    key_addr: u64,
    lamports_addr: u64,
    data_len: u64,
    data_addr: u64,
    owner_addr: u64,
    rent_epoch: u64,
    is_signer: bool,
    is_writable: bool,
    executable: bool,
}

/// Rust representation of C's SolSignerSeed
#[derive(Debug)]
#[repr(C)]
struct SolSignerSeedC {
    addr: u64,
    len: u64,
}

/// Rust representation of C's SolSignerSeeds
#[derive(Debug)]
#[repr(C)]
struct SolSignerSeedsC {
    addr: u64,
    len: u64,
}

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

impl SyscallInvokeSigned for SyscallInvokeSignedC {
    fn translate_instruction(
        addr: u64,
        memory_mapping: &MemoryMapping,
        invoke_context: &mut InvokeContext,
    ) -> Result<StableInstruction, Error> {
        let ix_c = translate_type::<SolInstruction>(
            memory_mapping,
            addr,
            invoke_context.get_check_aligned(),
        )?;

        let program_id = translate_type::<Pubkey>(
            memory_mapping,
            ix_c.program_id_addr,
            invoke_context.get_check_aligned(),
        )?;
        let account_metas = translate_slice::<SolAccountMeta>(
            memory_mapping,
            ix_c.accounts_addr,
            ix_c.accounts_len,
            invoke_context.get_check_aligned(),
        )?;
        let data = translate_slice::<u8>(
            memory_mapping,
            ix_c.data_addr,
            ix_c.data_len,
            invoke_context.get_check_aligned(),
        )?
        .to_vec();

        check_instruction_size(ix_c.accounts_len as usize, data.len(), invoke_context)?;

        if invoke_context
            .get_feature_set()
            .is_active(&features::loosen_cpi_size_restriction::id())
        {
            consume_compute_meter(
                invoke_context,
                (data.len() as u64)
                    .checked_div(invoke_context.get_compute_budget().cpi_bytes_per_unit)
                    .unwrap_or(u64::MAX),
            )?;
        }

        let mut accounts = Vec::with_capacity(ix_c.accounts_len as usize);
        #[allow(clippy::needless_range_loop)]
        for account_index in 0..ix_c.accounts_len as usize {
            #[allow(clippy::indexing_slicing)]
            let account_meta = &account_metas[account_index];
            if unsafe {
                std::ptr::read_volatile(&account_meta.is_signer as *const _ as *const u8) > 1
                    || std::ptr::read_volatile(&account_meta.is_writable as *const _ as *const u8)
                        > 1
            } {
                return Err(Box::new(InstructionError::InvalidArgument));
            }
            let pubkey = translate_type::<Pubkey>(
                memory_mapping,
                account_meta.pubkey_addr,
                invoke_context.get_check_aligned(),
            )?;
            accounts.push(AccountMeta {
                pubkey: *pubkey,
                is_signer: account_meta.is_signer,
                is_writable: account_meta.is_writable,
            });
        }

        Ok(StableInstruction {
            accounts: accounts.into(),
            data: data.into(),
            program_id: *program_id,
        })
    }

    fn translate_accounts<'a, 'b>(
        instruction_accounts: &[InstructionAccount],
        program_indices: &[IndexOfAccount],
        account_infos_addr: u64,
        account_infos_len: u64,
        is_loader_deprecated: bool,
        memory_mapping: &'b MemoryMapping<'a>,
        invoke_context: &mut InvokeContext,
    ) -> Result<TranslatedAccounts<'a, 'b>, Error> {
        let (account_infos, account_info_keys) = translate_account_infos(
            account_infos_addr,
            account_infos_len,
            |account_info: &SolAccountInfo| account_info.key_addr,
            memory_mapping,
            invoke_context,
        )?;

        translate_and_update_accounts(
            instruction_accounts,
            program_indices,
            &account_info_keys,
            account_infos,
            account_infos_addr,
            is_loader_deprecated,
            invoke_context,
            memory_mapping,
            CallerAccount::from_sol_account_info,
        )
    }

    fn translate_signers(
        program_id: &Pubkey,
        signers_seeds_addr: u64,
        signers_seeds_len: u64,
        memory_mapping: &MemoryMapping,
        invoke_context: &InvokeContext,
    ) -> Result<Vec<Pubkey>, Error> {
        if signers_seeds_len > 0 {
            let signers_seeds = translate_slice::<SolSignerSeedsC>(
                memory_mapping,
                signers_seeds_addr,
                signers_seeds_len,
                invoke_context.get_check_aligned(),
            )?;
            if signers_seeds.len() > MAX_SIGNERS {
                return Err(Box::new(SyscallError::TooManySigners));
            }
            Ok(signers_seeds
                .iter()
                .map(|signer_seeds| {
                    let seeds = translate_slice::<SolSignerSeedC>(
                        memory_mapping,
                        signer_seeds.addr,
                        signer_seeds.len,
                        invoke_context.get_check_aligned(),
                    )?;
                    if seeds.len() > MAX_SEEDS {
                        return Err(Box::new(InstructionError::MaxSeedLengthExceeded) as Error);
                    }
                    let seeds_bytes = seeds
                        .iter()
                        .map(|seed| {
                            translate_slice::<u8>(
                                memory_mapping,
                                seed.addr,
                                seed.len,
                                invoke_context.get_check_aligned(),
                            )
                        })
                        .collect::<Result<Vec<_>, Error>>()?;
                    Pubkey::create_program_address(&seeds_bytes, program_id)
                        .map_err(|err| Box::new(SyscallError::BadSeeds(err)) as Error)
                })
                .collect::<Result<Vec<_>, Error>>()?)
        } else {
            Ok(vec![])
        }
    }
}

fn translate_account_infos<'a, T, F>(
    account_infos_addr: u64,
    account_infos_len: u64,
    key_addr: F,
    memory_mapping: &MemoryMapping,
    invoke_context: &mut InvokeContext,
) -> Result<(&'a [T], Vec<&'a Pubkey>), Error>
where
    F: Fn(&T) -> u64,
{
    let direct_mapping = invoke_context
        .get_feature_set()
        .is_active(&features::bpf_account_data_direct_mapping::id());

    // In the same vein as the other check_account_info_pointer() checks, we don't lock
    // this pointer to a specific address but we don't want it to be inside accounts, or
    // callees might be able to write to the pointed memory.
    if direct_mapping
        && account_infos_addr
            .saturating_add(account_infos_len.saturating_mul(std::mem::size_of::<T>() as u64))
            >= ebpf::MM_INPUT_START
    {
        return Err(SyscallError::InvalidPointer.into());
    }

    let account_infos = translate_slice::<T>(
        memory_mapping,
        account_infos_addr,
        account_infos_len,
        invoke_context.get_check_aligned(),
    )?;
    check_account_infos(account_infos.len(), invoke_context)?;
    let mut account_info_keys = Vec::with_capacity(account_infos_len as usize);
    #[allow(clippy::needless_range_loop)]
    for account_index in 0..account_infos_len as usize {
        #[allow(clippy::indexing_slicing)]
        let account_info = &account_infos[account_index];
        account_info_keys.push(translate_type::<Pubkey>(
            memory_mapping,
            key_addr(account_info),
            invoke_context.get_check_aligned(),
        )?);
    }
    Ok((account_infos, account_info_keys))
}

// Finish translating accounts, build CallerAccount values and update callee
// accounts in preparation of executing the callee.
fn translate_and_update_accounts<'a, 'b, T, F>(
    instruction_accounts: &[InstructionAccount],
    program_indices: &[IndexOfAccount],
    account_info_keys: &[&Pubkey],
    account_infos: &[T],
    account_infos_addr: u64,
    is_loader_deprecated: bool,
    invoke_context: &mut InvokeContext,
    memory_mapping: &'b MemoryMapping<'a>,
    do_translate: F,
) -> Result<TranslatedAccounts<'a, 'b>, Error>
where
    F: Fn(
        &InvokeContext,
        &'b MemoryMapping<'a>,
        u64,
        &T,
        &SerializedAccountMetadata,
    ) -> Result<CallerAccount<'a, 'b>, Error>,
{
    let transaction_context = &invoke_context.transaction_context;
    let instruction_context = transaction_context.get_current_instruction_context()?;
    let mut accounts = Vec::with_capacity(instruction_accounts.len().saturating_add(1));

    let program_account_index = program_indices
        .last()
        .ok_or_else(|| Box::new(InstructionError::MissingAccount))?;
    accounts.push((*program_account_index, None));

    // unwrapping here is fine: we're in a syscall and the method below fails
    // only outside syscalls
    let accounts_metadata = &invoke_context
        .get_syscall_context()
        .unwrap()
        .accounts_metadata;

    let direct_mapping = invoke_context
        .get_feature_set()
        .is_active(&features::bpf_account_data_direct_mapping::id());

    for (instruction_account_index, instruction_account) in instruction_accounts.iter().enumerate()
    {
        if instruction_account_index as IndexOfAccount != instruction_account.index_in_callee {
            continue; // Skip duplicate account
        }

        let callee_account = instruction_context.try_borrow_instruction_account(
            transaction_context,
            instruction_account.index_in_caller,
        )?;
        let account_key = invoke_context
            .transaction_context
            .get_key_of_account_at_index(instruction_account.index_in_transaction)?;

        #[allow(deprecated)]
        if callee_account.is_executable() {
            // Use the known account
            consume_compute_meter(
                invoke_context,
                (callee_account.get_data().len() as u64)
                    .checked_div(invoke_context.get_compute_budget().cpi_bytes_per_unit)
                    .unwrap_or(u64::MAX),
            )?;

            accounts.push((instruction_account.index_in_caller, None));
        } else if let Some(caller_account_index) =
            account_info_keys.iter().position(|key| *key == account_key)
        {
            let serialized_metadata = accounts_metadata
                .get(instruction_account.index_in_caller as usize)
                .ok_or_else(|| {
                    ic_msg!(
                        invoke_context,
                        "Internal error: index mismatch for account {}",
                        account_key
                    );
                    Box::new(InstructionError::MissingAccount)
                })?;

            // build the CallerAccount corresponding to this account.
            if caller_account_index >= account_infos.len() {
                return Err(Box::new(SyscallError::InvalidLength));
            }
            #[allow(clippy::indexing_slicing)]
            let caller_account =
                do_translate(
                    invoke_context,
                    memory_mapping,
                    account_infos_addr.saturating_add(
                        caller_account_index.saturating_mul(mem::size_of::<T>()) as u64,
                    ),
                    &account_infos[caller_account_index],
                    serialized_metadata,
                )?;

            // before initiating CPI, the caller may have modified the
            // account (caller_account). We need to update the corresponding
            // BorrowedAccount (callee_account) so the callee can see the
            // changes.
            let update_caller = update_callee_account(
                invoke_context,
                memory_mapping,
                is_loader_deprecated,
                &caller_account,
                callee_account,
                direct_mapping,
            )?;

            let caller_account = if instruction_account.is_writable || update_caller {
                Some(caller_account)
            } else {
                None
            };
            accounts.push((instruction_account.index_in_caller, caller_account));
        } else {
            ic_msg!(
                invoke_context,
                "Instruction references an unknown account {}",
                account_key
            );
            return Err(Box::new(InstructionError::MissingAccount));
        }
    }

    Ok(accounts)
}

fn check_instruction_size(
    num_accounts: usize,
    data_len: usize,
    invoke_context: &mut InvokeContext,
) -> Result<(), Error> {
    if invoke_context
        .get_feature_set()
        .is_active(&features::loosen_cpi_size_restriction::id())
    {
        let data_len = data_len as u64;
        let max_data_len = MAX_CPI_INSTRUCTION_DATA_LEN;
        if data_len > max_data_len {
            return Err(Box::new(SyscallError::MaxInstructionDataLenExceeded {
                data_len,
                max_data_len,
            }));
        }

        let num_accounts = num_accounts as u64;
        let max_accounts = MAX_CPI_INSTRUCTION_ACCOUNTS as u64;
        if num_accounts > max_accounts {
            return Err(Box::new(SyscallError::MaxInstructionAccountsExceeded {
                num_accounts,
                max_accounts,
            }));
        }
    } else {
        let max_size = invoke_context.get_compute_budget().max_cpi_instruction_size;
        let size = num_accounts
            .saturating_mul(size_of::<AccountMeta>())
            .saturating_add(data_len);
        if size > max_size {
            return Err(Box::new(SyscallError::InstructionTooLarge(size, max_size)));
        }
    }
    Ok(())
}

fn check_account_infos(
    num_account_infos: usize,
    invoke_context: &mut InvokeContext,
) -> Result<(), Error> {
    if invoke_context
        .get_feature_set()
        .is_active(&features::loosen_cpi_size_restriction::id())
    {
        let max_cpi_account_infos = if invoke_context
            .get_feature_set()
            .is_active(&features::increase_tx_account_lock_limit::id())
        {
            MAX_CPI_ACCOUNT_INFOS
        } else {
            64
        };
        let num_account_infos = num_account_infos as u64;
        let max_account_infos = max_cpi_account_infos as u64;
        if num_account_infos > max_account_infos {
            return Err(Box::new(SyscallError::MaxInstructionAccountInfosExceeded {
                num_account_infos,
                max_account_infos,
            }));
        }
    } else {
        let adjusted_len = num_account_infos.saturating_mul(size_of::<Pubkey>());

        if adjusted_len > invoke_context.get_compute_budget().max_cpi_instruction_size {
            // Cap the number of account_infos a caller can pass to approximate
            // maximum that accounts that could be passed in an instruction
            return Err(Box::new(SyscallError::TooManyAccounts));
        };
    }
    Ok(())
}

fn check_authorized_program(
    program_id: &Pubkey,
    instruction_data: &[u8],
    invoke_context: &InvokeContext,
) -> Result<(), Error> {
    if native_loader::check_id(program_id)
        || bpf_loader::check_id(program_id)
        || bpf_loader_deprecated::check_id(program_id)
        || (bpf_loader_upgradeable::check_id(program_id)
            && !(bpf_loader_upgradeable::is_upgrade_instruction(instruction_data)
                || bpf_loader_upgradeable::is_set_authority_instruction(instruction_data)
                || (invoke_context
                    .get_feature_set()
                    .is_active(&enable_bpf_loader_set_authority_checked_ix::id())
                    && bpf_loader_upgradeable::is_set_authority_checked_instruction(
                        instruction_data,
                    ))
                || bpf_loader_upgradeable::is_close_instruction(instruction_data)))
        || is_precompile(program_id, |feature_id: &Pubkey| {
            invoke_context.get_feature_set().is_active(feature_id)
        })
    {
        return Err(Box::new(SyscallError::ProgramNotSupported(*program_id)));
    }
    Ok(())
}

pub fn is_precompile<F>(program_id: &Pubkey, is_enabled: F) -> bool
where
    F: Fn(&Pubkey) -> bool,
{
    PRECOMPILES
        .iter()
        .any(|precompile| precompile.check_id(program_id, |feature_id| is_enabled(feature_id)))
}

/// Call process instruction, common to both Rust and C
pub fn cpi_common<S: SyscallInvokeSigned>(
    invoke_context: &mut InvokeContext,
    instruction_addr: u64,
    account_infos_addr: u64,
    account_infos_len: u64,
    signers_seeds_addr: u64,
    signers_seeds_len: u64,
    memory_mapping: &MemoryMapping,
) -> Result<u64, Error> {
    // CPI entry.
    //
    // Translate the inputs to the syscall and synchronize the caller's account
    // changes so the callee can see them.
    consume_compute_meter(
        invoke_context,
        invoke_context.get_compute_budget().invoke_units,
    )?;
    if let Some(execute_time) = invoke_context.execute_time.as_mut() {
        execute_time.stop();
        invoke_context.timings.execute_us += execute_time.as_us();
    }

    let instruction = S::translate_instruction(instruction_addr, memory_mapping, invoke_context)?;
    let transaction_context = &invoke_context.transaction_context;
    let instruction_context = transaction_context.get_current_instruction_context()?;
    let caller_program_id = instruction_context.get_last_program_key(transaction_context)?;
    let signers = S::translate_signers(
        caller_program_id,
        signers_seeds_addr,
        signers_seeds_len,
        memory_mapping,
        invoke_context,
    )?;
    let is_loader_deprecated = *instruction_context
        .try_borrow_last_program_account(transaction_context)?
        .get_owner()
        == bpf_loader_deprecated::id();
    let (instruction_accounts, program_indices) =
        invoke_context.prepare_instruction(&instruction, &signers)?;
    check_authorized_program(&instruction.program_id, &instruction.data, invoke_context)?;

    let mut accounts = S::translate_accounts(
        &instruction_accounts,
        &program_indices,
        account_infos_addr,
        account_infos_len,
        is_loader_deprecated,
        memory_mapping,
        invoke_context,
    )?;

    // Process the callee instruction
    let mut compute_units_consumed = 0;
    invoke_context.process_instruction(
        &instruction.data,
        &instruction_accounts,
        &program_indices,
        &mut compute_units_consumed,
        &mut crate::ExecuteTimings::default(),
    )?;

    // re-bind to please the borrow checker
    let transaction_context = &invoke_context.transaction_context;
    let instruction_context = transaction_context.get_current_instruction_context()?;

    // CPI exit.
    //
    // Synchronize the callee's account changes so the caller can see them.
    let direct_mapping = invoke_context
        .get_feature_set()
        .is_active(&features::bpf_account_data_direct_mapping::id());

    if direct_mapping {
        // Update all perms at once before doing account data updates. This
        // isn't strictly required as we forbid updates to an account to touch
        // other accounts, but since we did have bugs around this in the past,
        // it's better to be safe than sorry.
        for (index_in_caller, caller_account) in accounts.iter() {
            if let Some(caller_account) = caller_account {
                let callee_account = instruction_context
                    .try_borrow_instruction_account(transaction_context, *index_in_caller)?;
                update_caller_account_perms(
                    memory_mapping,
                    caller_account,
                    &callee_account,
                    is_loader_deprecated,
                )?;
            }
        }
    }

    for (index_in_caller, caller_account) in accounts.iter_mut() {
        if let Some(caller_account) = caller_account {
            let mut callee_account = instruction_context
                .try_borrow_instruction_account(transaction_context, *index_in_caller)?;
            update_caller_account(
                invoke_context,
                memory_mapping,
                is_loader_deprecated,
                caller_account,
                &mut callee_account,
                direct_mapping,
            )?;
        }
    }

    invoke_context.execute_time = Some(Measure::start("execute"));
    Ok(SUCCESS)
}

// Update the given account before executing CPI.
//
// caller_account and callee_account describe the same account. At CPI entry
// caller_account might include changes the caller has made to the account
// before executing CPI.
//
// This method updates callee_account so the CPI callee can see the caller's
// changes.
//
// When true is returned, the caller account must be updated after CPI. This
// is only set for direct mapping when the pointer may have changed.
fn update_callee_account(
    invoke_context: &InvokeContext,
    memory_mapping: &MemoryMapping,
    is_loader_deprecated: bool,
    caller_account: &CallerAccount,
    mut callee_account: BorrowedAccount<'_>,
    direct_mapping: bool,
) -> Result<bool, Error> {
    let mut must_update_caller = false;

    if callee_account.get_lamports() != *caller_account.lamports {
        callee_account.set_lamports(*caller_account.lamports)?;
    }

    if direct_mapping {
        let prev_len = callee_account.get_data().len();
        let post_len = *caller_account.ref_to_len_in_vm.get()? as usize;
        match callee_account
            .can_data_be_resized(post_len)
            .and_then(|_| callee_account.can_data_be_changed())
        {
            Ok(()) => {
                let realloc_bytes_used = post_len.saturating_sub(caller_account.original_data_len);
                // bpf_loader_deprecated programs don't have a realloc region
                if is_loader_deprecated && realloc_bytes_used > 0 {
                    return Err(InstructionError::InvalidRealloc.into());
                }
                if prev_len != post_len {
                    callee_account.set_data_length(post_len)?;
                    // pointer to data may have changed, so caller must be updated
                    must_update_caller = true;
                }
                if realloc_bytes_used > 0 {
                    let serialized_data = translate_slice::<u8>(
                        memory_mapping,
                        caller_account
                            .vm_data_addr
                            .saturating_add(caller_account.original_data_len as u64),
                        realloc_bytes_used as u64,
                        invoke_context.get_check_aligned(),
                    )?;
                    callee_account
                        .get_data_mut()?
                        .get_mut(caller_account.original_data_len..post_len)
                        .ok_or(SyscallError::InvalidLength)?
                        .copy_from_slice(serialized_data);
                }
            }
            Err(err) if prev_len != post_len => {
                return Err(Box::new(err));
            }
            _ => {}
        }
    } else {
        // The redundant check helps to avoid the expensive data comparison if we can
        match callee_account
            .can_data_be_resized(caller_account.serialized_data.len())
            .and_then(|_| callee_account.can_data_be_changed())
        {
            Ok(()) => callee_account.set_data_from_slice(caller_account.serialized_data)?,
            Err(err) if callee_account.get_data() != caller_account.serialized_data => {
                return Err(Box::new(err));
            }
            _ => {}
        }
    }

    // Change the owner at the end so that we are allowed to change the lamports and data before
    if callee_account.get_owner() != caller_account.owner {
        callee_account.set_owner(caller_account.owner.as_ref())?;
    }

    Ok(must_update_caller)
}

pub(crate) fn account_data_region_memory_state(account: &BorrowedAccount<'_>) -> MemoryState {
    if account.can_data_be_changed().is_ok() {
        if account.is_shared() {
            MemoryState::Cow(account.get_index_in_transaction() as u64)
        } else {
            MemoryState::Writable
        }
    } else {
        MemoryState::Readable
    }
}

fn update_caller_account_perms(
    memory_mapping: &MemoryMapping,
    caller_account: &CallerAccount,
    callee_account: &BorrowedAccount<'_>,
    is_loader_deprecated: bool,
) -> Result<(), Error> {
    let CallerAccount {
        original_data_len,
        vm_data_addr,
        ..
    } = caller_account;

    let data_region = account_data_region(memory_mapping, *vm_data_addr, *original_data_len)?;
    if let Some(region) = data_region {
        region
            .state
            .set(account_data_region_memory_state(callee_account));
    }
    let realloc_region = account_realloc_region(
        memory_mapping,
        *vm_data_addr,
        *original_data_len,
        is_loader_deprecated,
    )?;
    if let Some(region) = realloc_region {
        region
            .state
            .set(if callee_account.can_data_be_changed().is_ok() {
                MemoryState::Writable
            } else {
                MemoryState::Readable
            });
    }

    Ok(())
}

// Update the given account after executing CPI.
//
// caller_account and callee_account describe to the same account. At CPI exit
// callee_account might include changes the callee has made to the account
// after executing.
//
// This method updates caller_account so the CPI caller can see the callee's
// changes.
fn update_caller_account(
    invoke_context: &InvokeContext,
    memory_mapping: &MemoryMapping,
    is_loader_deprecated: bool,
    caller_account: &mut CallerAccount,
    callee_account: &mut BorrowedAccount<'_>,
    direct_mapping: bool,
) -> Result<(), Error> {
    *caller_account.lamports = callee_account.get_lamports();
    *caller_account.owner = *callee_account.get_owner();

    let mut zero_all_mapped_spare_capacity = false;
    if direct_mapping {
        if let Some(region) = account_data_region(
            memory_mapping,
            caller_account.vm_data_addr,
            caller_account.original_data_len,
        )? {
            // Since each instruction account is directly mapped in a memory region with a *fixed*
            // length, upon returning from CPI we must ensure that the current capacity is at least
            // the original length (what is mapped in memory), so that the account's memory region
            // never points to an invalid address.
            //
            // Note that the capacity can be smaller than the original length only if the account is
            // reallocated using the AccountSharedData API directly (deprecated) or using
            // BorrowedAccount::set_data_from_slice(), which implements an optimization to avoid an
            // extra allocation.
            let min_capacity = caller_account.original_data_len;
            if callee_account.capacity() < min_capacity {
                callee_account
                    .reserve(min_capacity.saturating_sub(callee_account.get_data().len()))?;
                zero_all_mapped_spare_capacity = true;
            }

            // If an account's data pointer has changed we must update the corresponding
            // MemoryRegion in the caller's address space. Address spaces are fixed so we don't need
            // to update the MemoryRegion's length.
            //
            // An account's data pointer can change if the account is reallocated because of CoW,
            // because of BorrowedAccount::make_data_mut or by a program that uses the
            // AccountSharedData API directly (deprecated).
            let callee_ptr = callee_account.get_data().as_ptr() as u64;
            if region.host_addr.get() != callee_ptr {
                region.host_addr.set(callee_ptr);
                zero_all_mapped_spare_capacity = true;
            }
        }
    }

    let prev_len = *caller_account.ref_to_len_in_vm.get()? as usize;
    let post_len = callee_account.get_data().len();
    if prev_len != post_len {
        let max_increase = if direct_mapping && !invoke_context.get_check_aligned() {
            0
        } else {
            MAX_PERMITTED_DATA_INCREASE
        };
        let data_overflow = post_len
            > caller_account
                .original_data_len
                .saturating_add(max_increase);
        if data_overflow {
            ic_msg!(
                invoke_context,
                "Account data size realloc limited to {max_increase} in inner instructions",
            );
            return Err(Box::new(InstructionError::InvalidRealloc));
        }

        // If the account has been shrunk, we're going to zero the unused memory
        // *that was previously used*.
        if post_len < prev_len {
            if direct_mapping {
                // We have two separate regions to zero out: the account data
                // and the realloc region. Here we zero the realloc region, the
                // data region is zeroed further down below.
                //
                // This is done for compatibility but really only necessary for
                // the fringe case of a program calling itself, see
                // TEST_CPI_ACCOUNT_UPDATE_CALLER_GROWS_CALLEE_SHRINKS.
                //
                // Zeroing the realloc region isn't necessary in the normal
                // invoke case because consider the following scenario:
                //
                // 1. Caller grows an account (prev_len > original_data_len)
                // 2. Caller assigns the account to the callee (needed for 3 to
                //    work)
                // 3. Callee shrinks the account (post_len < prev_len)
                //
                // In order for the caller to assign the account to the callee,
                // the caller _must_ either set the account length to zero,
                // therefore making prev_len > original_data_len impossible,
                // or it must zero the account data, therefore making the
                // zeroing we do here redundant.
                if prev_len > caller_account.original_data_len {
                    // If we get here and prev_len > original_data_len, then
                    // we've already returned InvalidRealloc for the
                    // bpf_loader_deprecated case.
                    debug_assert!(!is_loader_deprecated);

                    // Temporarily configure the realloc region as writable then set it back to
                    // whatever state it had.
                    let realloc_region = caller_account
                        .realloc_region(memory_mapping, is_loader_deprecated)?
                        .unwrap(); // unwrapping here is fine, we already asserted !is_loader_deprecated
                    let original_state = realloc_region.state.replace(MemoryState::Writable);
                    defer! {
                        realloc_region.state.set(original_state);
                    };

                    // We need to zero the unused space in the realloc region, starting after the
                    // last byte of the new data which might be > original_data_len.
                    let dirty_realloc_start = caller_account.original_data_len.max(post_len);
                    // and we want to zero up to the old length
                    let dirty_realloc_len = prev_len.saturating_sub(dirty_realloc_start);
                    let serialized_data = translate_slice_mut::<u8>(
                        memory_mapping,
                        caller_account
                            .vm_data_addr
                            .saturating_add(dirty_realloc_start as u64),
                        dirty_realloc_len as u64,
                        invoke_context.get_check_aligned(),
                    )?;
                    serialized_data.fill(0);
                }
            } else {
                caller_account
                    .serialized_data
                    .get_mut(post_len..)
                    .ok_or_else(|| Box::new(InstructionError::AccountDataTooSmall))?
                    .fill(0);
            }
        }

        // when direct mapping is enabled we don't cache the serialized data in
        // caller_account.serialized_data. See CallerAccount::from_account_info.
        if !direct_mapping {
            caller_account.serialized_data = translate_slice_mut::<u8>(
                memory_mapping,
                caller_account.vm_data_addr,
                post_len as u64,
                false, // Don't care since it is byte aligned
            )?;
        }
        // this is the len field in the AccountInfo::data slice
        *caller_account.ref_to_len_in_vm.get_mut()? = post_len as u64;

        // this is the len field in the serialized parameters
        let serialized_len_ptr = translate_type_mut::<u64>(
            memory_mapping,
            caller_account
                .vm_data_addr
                .saturating_sub(std::mem::size_of::<u64>() as u64),
            invoke_context.get_check_aligned(),
        )?;
        *serialized_len_ptr = post_len as u64;
    }

    if direct_mapping {
        // Here we zero the account data region.
        //
        // If zero_all_mapped_spare_capacity=true, we need to zero regardless of whether the account
        // size changed, because the underlying vector holding the account might have been
        // reallocated and contain uninitialized memory in the spare capacity.
        //
        // See TEST_CPI_CHANGE_ACCOUNT_DATA_MEMORY_ALLOCATION for an example of
        // this case.
        let spare_len = if zero_all_mapped_spare_capacity {
            // In the unlikely case where the account data vector has
            // changed - which can happen during CoW - we zero the whole
            // extra capacity up to the original data length.
            //
            // The extra capacity up to original data length is
            // accessible from the vm and since it's uninitialized
            // memory, it could be a source of non determinism.
            caller_account.original_data_len
        } else {
            // If the allocation has not changed, we only zero the
            // difference between the previous and current lengths. The
            // rest of the memory contains whatever it contained before,
            // which is deterministic.
            prev_len
        }
        .saturating_sub(post_len);

        if spare_len > 0 {
            let dst = callee_account
                .spare_data_capacity_mut()?
                .get_mut(..spare_len)
                .ok_or_else(|| Box::new(InstructionError::AccountDataTooSmall))?
                .as_mut_ptr();
            // Safety: we check bounds above
            unsafe { ptr::write_bytes(dst, 0, spare_len) };
        }

        // Propagate changes to the realloc region in the callee up to the caller.
        let realloc_bytes_used = post_len.saturating_sub(caller_account.original_data_len);
        if realloc_bytes_used > 0 {
            // In the is_loader_deprecated case, we must have failed with
            // InvalidRealloc by now.
            debug_assert!(!is_loader_deprecated);

            let to_slice = {
                // If a callee reallocs an account, we write into the caller's
                // realloc region regardless of whether the caller has write
                // permissions to the account or not. If the callee has been able to
                // make changes, it means they had permissions to do so, and here
                // we're just going to reflect those changes to the caller's frame.
                //
                // Therefore we temporarily configure the realloc region as writable
                // then set it back to whatever state it had.
                let realloc_region = caller_account
                    .realloc_region(memory_mapping, is_loader_deprecated)?
                    .unwrap(); // unwrapping here is fine, we asserted !is_loader_deprecated
                let original_state = realloc_region.state.replace(MemoryState::Writable);
                defer! {
                    realloc_region.state.set(original_state);
                };

                translate_slice_mut::<u8>(
                    memory_mapping,
                    caller_account
                        .vm_data_addr
                        .saturating_add(caller_account.original_data_len as u64),
                    realloc_bytes_used as u64,
                    invoke_context.get_check_aligned(),
                )?
            };
            let from_slice = callee_account
                .get_data()
                .get(caller_account.original_data_len..post_len)
                .ok_or(SyscallError::InvalidLength)?;
            if to_slice.len() != from_slice.len() {
                return Err(Box::new(InstructionError::AccountDataTooSmall));
            }
            to_slice.copy_from_slice(from_slice);
        }
    } else {
        let to_slice = &mut caller_account.serialized_data;
        let from_slice = callee_account
            .get_data()
            .get(0..post_len)
            .ok_or(SyscallError::InvalidLength)?;
        if to_slice.len() != from_slice.len() {
            return Err(Box::new(InstructionError::AccountDataTooSmall));
        }
        to_slice.copy_from_slice(from_slice);
    }

    Ok(())
}

fn account_data_region<'a>(
    memory_mapping: &'a MemoryMapping<'_>,
    vm_data_addr: u64,
    original_data_len: usize,
) -> Result<Option<&'a MemoryRegion>, Error> {
    if original_data_len == 0 {
        return Ok(None);
    }

    // We can trust vm_data_addr to point to the correct region because we
    // enforce that in CallerAccount::from_(sol_)account_info.
    let data_region = memory_mapping.region(AccessType::Load, vm_data_addr)?;
    // vm_data_addr must always point to the beginning of the region
    debug_assert_eq!(data_region.vm_addr, vm_data_addr);
    Ok(Some(data_region))
}

fn account_realloc_region<'a>(
    memory_mapping: &'a MemoryMapping<'_>,
    vm_data_addr: u64,
    original_data_len: usize,
    is_loader_deprecated: bool,
) -> Result<Option<&'a MemoryRegion>, Error> {
    if is_loader_deprecated {
        return Ok(None);
    }

    let realloc_vm_addr = vm_data_addr.saturating_add(original_data_len as u64);
    let realloc_region = memory_mapping.region(AccessType::Load, realloc_vm_addr)?;
    debug_assert_eq!(realloc_region.vm_addr, realloc_vm_addr);
    debug_assert!((MAX_PERMITTED_DATA_INCREASE
        ..MAX_PERMITTED_DATA_INCREASE.saturating_add(BPF_ALIGN_OF_U128))
        .contains(&(realloc_region.len as usize)));
    debug_assert!(!matches!(realloc_region.state.get(), MemoryState::Cow(_)));
    Ok(Some(realloc_region))
}
