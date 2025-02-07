use std::{collections::HashMap, num::Saturating};

use enum_iterator::Sequence;

use crate::Pubkey;

#[derive(Default, Debug, PartialEq, Eq)]
pub struct ProgramTiming {
    pub accumulated_us: Saturating<u64>,
    pub accumulated_units: Saturating<u64>,
    pub count: Saturating<u32>,
    pub errored_txs_compute_consumed: Vec<u64>,
    // Sum of all units in `errored_txs_compute_consumed`
    pub total_errored_units: Saturating<u64>,
}

impl ProgramTiming {
    pub fn coalesce_error_timings(&mut self, current_estimated_program_cost: u64) {
        for tx_error_compute_consumed in self.errored_txs_compute_consumed.drain(..) {
            let compute_units_update =
                std::cmp::max(current_estimated_program_cost, tx_error_compute_consumed);
            self.accumulated_units += compute_units_update;
            self.count += 1;
        }
    }

    pub fn accumulate_program_timings(&mut self, other: &ProgramTiming) {
        self.accumulated_us += other.accumulated_us;
        self.accumulated_units += other.accumulated_units;
        self.count += other.count;
        // Clones the entire vector, maybe not great...
        self.errored_txs_compute_consumed
            .extend(other.errored_txs_compute_consumed.clone());
        self.total_errored_units += other.total_errored_units;
    }
}

/// Used as an index for `Metrics`.
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

#[derive(Default, Debug, PartialEq, Eq)]
pub struct ExecuteDetailsTimings {
    pub serialize_us: Saturating<u64>,
    pub create_vm_us: Saturating<u64>,
    pub execute_us: Saturating<u64>,
    pub deserialize_us: Saturating<u64>,
    pub get_or_create_executor_us: Saturating<u64>,
    pub changed_account_count: Saturating<u64>,
    pub total_account_count: Saturating<u64>,
    pub create_executor_register_syscalls_us: Saturating<u64>,
    pub create_executor_load_elf_us: Saturating<u64>,
    pub create_executor_verify_code_us: Saturating<u64>,
    pub create_executor_jit_compile_us: Saturating<u64>,
    pub per_program_timings: HashMap<Pubkey, ProgramTiming>,
}

impl ExecuteDetailsTimings {
    pub fn accumulate(&mut self, other: &ExecuteDetailsTimings) {
        self.serialize_us += other.serialize_us;
        self.create_vm_us += other.create_vm_us;
        self.execute_us += other.execute_us;
        self.deserialize_us += other.deserialize_us;
        self.get_or_create_executor_us += other.get_or_create_executor_us;
        self.changed_account_count += other.changed_account_count;
        self.total_account_count += other.total_account_count;
        self.create_executor_register_syscalls_us += other.create_executor_register_syscalls_us;
        self.create_executor_load_elf_us += other.create_executor_load_elf_us;
        self.create_executor_verify_code_us += other.create_executor_verify_code_us;
        self.create_executor_jit_compile_us += other.create_executor_jit_compile_us;
        for (id, other) in &other.per_program_timings {
            let program_timing = self.per_program_timings.entry(*id).or_default();
            program_timing.accumulate_program_timings(other);
        }
    }

    pub fn accumulate_program(
        &mut self,
        program_id: &Pubkey,
        us: u64,
        compute_units_consumed: u64,
        is_error: bool,
    ) {
        let program_timing = self.per_program_timings.entry(*program_id).or_default();
        program_timing.accumulated_us += us;
        if is_error {
            program_timing
                .errored_txs_compute_consumed
                .push(compute_units_consumed);
            program_timing.total_errored_units += compute_units_consumed;
        } else {
            program_timing.accumulated_units += compute_units_consumed;
            program_timing.count += 1;
        };
    }
}
