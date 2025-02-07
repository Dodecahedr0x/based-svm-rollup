use std::{
    cmp::Ordering,
    collections::{HashMap, HashSet},
    fmt,
    sync::Arc,
};

use lazy_static::lazy_static;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{AccountInfo, Epoch, InstructionError, Pubkey, Slot};

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

pub mod deprecate_rewards_sysvar {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("GaBtBJvmS4Arjj5W1NmFcyvPjsHN38UGYDq2MDwbs9Qu")
    }
}

pub mod pico_inflation {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("4RWNif6C2WCNiKVW7otP4G7dkmkHGyKQWRpuZ1pxKU5m")
    }
}

pub mod full_inflation {
    pub mod devnet_and_testnet {
        use crate::{pubkey_from_str, Pubkey};
        pub fn id() -> Pubkey {
            pubkey_from_str("DT4n6ABDqs6w4bnfwrXT9rsprcPf6cdDga1egctaPkLC")
        }
    }

    pub mod mainnet {
        pub mod certusone {
            pub mod vote {
                use crate::{pubkey_from_str, Pubkey};
                pub fn id() -> Pubkey {
                    pubkey_from_str("BzBBveUDymEYoYzcMWNQCx3cd4jQs7puaVFHLtsbB6fm")
                }
            }
            pub mod enable {
                use crate::{pubkey_from_str, Pubkey};
                pub fn id() -> Pubkey {
                    pubkey_from_str("7XRJcS5Ud5vxGB54JbK9N2vBZVwnwdBNeJW1ibRgD9gx")
                }
            }
        }
    }
}

pub mod secp256k1_program_enabled {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("E3PHP7w8kB7np3CTQ1qQ2tW3KCtjRSXBQgW9vM2mWv2Y")
    }
}

pub mod spl_token_v2_multisig_fix {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("E5JiFDQCwyC6QfT9REFyMpfK2mHcmv1GUDySU1Ue7TYv")
    }
}

pub mod no_overflow_rent_distribution {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("4kpdyrcj5jS47CZb2oJGfVxjYbsMm2Kx97gFyZrxxwXz")
    }
}

pub mod filter_stake_delegation_accounts {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("GE7fRxmW46K6EmCD9AMZSbnaJ2e3LfqCZzdHi9hmYAgi")
    }
}

pub mod require_custodian_for_locked_stake_authorize {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("D4jsDcXaqdW8tDAWn8H4R25Cdns2YwLneujSL1zvjW6R")
    }
}

pub mod spl_token_v2_self_transfer_fix {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("BL99GYhdjjcv6ys22C9wPgn2aTVERDbPHHo4NbS3hgp7")
    }
}

pub mod warp_timestamp_again {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("GvDsGDkH5gyzwpDhxNixx8vtx1kwYHH13RiNAPw27zXb")
    }
}

pub mod check_init_vote_data {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("3ccR6QpxGYsAbWyfevEtBNGfWV4xBffxRj2tD6A9i39F")
    }
}

pub mod secp256k1_recover_syscall_enabled {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("6RvdSWHh8oh72Dp7wMTS2DBkf3fRPtChfNrAo3cZZoXJ")
    }
}

pub mod system_transfer_zero_check {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("BrTR9hzw4WBGFP65AJMbpAo64DcA3U6jdPSga9fMV5cS")
    }
}

pub mod blake3_syscall_enabled {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("HTW2pSyErTj4BV6KBM9NZ9VBUJVxt7sacNWcf76wtzb3")
    }
}

pub mod dedupe_config_program_signers {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("8kEuAshXLsgkUEdcFVLqrjCGGHVWFW99ZZpxvAzzMtBp")
    }
}

pub mod verify_tx_signatures_len {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("EVW9B5xD9FFK7vw1SBARwMA4s5eRo5eKJdKpsBikzKBz")
    }
}

pub mod vote_stake_checked_instructions {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("BcWknVcgvonN8sL4HE4XFuEVgfcee5MwxWPAgP6ZV89X")
    }
}

pub mod rent_for_sysvars {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("BKCPBQQBZqggVnFso5nQ8rQ4RwwogYwjuUt9biBjxwNF")
    }
}

pub mod libsecp256k1_0_5_upgrade_enabled {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("DhsYfRjxfnh2g7HKJYSzT79r74Afa1wbHkAgHndrA1oy")
    }
}

pub mod tx_wide_compute_cap {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("5ekBxc8itEnPv4NzGJtr8BVVQLNMQuLMNQQj7pHoLNZ9")
    }
}

pub mod spl_token_v2_set_authority_fix {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("FToKNBYyiF4ky9s8WsmLBXHCht17Ek7RXaLZGHzzQhJ1")
    }
}

pub mod merge_nonce_error_into_system_error {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("21AWDosvp3pBamFW91KB35pNoaoZVTM7ess8nr2nt53B")
    }
}

pub mod disable_fees_sysvar {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("JAN1trEUEtZjgXYzNBYHU9DYd7GnThhXfFP7SzPXkPsG")
    }
}

pub mod stake_merge_with_unmatched_credits_observed {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("meRgp4ArRPhD3KtCY9c5yAf2med7mBLsjKTPeVUHqBL")
    }
}

pub mod zk_token_sdk_enabled {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("zk1snxsc6Fh3wsGNbbHAJNHiJoYgF29mMnTSusGx5EJ")
    }
}

pub mod curve25519_syscall_enabled {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("7rcw5UtqgDTBBv2EcynNfYckgdAaH1MAsCjKgXMkN7Ri")
    }
}

pub mod curve25519_restrict_msm_length {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("eca6zf6JJRjQsYYPkBHF3N32MTzur4n2WL4QiiacPCL")
    }
}

pub mod versioned_tx_message_enabled {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("3KZZ6Ks1885aGBQ45fwRcPXVBCtzUvxhUTkwKMR41Tca")
    }
}

pub mod libsecp256k1_fail_on_bad_count {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("8aXvSuopd1PUj7UhehfXJRg6619RHp8ZvwTyyJHdUYsj")
    }
}

pub mod libsecp256k1_fail_on_bad_count2 {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("54KAoNiUERNoWWUhTWWwXgym94gzoXFVnHyQwPA18V9A")
    }
}

pub mod instructions_sysvar_owned_by_sysvar {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("H3kBSaKdeiUsyHmeHqjJYNc27jesXZ6zWj3zWkowQbkV")
    }
}

pub mod stake_program_advance_activating_credits_observed {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("SAdVFw3RZvzbo6DvySbSdBnHN4gkzSTH9dSxesyKKPj")
    }
}

pub mod credits_auto_rewind {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("BUS12ciZ5gCoFafUHWW8qaFMMtwFQGVxjsDheWLdqBE2")
    }
}

pub mod demote_program_write_locks {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("3E3jV7v9VcdJL8iYZUMax9DiDno8j7EWUVbhm9RtShj2")
    }
}

pub mod ed25519_program_enabled {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("6ppMXNYLhVd7GcsZ5uV11wQEW7spppiMVfqQv5SXhDpX")
    }
}

pub mod return_data_syscall_enabled {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("DwScAzPUjuv65TMbDnFY7AgwmotzWy3xpEJMXM3hZFaB")
    }
}

pub mod reduce_required_deploy_balance {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("EBeznQDjcPG8491sFsKZYBi5S5jTVXMpAKNDJMQPS2kq")
    }
}

pub mod sol_log_data_syscall_enabled {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("6uaHcKPGUy4J7emLBgUTeufhJdiwhngW6a1R9B7c2ob9")
    }
}

pub mod stakes_remove_delegation_if_inactive {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("HFpdDDNQjvcXnXKec697HDDsyk6tFoWS2o8fkxuhQZpL")
    }
}

pub mod do_support_realloc {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("75m6ysz33AfLA5DDEzWM1obBrnPQRSsdVQ2nRmc8Vuu1")
    }
}

pub mod prevent_calling_precompiles_as_programs {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("4ApgRX3ud6p7LNMJmsuaAcZY5HWctGPr5obAsjB3A54d")
    }
}

pub mod optimize_epoch_boundary_updates {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("265hPS8k8xJ37ot82KEgjRunsUp5w4n4Q4VwwiN9i9ps")
    }
}

pub mod remove_native_loader {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("HTTgmruMYRZEntyL3EdCDdnS6e4D5wRq1FA7kQsb66qq")
    }
}

pub mod send_to_tpu_vote_port {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("C5fh68nJ7uyKAuYZg2x9sEQ5YrVf3dkW6oojNBSc3Jvo")
    }
}

pub mod requestable_heap_size {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("CCu4boMmfLuqcmfTLPHQiUo22ZdUsXjgzPAURYaWt1Bw")
    }
}

pub mod disable_fee_calculator {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("2jXx2yDmGysmBKfKYNgLj2DQyAQv6mMk2BPh4eSbyB4H")
    }
}

pub mod add_compute_budget_program {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("4d5AKtxoh93Dwm1vHXUU3iRATuMndx1c431KgT2td52r")
    }
}

pub mod nonce_must_be_writable {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("BiCU7M5w8ZCMykVSyhZ7Q3m2SWoR2qrEQ86ERcDX77ME")
    }
}

pub mod spl_token_v3_3_0_release {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("Ftok2jhqAqxUWEiCVRrfRs9DPppWP8cgTB7NQNKL88mS")
    }
}

pub mod leave_nonce_on_success {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("E8MkiWZNNPGU6n55jkGzyj8ghUmjCHRmDFdYYFYHxWhQ")
    }
}

pub mod reject_empty_instruction_without_program {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("9kdtFSrXHQg3hKkbXkQ6trJ3Ja1xpJ22CTFSNAciEwmL")
    }
}

pub mod fixed_memcpy_nonoverlapping_check {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("36PRUK2Dz6HWYdG9SpjeAsF5F3KxnFCakA2BZMbtMhSb")
    }
}

pub mod reject_non_rent_exempt_vote_withdraws {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("7txXZZD6Um59YoLMF7XUNimbMjsqsWhc7g2EniiTrmp1")
    }
}

pub mod evict_invalid_stakes_cache_entries {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("EMX9Q7TVFAmQ9V1CggAkhMzhXSg8ECp7fHrWQX2G1chf")
    }
}

pub mod allow_votes_to_directly_update_vote_state {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("Ff8b1fBeB86q8cjq47ZhsQLgv5EkHu3G1C99zjUfAzrq")
    }
}

pub mod max_tx_account_locks {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("CBkDroRDqm8HwHe6ak9cguPjUomrASEkfmxEaZ5CNNxz")
    }
}

pub mod require_rent_exempt_accounts {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("BkFDxiJQWZXGTZaJQxH7wVEHkAmwCgSEVkrvswFfRJPD")
    }
}

pub mod filter_votes_outside_slot_hashes {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("3gtZPqvPpsbXZVCx6hceMfWxtsmrjMzmg8C7PLKSxS2d")
    }
}

pub mod update_syscall_base_costs {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("2h63t332mGCCsWK2nqqqHhN4U9ayyqhLVFvczznHDoTZ")
    }
}

pub mod stake_deactivate_delinquent_instruction {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("437r62HoAdUb63amq3D7ENnBLDhHT2xY8eFkLJYVKK4x")
    }
}

pub mod vote_withdraw_authority_may_change_authorized_voter {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("AVZS3ZsN4gi6Rkx2QUibYuSJG3S6QHib7xCYhG6vGJxU")
    }
}

pub mod spl_associated_token_account_v1_0_4 {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("FaTa4SpiaSNH44PGC4z8bnGVTkSRYaWvrBs3KTu8XQQq")
    }
}

pub mod reject_vote_account_close_unless_zero_credit_epoch {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("ALBk3EWdeAg2WAGf6GPDUf1nynyNqCdEVmgouG7rpuCj")
    }
}

pub mod add_get_processed_sibling_instruction_syscall {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("CFK1hRCNy8JJuAAY8Pb2GjLFNdCThS2qwZNe3izzBMgn")
    }
}

pub mod bank_transaction_count_fix {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("Vo5siZ442SaZBKPXNocthiXysNviW4UYPwRFggmbgAp")
    }
}

pub mod disable_bpf_deprecated_load_instructions {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("3XgNukcZWf9o3HdA3fpJbm94XFc4qpvTXc8h1wxYwiPi")
    }
}

pub mod disable_bpf_unresolved_symbols_at_runtime {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("4yuaYAj2jGMGTh1sSmi4G2eFscsDq8qjugJXZoBN6YEa")
    }
}

pub mod record_instruction_in_transaction_context_push {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("3aJdcZqxoLpSBxgeYGjPwaYS1zzcByxUDqJkbzWAH1Zb")
    }
}

pub mod syscall_saturated_math {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("HyrbKftCdJ5CrUfEti6x26Cj7rZLNe32weugk7tLcWb8")
    }
}

pub mod check_physical_overlapping {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("nWBqjr3gpETbiaVj3CBJ3HFC5TMdnJDGt21hnvSTvVZ")
    }
}

pub mod limit_secp256k1_recovery_id {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("7g9EUwj4j7CS21Yx1wvgWLjSZeh5aPq8x9kpoPwXM8n8")
    }
}

pub mod disable_deprecated_loader {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("GTUMCZ8LTNxVfxdrw7ZsDFTxXb7TutYkzJnFwinpE6dg")
    }
}

pub mod check_slice_translation_size {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("GmC19j9qLn2RFk5NduX6QXaDhVpGncVVBzyM8e9WMz2F")
    }
}

pub mod stake_split_uses_rent_sysvar {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("FQnc7U4koHqWgRvFaBJjZnV8VPg6L6wWK33yJeDp4yvV")
    }
}

pub mod add_get_minimum_delegation_instruction_to_stake_program {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("St8k9dVXP97xT6faW24YmRSYConLbhsMJA4TJTBLmMT")
    }
}

pub mod error_on_syscall_bpf_function_hash_collisions {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("8199Q2gMD2kwgfopK5qqVWuDbegLgpuFUFHCcUJQDN8b")
    }
}

pub mod reject_callx_r10 {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("3NKRSwpySNwD3TvP5pHnRmkAQRsdkXWRr1WaQh8p4PWX")
    }
}

pub mod drop_redundant_turbine_path {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("4Di3y24QFLt5QEUPZtbnjyfQKfm6ZMTfa6Dw1psfoMKU")
    }
}

pub mod executables_incur_cpi_data_cost {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("7GUcYgq4tVtaqNCKT3dho9r4665Qp5TxCZ27Qgjx3829")
    }
}

pub mod fix_recent_blockhashes {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("6iyggb5MTcsvdcugX7bEKbHV8c6jdLbpHwkncrgLMhfo")
    }
}

pub mod update_rewards_from_cached_accounts {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("28s7i3htzhahXQKqmS2ExzbEoUypg9krwvtK2M9UWXh9")
    }
}
pub mod enable_partitioned_epoch_reward {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("9bn2vTJUsUcnpiZWbu2woSKtTGW3ErZC9ERv88SDqQjK")
    }
}

pub mod partitioned_epoch_rewards_superfeature {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("PERzQrt5gBD1XEe2c9XdFWqwgHY3mr7cYWbm5V772V8")
    }
}

pub mod spl_token_v3_4_0 {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("Ftok4njE8b7tDffYkC5bAbCaQv5sL6jispYrprzatUwN")
    }
}

pub mod spl_associated_token_account_v1_1_0 {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("FaTa17gVKoqbh38HcfiQonPsAaQViyDCCSg71AubYZw8")
    }
}

pub mod default_units_per_instruction {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("J2QdYx8crLbTVK8nur1jeLsmc3krDbfjoxoea2V1Uy5Q")
    }
}

pub mod stake_allow_zero_undelegated_amount {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("sTKz343FM8mqtyGvYWvbLpTThw3ixRM4Xk8QvZ985mw")
    }
}

pub mod require_static_program_ids_in_transaction {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("8FdwgyHFEjhAdjWfV2vfqk7wA1g9X3fQpKH7SBpEv3kC")
    }
}

pub mod stake_raise_minimum_delegation_to_1_sol {
    // This is a feature-proposal *feature id*.  The feature keypair address is `GQXzC7YiSNkje6FFUk6sc2p53XRvKoaZ9VMktYzUMnpL`.
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("9onWzzvCzNC2jfhxxeqRgs5q7nFAAKpCUvkj6T6GJK9i")
    }
}

pub mod stake_minimum_delegation_for_rewards {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("G6ANXD6ptCSyNd9znZm7j4dEczAJCfx7Cy43oBx3rKHJ")
    }
}

pub mod add_set_compute_unit_price_ix {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("98std1NSHqXi9WYvFShfVepRdCoq1qvsp8fsR2XZtG8g")
    }
}

pub mod disable_deploy_of_alloc_free_syscall {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("79HWsX9rpnnJBPcdNURVqygpMAfxdrAirzAGAVmf92im")
    }
}

pub mod include_account_index_in_rent_error {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("2R72wpcQ7qV7aTJWUumdn8u5wmmTyXbK7qzEy7YSAgyY")
    }
}

pub mod add_shred_type_to_shred_seed {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("Ds87KVeqhbv7Jw8W6avsS1mqz3Mw5J3pRTpPoDQ2QdiJ")
    }
}

pub mod warp_timestamp_with_a_vengeance {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("3BX6SBeEBibHaVQXywdkcgyUk6evfYZkHdztXiDtEpFS")
    }
}

pub mod separate_nonce_from_blockhash {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("Gea3ZkK2N4pHuVZVxWcnAtS6UEDdyumdYt4pFcKjA3ar")
    }
}

pub mod enable_durable_nonce {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("4EJQtF2pkRyawwcTVfQutzq4Sa5hRhibF6QAK1QXhtEX")
    }
}

pub mod vote_state_update_credit_per_dequeue {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("CveezY6FDLVBToHDcvJRmtMouqzsmj4UXYh5ths5G5Uv")
    }
}

pub mod quick_bail_on_panic {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("DpJREPyuMZ5nDfU6H3WTqSqUFSXAfw8u7xqmWtEwJDcP")
    }
}

pub mod nonce_must_be_authorized {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("HxrEu1gXuH7iD3Puua1ohd5n4iUKJyFNtNxk9DVJkvgr")
    }
}

pub mod nonce_must_be_advanceable {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("3u3Er5Vc2jVcwz4xr2GJeSAXT3fAj6ADHZ4BJMZiScFd")
    }
}

pub mod vote_authorize_with_seed {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("6tRxEYKuy2L5nnv5bgn7iT28MxUbYxp5h7F3Ncf1exrT")
    }
}

pub mod preserve_rent_epoch_for_rent_exempt_accounts {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("HH3MUYReL2BvqqA3oEcAa7txju5GY6G4nxJ51zvsEjEZ")
    }
}

pub mod enable_bpf_loader_extend_program_ix {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("8Zs9W7D9MpSEtUWSQdGniZk2cNmV22y6FLJwCx53asme")
    }
}

pub mod enable_early_verification_of_account_modifications {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("7Vced912WrRnfjaiKRiNBcbuFw7RrnLv3E3z95Y4GTNc")
    }
}

pub mod skip_rent_rewrites {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("CGB2jM8pwZkeeiXQ66kBMyBR6Np61mggL7XUsmLjVcrw")
    }
}

pub mod prevent_crediting_accounts_that_end_rent_paying {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("812kqX67odAp5NFwM8D2N24cku7WTm9CHUTFUXaDkWPn")
    }
}

pub mod cap_bpf_program_instruction_accounts {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("9k5ijzTbYPtjzu8wj2ErH9v45xecHzQ1x4PMYMMxFgdM")
    }
}

pub mod loosen_cpi_size_restriction {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("GDH5TVdbTPUpRnXaRyQqiKUa7uZAbZ28Q2N9bhbKoMLm")
    }
}

pub mod use_default_units_in_fee_calculation {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("8sKQrMQoUHtQSUP83SPG4ta2JDjSAiWs7t5aJ9uEd6To")
    }
}

pub mod compact_vote_state_updates {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("86HpNqzutEZwLcPxS6EHDcMNYWk6ikhteg9un7Y2PBKE")
    }
}

pub mod incremental_snapshot_only_incremental_hash_calculation {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("25vqsfjk7Nv1prsQJmA4Xu1bN61s8LXCBGUPp8Rfy1UF")
    }
}

pub mod disable_cpi_setting_executable_and_rent_epoch {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("B9cdB55u4jQsDNsdTK525yE9dmSc5Ga7YBaBrDFvEhM9")
    }
}

pub mod on_load_preserve_rent_epoch_for_rent_exempt_accounts {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("CpkdQmspsaZZ8FVAouQTtTWZkc8eeQ7V3uj7dWz543rZ")
    }
}

pub mod account_hash_ignore_slot {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("SVn36yVApPLYsa8koK3qUcy14zXDnqkNYWyUh1f4oK1")
    }
}

pub mod set_exempt_rent_epoch_max {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("5wAGiy15X1Jb2hkHnPDCM8oB9V42VNA9ftNVFK84dEgv")
    }
}

pub mod relax_authority_signer_check_for_lookup_table_creation {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("FKAcEvNgSY79RpqsPNUV5gDyumopH4cEHqUxyfm8b8Ap")
    }
}

pub mod stop_sibling_instruction_search_at_parent {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("EYVpEP7uzH1CoXzbD6PubGhYmnxRXPeq3PPsm1ba3gpo")
    }
}

pub mod vote_state_update_root_fix {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("G74BkWBzmsByZ1kxHy44H3wjwp5hp7JbrGRuDpco22tY")
    }
}

pub mod cap_accounts_data_allocations_per_transaction {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("9gxu85LYRAcZL38We8MYJ4A9AwgBBPtVBAqebMcT1241")
    }
}

pub mod epoch_accounts_hash {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("5GpmAKxaGsWWbPp4bNXFLJxZVvG92ctxf7jQnzTQjF3n")
    }
}

pub mod remove_deprecated_request_unit_ix {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("EfhYd3SafzGT472tYQDUc4dPd2xdEfKs5fwkowUgVt4W")
    }
}

pub mod disable_rehash_for_rent_epoch {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("DTVTkmw3JSofd8CJVJte8PXEbxNQ2yZijvVr3pe2APPj")
    }
}

pub mod increase_tx_account_lock_limit {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("9LZdXeKGeBV6hRLdxS1rHbHoEUsKqesCC2ZAPTPKJAbK")
    }
}

pub mod limit_max_instruction_trace_length {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("GQALDaC48fEhZGWRj9iL5Q889emJKcj3aCvHF7VCbbF4")
    }
}

pub mod check_syscall_outputs_do_not_overlap {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("3uRVPBpyEJRo1emLCrq38eLRFGcu6uKSpUXqGvU8T7SZ")
    }
}

pub mod enable_bpf_loader_set_authority_checked_ix {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("5x3825XS7M2A3Ekbn5VGGkvFoAg5qrRWkTrY4bARP1GL")
    }
}

pub mod enable_alt_bn128_syscall {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("A16q37opZdQMCbe5qJ6xpBB9usykfv8jZaMkxvZQi4GJ")
    }
}

pub mod simplify_alt_bn128_syscall_error_codes {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("JDn5q3GBeqzvUa7z67BbmVHVdE3EbUAjvFep3weR3jxX")
    }
}

pub mod enable_alt_bn128_compression_syscall {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("EJJewYSddEEtSZHiqugnvhQHiWyZKjkFDQASd7oKSagn")
    }
}

pub mod fix_alt_bn128_multiplication_input_length {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("bn2puAyxUx6JUabAxYdKdJ5QHbNNmKw8dCGuGCyRrFN")
    }
}

pub mod enable_program_redeployment_cooldown {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("J4HFT8usBxpcF63y46t1upYobJgChmKyZPm5uTBRg25Z")
    }
}

pub mod commission_updates_only_allowed_in_first_half_of_epoch {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("noRuG2kzACwgaY7TVmLRnUNPLKNVQE1fb7X55YWBehp")
    }
}

pub mod enable_turbine_fanout_experiments {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("D31EFnLgdiysi84Woo3of4JMu7VmasUS3Z7j9HYXCeLY")
    }
}

pub mod disable_turbine_fanout_experiments {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("Gz1aLrbeQ4Q6PTSafCZcGWZXz91yVRi7ASFzFEr1U4sa")
    }
}

pub mod move_serialized_len_ptr_in_cpi {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("74CoWuBmt3rUVUrCb2JiSTvh6nXyBWUsK4SaMj3CtE3T")
    }
}

pub mod update_hashes_per_tick {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("3uFHb9oKdGfgZGJK9EHaAXN4USvnQtAFC13Fh5gGFS5B")
    }
}

pub mod enable_big_mod_exp_syscall {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("EBq48m8irRKuE7ZnMTLvLg2UuGSqhe8s8oMqnmja1fJw")
    }
}

pub mod disable_builtin_loader_ownership_chains {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("4UDcAfQ6EcA6bdcadkeHpkarkhZGJ7Bpq7wTAiRMjkoi")
    }
}

pub mod cap_transaction_accounts_data_size {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("DdLwVYuvDz26JohmgSbA7mjpJFgX5zP2dkp8qsF2C33V")
    }
}

pub mod remove_congestion_multiplier_from_fee_calculation {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("A8xyMHZovGXFkorFqEmVH2PKGLiBip5JD7jt4zsUWo4H")
    }
}

pub mod enable_request_heap_frame_ix {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("Hr1nUA9b7NJ6eChS26o7Vi8gYYDDwWD3YeBfzJkTbU86")
    }
}

pub mod prevent_rent_paying_rent_recipients {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("Fab5oP3DmsLYCiQZXdjyqT3ukFFPrsmqhXU4WU1AWVVF")
    }
}

pub mod delay_visibility_of_program_deployment {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("GmuBvtFb2aHfSfMXpuFeWZGHyDeCLPS79s48fmCWCfM5")
    }
}

pub mod apply_cost_tracker_during_replay {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("2ry7ygxiYURULZCrypHhveanvP5tzZ4toRwVp89oCNSj")
    }
}
pub mod bpf_account_data_direct_mapping {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("FNPWmNbHbYy1R8JWVZgCPqsoRBcRu4F6ezSnq5o97Px")
    }
}

pub mod add_set_tx_loaded_accounts_data_size_instruction {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("G6vbf1UBok8MWb8m25ex86aoQHeKTzDKzuZADHkShqm6")
    }
}

pub mod switch_to_new_elf_parser {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("Cdkc8PPTeTNUPoZEfCY5AyetUrEdkZtNPMgz58nqyaHD")
    }
}

pub mod round_up_heap_size {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("CE2et8pqgyQMP2mQRg3CgvX8nJBKUArMu3wfiQiQKY1y")
    }
}

pub mod remove_bpf_loader_incorrect_program_id {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("2HmTkCj9tXuPE4ueHzdD7jPeMf9JGCoZh5AsyoATiWEe")
    }
}

pub mod include_loaded_accounts_data_size_in_fee_calculation {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("EaQpmC6GtRssaZ3PCUM5YksGqUdMLeZ46BQXYtHYakDS")
    }
}

pub mod native_programs_consume_cu {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("8pgXCMNXC8qyEFypuwpXyRxLXZdpM4Qo72gJ6k87A6wL")
    }
}

pub mod simplify_writable_program_account_check {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("5ZCcFAzJ1zsFKe1KSZa9K92jhx7gkcKj97ci2DBo1vwj")
    }
}

pub mod stop_truncating_strings_in_syscalls {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("16FMCmgLzCNNz6eTwGanbyN2ZxvTBSLuQ6DZhgeMshg")
    }
}

pub mod clean_up_delegation_errors {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("Bj2jmUsM2iRhfdLLDSTkhM5UQRQvQHm57HSmPibPtEyu")
    }
}

pub mod vote_state_add_vote_latency {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("7axKe5BTYBDD87ftzWbk5DfzWMGyRvqmWTduuo22Yaqy")
    }
}

pub mod checked_arithmetic_in_fee_validation {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("5Pecy6ie6XGm22pc9d4P9W5c31BugcFBuy6hsP2zkETv")
    }
}

pub mod last_restart_slot_sysvar {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("HooKD5NC9QNxk25QuzCssB8ecrEzGt6eXEPBUxWp1LaR")
    }
}

pub mod reduce_stake_warmup_cooldown {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("GwtDQBghCTBgmX2cpEGNPxTEBUTQRaDMGTr5qychdGMj")
    }
}

mod revise_turbine_epoch_stakes {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("BTWmtJC8U5ZLMbBUUA1k6As62sYjPEjAiNAT55xYGdJU")
    }
}

pub mod enable_poseidon_syscall {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("FL9RsQA6TVUoh5xJQ9d936RHSebA1NLQqe3Zv9sXZRpr")
    }
}

pub mod timely_vote_credits {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("tvcF6b1TRz353zKuhBjinZkKzjmihXmBAHJdjNYw1sQ")
    }
}

pub mod remaining_compute_units_syscall_enabled {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("5TuppMutoyzhUSfuYdhgzD47F92GL1g89KpCZQKqedxP")
    }
}

pub mod enable_loader_v4 {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("8Cb77yHjPWe9wuWUfXeh6iszFGCDGNCoFk3tprViYHNm")
    }
}

pub mod require_rent_exempt_split_destination {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("D2aip4BBr8NPWtU9vLrwrBvbuaQ8w1zV38zFLxx4pfBV")
    }
}

pub mod better_error_codes_for_tx_lamport_check {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("Ffswd3egL3tccB6Rv3XY6oqfdzn913vUcjCSnpvCKpfx")
    }
}

pub mod update_hashes_per_tick2 {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("EWme9uFqfy1ikK1jhJs8fM5hxWnK336QJpbscNtizkTU")
    }
}

pub mod update_hashes_per_tick3 {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("8C8MCtsab5SsfammbzvYz65HHauuUYdbY2DZ4sznH6h5")
    }
}

pub mod update_hashes_per_tick4 {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("8We4E7DPwF2WfAN8tRTtWQNhi98B99Qpuj7JoZ3Aikgg")
    }
}

pub mod update_hashes_per_tick5 {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("BsKLKAn1WM4HVhPRDsjosmqSg2J8Tq5xP2s2daDS6Ni4")
    }
}

pub mod update_hashes_per_tick6 {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("FKu1qYwLQSiehz644H6Si65U5ZQ2cp9GxsyFUfYcuADv")
    }
}

pub mod validate_fee_collector_account {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("prpFrMtgNmzaNzkPJg9o753fVvbHKqNrNTm76foJ2wm")
    }
}

pub mod disable_rent_fees_collection {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("CJzY83ggJHqPGDq8VisV3U91jDJLuEaALZooBrXtnnLU")
    }
}

pub mod enable_zk_transfer_with_fee {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("zkNLP7EQALfC1TYeB3biDU7akDckj8iPkvh9y2Mt2K3")
    }
}

pub mod drop_legacy_shreds {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("GV49KKQdBNaiv2pgqhS2Dy3GWYJGXMTVYbYkdk91orRy")
    }
}

pub mod allow_commission_decrease_at_any_time {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("decoMktMcnmiq6t3u7g5BfgcQu91nKZr6RvMYf9z1Jb")
    }
}

pub mod add_new_reserved_account_keys {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("8U4skmMVnF6k2kMvrWbQuRUT3qQSiTYpSjqmhmgfthZu")
    }
}

pub mod consume_blockstore_duplicate_proofs {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("6YsBCejwK96GZCkJ6mkZ4b68oP63z2PLoQmWjC7ggTqZ")
    }
}

pub mod index_erasure_conflict_duplicate_proofs {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("dupPajaLy2SSn8ko42aZz4mHANDNrLe8Nw8VQgFecLa")
    }
}

pub mod merkle_conflict_duplicate_proofs {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("mrkPjRg79B2oK2ZLgd7S3AfEJaX9B6gAF3H9aEykRUS")
    }
}

pub mod disable_bpf_loader_instructions {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("7WeS1vfPRgeeoXArLh7879YcB9mgE9ktjPDtajXeWfXn")
    }
}

pub mod enable_zk_proof_from_account {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("zkiTNuzBKxrCLMKehzuQeKZyLtX2yvFcEKMML8nExU8")
    }
}

pub mod cost_model_requested_write_lock_cost {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("wLckV1a64ngtcKPRGU4S4grVTestXjmNjxBjaKZrAcn")
    }
}

pub mod enable_gossip_duplicate_proof_ingestion {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("FNKCMBzYUdjhHyPdsKG2LSmdzH8TCHXn3ytj8RNBS4nG")
    }
}

pub mod chained_merkle_conflict_duplicate_proofs {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("chaie9S2zVfuxJKNRGkyTDokLwWxx6kD2ZLsqQHaDD8")
    }
}

pub mod enable_chained_merkle_shreds {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("7uZBkJXJ1HkuP6R3MJfZs7mLwymBcDbKdqbF51ZWLier")
    }
}

pub mod remove_rounding_in_fee_calculation {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("BtVN7YjDzNE6Dk7kTT7YTDgMNUZTNgiSJgsdzAeTg2jF")
    }
}

pub mod enable_tower_sync_ix {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("tSynMCspg4xFiCj1v3TDb4c7crMR5tSBhLz4sF7rrNA")
    }
}

pub mod deprecate_unused_legacy_vote_plumbing {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("6Uf8S75PVh91MYgPQSHnjRAPQq6an5BDv9vomrCwDqLe")
    }
}

pub mod reward_full_priority_fee {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("3opE3EzAKnUftUDURkzMgwpNgimBAypW1mNDYH4x4Zg7")
    }
}

pub mod get_sysvar_syscall_enabled {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("CLCoTADvV64PSrnR6QXty6Fwrt9Xc6EdxSJE4wLRePjq")
    }
}

pub mod abort_on_invalid_curve {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("FuS3FPfJDKSNot99ECLXtp3rueq36hMNStJkPJwWodLh")
    }
}

pub mod migrate_feature_gate_program_to_core_bpf {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("4eohviozzEeivk1y9UbrnekbAFMDQyJz5JjA9Y6gyvky")
    }
}

pub mod vote_only_full_fec_sets {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("ffecLRhhakKSGhMuc6Fz2Lnfq4uT9q3iu9ZsNaPLxPc")
    }
}

pub mod migrate_config_program_to_core_bpf {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("2Fr57nzzkLYXW695UdDxDeR5fhnZWSttZeZYemrnpGFV")
    }
}

pub mod enable_get_epoch_stake_syscall {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("FKe75t4LXxGaQnVHdUKM6DSFifVVraGZ8LyNo7oPwy1Z")
    }
}

pub mod migrate_address_lookup_table_program_to_core_bpf {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("C97eKZygrkU4JxJsZdjgbUY7iQR7rKTr4NyDWo2E5pRm")
    }
}

pub mod zk_elgamal_proof_program_enabled {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("zkhiy5oLowR7HY4zogXjCjeMXyruLqBwSWH21qcFtnv")
    }
}

pub mod verify_retransmitter_signature {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("BZ5g4hRbu5hLQQBdPyo2z9icGyJ8Khiyj3QS6dhWijTb")
    }
}

pub mod move_stake_and_move_lamports_ixs {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("7bTK6Jis8Xpfrs8ZoUfiMDPazTcdPcTWheZFJTA5Z6X4")
    }
}

pub mod ed25519_precompile_verify_strict {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("ed9tNscbWLYBooxWA7FE2B5KHWs8A6sxfY8EzezEcoo")
    }
}

pub mod vote_only_retransmitter_signed_fec_sets {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("RfEcA95xnhuwooVAhUUksEJLZBF7xKCLuqrJoqk4Zph")
    }
}

pub mod move_precompile_verification_to_svm {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("9ypxGLzkMxi89eDerRKXWDXe44UY2z4hBig4mDhNq5Dp")
    }
}

pub mod enable_transaction_loading_failure_fees {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("PaymEPK2oqwT9TXAVfadjztH2H6KfLEB9Hhd5Q5frvP")
    }
}

pub mod enable_turbine_extended_fanout_experiments {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("BZn14Liea52wtBwrXUxTv6vojuTTmfc7XGEDTXrvMD7b")
    }
}

pub mod deprecate_legacy_vote_ixs {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("depVvnQ2UysGrhwdiwU42tCadZL8GcBb1i2GYhMopQv")
    }
}

pub mod disable_sbpf_v0_execution {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("TestFeature11111111111111111111111111111111")
    }
}

pub mod reenable_sbpf_v0_execution {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("TestFeature21111111111111111111111111111111")
    }
}

pub mod enable_sbpf_v1_deployment_and_execution {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("JE86WkYvTrzW8HgNmrHY7dFYpCmSptUpKupbo2AdQ9cG")
    }
}

pub mod enable_sbpf_v2_deployment_and_execution {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("F6UVKh1ujTEFK3en2SyAL3cdVnqko1FVEXWhmdLRu6WP")
    }
}

pub mod enable_sbpf_v3_deployment_and_execution {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("C8XZNs1bfzaiT3YDeXZJ7G5swQWQv7tVzDnCxtHvnSpw")
    }
}

pub mod remove_accounts_executable_flag_checks {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("FfgtauHUWKeXTzjXkua9Px4tNGBFHKZ9WaigM5VbbzFx")
    }
}

pub mod lift_cpi_caller_restriction {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("HcW8ZjBezYYgvcbxNJwqv1t484Y2556qJsfNDWvJGZRH")
    }
}

pub mod disable_account_loader_special_case {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("EQUMpNFr7Nacb1sva56xn1aLfBxppEoSBH8RRVdkcD1x")
    }
}

pub mod enable_secp256r1_precompile {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("sryYyFwxzJop1Bh9XpyiVWjZP4nfHExiqNp3Dh71W9i")
    }
}

pub mod accounts_lt_hash {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("LtHaSHHsUge7EWTPVrmpuexKz6uVHZXZL6cgJa7W7Zn")
    }
}

pub mod snapshots_lt_hash {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("LTsNAP8h1voEVVToMNBNqoiNQex4aqfUrbFhRH3mSQ2")
    }
}

pub mod migrate_stake_program_to_core_bpf {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("6M4oQ6eXneVhtLoiAr4yRYQY43eVLjrKbiDZDJc892yk")
    }
}

pub mod deplete_cu_meter_on_vm_failure {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("B7H2caeia4ZFcpE3QcgMqbiWiBtWrdBRBSJ1DY6Ktxbq")
    }
}

pub mod reserve_minimal_cus_for_builtin_instructions {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("C9oAhLxDBm3ssWtJx1yBGzPY55r2rArHmN1pbQn6HogH")
    }
}

pub mod raise_block_limits_to_50m {
    use crate::{pubkey_from_str, Pubkey};
    pub fn id() -> Pubkey {
        pubkey_from_str("5oMCU3JPaFLr8Zr4ct7yFA7jdk6Mw1RmB8K4u9ZbS42z")
    }
}

lazy_static! {
    /// Map of feature identifiers to user-visible description
    pub static ref FEATURE_NAMES: HashMap<Pubkey, &'static str> = [
        (secp256k1_program_enabled::id(), "secp256k1 program"),
        (deprecate_rewards_sysvar::id(), "deprecate unused rewards sysvar"),
        (pico_inflation::id(), "pico inflation"),
        (full_inflation::devnet_and_testnet::id(), "full inflation on devnet and testnet"),
        (spl_token_v2_multisig_fix::id(), "spl-token multisig fix"),
        (no_overflow_rent_distribution::id(), "no overflow rent distribution"),
        (filter_stake_delegation_accounts::id(), "filter stake_delegation_accounts #14062"),
        (require_custodian_for_locked_stake_authorize::id(), "require custodian to authorize withdrawer change for locked stake"),
        (spl_token_v2_self_transfer_fix::id(), "spl-token self-transfer fix"),
        (full_inflation::mainnet::certusone::enable::id(), "full inflation enabled by Certus One"),
        (full_inflation::mainnet::certusone::vote::id(), "community vote allowing Certus One to enable full inflation"),
        (warp_timestamp_again::id(), "warp timestamp again, adjust bounding to 25% fast 80% slow #15204"),
        (check_init_vote_data::id(), "check initialized Vote data"),
        (secp256k1_recover_syscall_enabled::id(), "secp256k1_recover syscall"),
        (system_transfer_zero_check::id(), "perform all checks for transfers of 0 lamports"),
        (blake3_syscall_enabled::id(), "blake3 syscall"),
        (dedupe_config_program_signers::id(), "dedupe config program signers"),
        (verify_tx_signatures_len::id(), "prohibit extra transaction signatures"),
        (vote_stake_checked_instructions::id(), "vote/state program checked instructions #18345"),
        (rent_for_sysvars::id(), "collect rent from accounts owned by sysvars"),
        (libsecp256k1_0_5_upgrade_enabled::id(), "upgrade libsecp256k1 to v0.5.0"),
        (tx_wide_compute_cap::id(), "transaction wide compute cap"),
        (spl_token_v2_set_authority_fix::id(), "spl-token set_authority fix"),
        (merge_nonce_error_into_system_error::id(), "merge NonceError into SystemError"),
        (disable_fees_sysvar::id(), "disable fees sysvar"),
        (stake_merge_with_unmatched_credits_observed::id(), "allow merging active stakes with unmatched credits_observed #18985"),
        (zk_token_sdk_enabled::id(), "enable Zk Token proof program and syscalls"),
        (curve25519_syscall_enabled::id(), "enable curve25519 syscalls"),
        (versioned_tx_message_enabled::id(), "enable versioned transaction message processing"),
        (libsecp256k1_fail_on_bad_count::id(), "fail libsecp256k1_verify if count appears wrong"),
        (libsecp256k1_fail_on_bad_count2::id(), "fail libsecp256k1_verify if count appears wrong"),
        (instructions_sysvar_owned_by_sysvar::id(), "fix owner for instructions sysvar"),
        (stake_program_advance_activating_credits_observed::id(), "Enable advancing credits observed for activation epoch #19309"),
        (credits_auto_rewind::id(), "Auto rewind stake's credits_observed if (accidental) vote recreation is detected #22546"),
        (demote_program_write_locks::id(), "demote program write locks to readonly, except when upgradeable loader present #19593 #20265"),
        (ed25519_program_enabled::id(), "enable builtin ed25519 signature verify program"),
        (return_data_syscall_enabled::id(), "enable sol_{set,get}_return_data syscall"),
        (reduce_required_deploy_balance::id(), "reduce required payer balance for program deploys"),
        (sol_log_data_syscall_enabled::id(), "enable sol_log_data syscall"),
        (stakes_remove_delegation_if_inactive::id(), "remove delegations from stakes cache when inactive"),
        (do_support_realloc::id(), "support account data reallocation"),
        (prevent_calling_precompiles_as_programs::id(), "prevent calling precompiles as programs"),
        (optimize_epoch_boundary_updates::id(), "optimize epoch boundary updates"),
        (remove_native_loader::id(), "remove support for the native loader"),
        (send_to_tpu_vote_port::id(), "send votes to the tpu vote port"),
        (requestable_heap_size::id(), "Requestable heap frame size"),
        (disable_fee_calculator::id(), "deprecate fee calculator"),
        (add_compute_budget_program::id(), "Add compute_budget_program"),
        (nonce_must_be_writable::id(), "nonce must be writable"),
        (spl_token_v3_3_0_release::id(), "spl-token v3.3.0 release"),
        (leave_nonce_on_success::id(), "leave nonce as is on success"),
        (reject_empty_instruction_without_program::id(), "fail instructions which have native_loader as program_id directly"),
        (fixed_memcpy_nonoverlapping_check::id(), "use correct check for nonoverlapping regions in memcpy syscall"),
        (reject_non_rent_exempt_vote_withdraws::id(), "fail vote withdraw instructions which leave the account non-rent-exempt"),
        (evict_invalid_stakes_cache_entries::id(), "evict invalid stakes cache entries on epoch boundaries"),
        (allow_votes_to_directly_update_vote_state::id(), "enable direct vote state update"),
        (max_tx_account_locks::id(), "enforce max number of locked accounts per transaction"),
        (require_rent_exempt_accounts::id(), "require all new transaction accounts with data to be rent-exempt"),
        (filter_votes_outside_slot_hashes::id(), "filter vote slots older than the slot hashes history"),
        (update_syscall_base_costs::id(), "update syscall base costs"),
        (stake_deactivate_delinquent_instruction::id(), "enable the deactivate delinquent stake instruction #23932"),
        (vote_withdraw_authority_may_change_authorized_voter::id(), "vote account withdraw authority may change the authorized voter #22521"),
        (spl_associated_token_account_v1_0_4::id(), "SPL Associated Token Account Program release version 1.0.4, tied to token 3.3.0 #22648"),
        (reject_vote_account_close_unless_zero_credit_epoch::id(), "fail vote account withdraw to 0 unless account earned 0 credits in last completed epoch"),
        (add_get_processed_sibling_instruction_syscall::id(), "add add_get_processed_sibling_instruction_syscall"),
        (bank_transaction_count_fix::id(), "fixes Bank::transaction_count to include all committed transactions, not just successful ones"),
        (disable_bpf_deprecated_load_instructions::id(), "disable ldabs* and ldind* SBF instructions"),
        (disable_bpf_unresolved_symbols_at_runtime::id(), "disable reporting of unresolved SBF symbols at runtime"),
        (record_instruction_in_transaction_context_push::id(), "move the CPI stack overflow check to the end of push"),
        (syscall_saturated_math::id(), "syscalls use saturated math"),
        (check_physical_overlapping::id(), "check physical overlapping regions"),
        (limit_secp256k1_recovery_id::id(), "limit secp256k1 recovery id"),
        (disable_deprecated_loader::id(), "disable the deprecated BPF loader"),
        (check_slice_translation_size::id(), "check size when translating slices"),
        (stake_split_uses_rent_sysvar::id(), "stake split instruction uses rent sysvar"),
        (add_get_minimum_delegation_instruction_to_stake_program::id(), "add GetMinimumDelegation instruction to stake program"),
        (error_on_syscall_bpf_function_hash_collisions::id(), "error on bpf function hash collisions"),
        (reject_callx_r10::id(), "Reject bpf callx r10 instructions"),
        (drop_redundant_turbine_path::id(), "drop redundant turbine path"),
        (executables_incur_cpi_data_cost::id(), "Executables incur CPI data costs"),
        (fix_recent_blockhashes::id(), "stop adding hashes for skipped slots to recent blockhashes"),
        (update_rewards_from_cached_accounts::id(), "update rewards from cached accounts"),
        (enable_partitioned_epoch_reward::id(), "enable partitioned rewards at epoch boundary #32166"),
        (spl_token_v3_4_0::id(), "SPL Token Program version 3.4.0 release #24740"),
        (spl_associated_token_account_v1_1_0::id(), "SPL Associated Token Account Program version 1.1.0 release #24741"),
        (default_units_per_instruction::id(), "Default max tx-wide compute units calculated per instruction"),
        (stake_allow_zero_undelegated_amount::id(), "Allow zero-lamport undelegated amount for initialized stakes #24670"),
        (require_static_program_ids_in_transaction::id(), "require static program ids in versioned transactions"),
        (stake_raise_minimum_delegation_to_1_sol::id(), "Raise minimum stake delegation to 1.0 SOL #24357"),
        (stake_minimum_delegation_for_rewards::id(), "stakes must be at least the minimum delegation to earn rewards"),
        (add_set_compute_unit_price_ix::id(), "add compute budget ix for setting a compute unit price"),
        (disable_deploy_of_alloc_free_syscall::id(), "disable new deployments of deprecated sol_alloc_free_ syscall"),
        (include_account_index_in_rent_error::id(), "include account index in rent tx error #25190"),
        (add_shred_type_to_shred_seed::id(), "add shred-type to shred seed #25556"),
        (warp_timestamp_with_a_vengeance::id(), "warp timestamp again, adjust bounding to 150% slow #25666"),
        (separate_nonce_from_blockhash::id(), "separate durable nonce and blockhash domains #25744"),
        (enable_durable_nonce::id(), "enable durable nonce #25744"),
        (vote_state_update_credit_per_dequeue::id(), "Calculate vote credits for VoteStateUpdate per vote dequeue to match credit awards for Vote instruction"),
        (quick_bail_on_panic::id(), "quick bail on panic"),
        (nonce_must_be_authorized::id(), "nonce must be authorized"),
        (nonce_must_be_advanceable::id(), "durable nonces must be advanceable"),
        (vote_authorize_with_seed::id(), "An instruction you can use to change a vote accounts authority when the current authority is a derived key #25860"),
        (preserve_rent_epoch_for_rent_exempt_accounts::id(), "preserve rent epoch for rent exempt accounts #26479"),
        (enable_bpf_loader_extend_program_ix::id(), "enable bpf upgradeable loader ExtendProgram instruction #25234"),
        (skip_rent_rewrites::id(), "skip rewriting rent exempt accounts during rent collection #26491"),
        (enable_early_verification_of_account_modifications::id(), "enable early verification of account modifications #25899"),
        (disable_rehash_for_rent_epoch::id(), "on accounts hash calculation, do not try to rehash accounts #28934"),
        (account_hash_ignore_slot::id(), "ignore slot when calculating an account hash #28420"),
        (set_exempt_rent_epoch_max::id(), "set rent epoch to Epoch::MAX for rent-exempt accounts #28683"),
        (on_load_preserve_rent_epoch_for_rent_exempt_accounts::id(), "on bank load account, do not try to fix up rent_epoch #28541"),
        (prevent_crediting_accounts_that_end_rent_paying::id(), "prevent crediting rent paying accounts #26606"),
        (cap_bpf_program_instruction_accounts::id(), "enforce max number of accounts per bpf program instruction #26628"),
        (loosen_cpi_size_restriction::id(), "loosen cpi size restrictions #26641"),
        (use_default_units_in_fee_calculation::id(), "use default units per instruction in fee calculation #26785"),
        (compact_vote_state_updates::id(), "Compact vote state updates to lower block size"),
        (incremental_snapshot_only_incremental_hash_calculation::id(), "only hash accounts in incremental snapshot during incremental snapshot creation #26799"),
        (disable_cpi_setting_executable_and_rent_epoch::id(), "disable setting is_executable and_rent_epoch in CPI #26987"),
        (relax_authority_signer_check_for_lookup_table_creation::id(), "relax authority signer check for lookup table creation #27205"),
        (stop_sibling_instruction_search_at_parent::id(), "stop the search in get_processed_sibling_instruction when the parent instruction is reached #27289"),
        (vote_state_update_root_fix::id(), "fix root in vote state updates #27361"),
        (cap_accounts_data_allocations_per_transaction::id(), "cap accounts data allocations per transaction #27375"),
        (epoch_accounts_hash::id(), "enable epoch accounts hash calculation #27539"),
        (remove_deprecated_request_unit_ix::id(), "remove support for RequestUnitsDeprecated instruction #27500"),
        (increase_tx_account_lock_limit::id(), "increase tx account lock limit to 128 #27241"),
        (limit_max_instruction_trace_length::id(), "limit max instruction trace length #27939"),
        (check_syscall_outputs_do_not_overlap::id(), "check syscall outputs do_not overlap #28600"),
        (enable_bpf_loader_set_authority_checked_ix::id(), "enable bpf upgradeable loader SetAuthorityChecked instruction #28424"),
        (enable_alt_bn128_syscall::id(), "add alt_bn128 syscalls #27961"),
        (simplify_alt_bn128_syscall_error_codes::id(), "simplify alt_bn128 syscall error codes SIMD-0129"),
        (enable_program_redeployment_cooldown::id(), "enable program redeployment cooldown #29135"),
        (commission_updates_only_allowed_in_first_half_of_epoch::id(), "validator commission updates are only allowed in the first half of an epoch #29362"),
        (enable_turbine_fanout_experiments::id(), "enable turbine fanout experiments #29393"),
        (disable_turbine_fanout_experiments::id(), "disable turbine fanout experiments #29393"),
        (move_serialized_len_ptr_in_cpi::id(), "cpi ignore serialized_len_ptr #29592"),
        (update_hashes_per_tick::id(), "Update desired hashes per tick on epoch boundary"),
        (enable_big_mod_exp_syscall::id(), "add big_mod_exp syscall #28503"),
        (disable_builtin_loader_ownership_chains::id(), "disable builtin loader ownership chains #29956"),
        (cap_transaction_accounts_data_size::id(), "cap transaction accounts data size up to a limit #27839"),
        (remove_congestion_multiplier_from_fee_calculation::id(), "Remove congestion multiplier from transaction fee calculation #29881"),
        (enable_request_heap_frame_ix::id(), "Enable transaction to request heap frame using compute budget instruction #30076"),
        (prevent_rent_paying_rent_recipients::id(), "prevent recipients of rent rewards from ending in rent-paying state #30151"),
        (delay_visibility_of_program_deployment::id(), "delay visibility of program upgrades #30085"),
        (apply_cost_tracker_during_replay::id(), "apply cost tracker to blocks during replay #29595"),
        (add_set_tx_loaded_accounts_data_size_instruction::id(), "add compute budget instruction for setting account data size per transaction #30366"),
        (switch_to_new_elf_parser::id(), "switch to new ELF parser #30497"),
        (round_up_heap_size::id(), "round up heap size when calculating heap cost #30679"),
        (remove_bpf_loader_incorrect_program_id::id(), "stop incorrectly throwing IncorrectProgramId in bpf_loader #30747"),
        (include_loaded_accounts_data_size_in_fee_calculation::id(), "include transaction loaded accounts data size in base fee calculation #30657"),
        (native_programs_consume_cu::id(), "Native program should consume compute units #30620"),
        (simplify_writable_program_account_check::id(), "Simplify checks performed for writable upgradeable program accounts #30559"),
        (stop_truncating_strings_in_syscalls::id(), "Stop truncating strings in syscalls #31029"),
        (clean_up_delegation_errors::id(), "Return InsufficientDelegation instead of InsufficientFunds or InsufficientStake where applicable #31206"),
        (vote_state_add_vote_latency::id(), "replace Lockout with LandedVote (including vote latency) in vote state #31264"),
        (checked_arithmetic_in_fee_validation::id(), "checked arithmetic in fee validation #31273"),
        (bpf_account_data_direct_mapping::id(), "use memory regions to map account data into the rbpf vm instead of copying the data"),
        (last_restart_slot_sysvar::id(), "enable new sysvar last_restart_slot"),
        (reduce_stake_warmup_cooldown::id(), "reduce stake warmup cooldown from 25% to 9%"),
        (revise_turbine_epoch_stakes::id(), "revise turbine epoch stakes"),
        (enable_poseidon_syscall::id(), "Enable Poseidon syscall"),
        (timely_vote_credits::id(), "use timeliness of votes in determining credits to award"),
        (remaining_compute_units_syscall_enabled::id(), "enable the remaining_compute_units syscall"),
        (enable_loader_v4::id(), "Enable Loader-v4 SIMD-0167"),
        (require_rent_exempt_split_destination::id(), "Require stake split destination account to be rent exempt"),
        (better_error_codes_for_tx_lamport_check::id(), "better error codes for tx lamport check #33353"),
        (enable_alt_bn128_compression_syscall::id(), "add alt_bn128 compression syscalls"),
        (update_hashes_per_tick2::id(), "Update desired hashes per tick to 2.8M"),
        (update_hashes_per_tick3::id(), "Update desired hashes per tick to 4.4M"),
        (update_hashes_per_tick4::id(), "Update desired hashes per tick to 7.6M"),
        (update_hashes_per_tick5::id(), "Update desired hashes per tick to 9.2M"),
        (update_hashes_per_tick6::id(), "Update desired hashes per tick to 10M"),
        (validate_fee_collector_account::id(), "validate fee collector account #33888"),
        (disable_rent_fees_collection::id(), "Disable rent fees collection #33945"),
        (enable_zk_transfer_with_fee::id(), "enable Zk Token proof program transfer with fee"),
        (drop_legacy_shreds::id(), "drops legacy shreds #34328"),
        (allow_commission_decrease_at_any_time::id(), "Allow commission decrease at any time in epoch #33843"),
        (consume_blockstore_duplicate_proofs::id(), "consume duplicate proofs from blockstore in consensus #34372"),
        (add_new_reserved_account_keys::id(), "add new unwritable reserved accounts #34899"),
        (index_erasure_conflict_duplicate_proofs::id(), "generate duplicate proofs for index and erasure conflicts #34360"),
        (merkle_conflict_duplicate_proofs::id(), "generate duplicate proofs for merkle root conflicts #34270"),
        (disable_bpf_loader_instructions::id(), "disable bpf loader management instructions #34194"),
        (enable_zk_proof_from_account::id(), "Enable zk token proof program to read proof from accounts instead of instruction data #34750"),
        (curve25519_restrict_msm_length::id(), "restrict curve25519 multiscalar multiplication vector lengths #34763"),
        (cost_model_requested_write_lock_cost::id(), "cost model uses number of requested write locks #34819"),
        (enable_gossip_duplicate_proof_ingestion::id(), "enable gossip duplicate proof ingestion #32963"),
        (enable_chained_merkle_shreds::id(), "Enable chained Merkle shreds #34916"),
        (remove_rounding_in_fee_calculation::id(), "Removing unwanted rounding in fee calculation #34982"),
        (deprecate_unused_legacy_vote_plumbing::id(), "Deprecate unused legacy vote tx plumbing"),
        (enable_tower_sync_ix::id(), "Enable tower sync vote instruction"),
        (chained_merkle_conflict_duplicate_proofs::id(), "generate duplicate proofs for chained merkle root conflicts"),
        (reward_full_priority_fee::id(), "Reward full priority fee to validators #34731"),
        (abort_on_invalid_curve::id(), "Abort when elliptic curve syscalls invoked on invalid curve id SIMD-0137"),
        (get_sysvar_syscall_enabled::id(), "Enable syscall for fetching Sysvar bytes #615"),
        (migrate_feature_gate_program_to_core_bpf::id(), "Migrate Feature Gate program to Core BPF (programify) #1003"),
        (vote_only_full_fec_sets::id(), "vote only full fec sets"),
        (migrate_config_program_to_core_bpf::id(), "Migrate Config program to Core BPF #1378"),
        (enable_get_epoch_stake_syscall::id(), "Enable syscall: sol_get_epoch_stake #884"),
        (migrate_address_lookup_table_program_to_core_bpf::id(), "Migrate Address Lookup Table program to Core BPF #1651"),
        (zk_elgamal_proof_program_enabled::id(), "Enable ZkElGamalProof program SIMD-0153"),
        (verify_retransmitter_signature::id(), "Verify retransmitter signature #1840"),
        (move_stake_and_move_lamports_ixs::id(), "Enable MoveStake and MoveLamports stake program instructions #1610"),
        (ed25519_precompile_verify_strict::id(), "Use strict verification in ed25519 precompile SIMD-0152"),
        (vote_only_retransmitter_signed_fec_sets::id(), "vote only on retransmitter signed fec sets"),
        (move_precompile_verification_to_svm::id(), "SIMD-0159: Move precompile verification into SVM"),
        (enable_transaction_loading_failure_fees::id(), "Enable fees for some additional transaction failures SIMD-0082"),
        (enable_turbine_extended_fanout_experiments::id(), "enable turbine extended fanout experiments #"),
        (deprecate_legacy_vote_ixs::id(), "Deprecate legacy vote instructions"),
        (partitioned_epoch_rewards_superfeature::id(), "replaces enable_partitioned_epoch_reward to enable partitioned rewards at epoch boundary SIMD-0118"),
        (disable_sbpf_v0_execution::id(), "Disables execution of SBPFv1 programs SIMD-0161"),
        (reenable_sbpf_v0_execution::id(), "Re-enables execution of SBPFv1 programs"),
        (enable_sbpf_v1_deployment_and_execution::id(), "Enables deployment and execution of SBPFv1 programs SIMD-0161"),
        (enable_sbpf_v2_deployment_and_execution::id(), "Enables deployment and execution of SBPFv2 programs SIMD-0161"),
        (enable_sbpf_v3_deployment_and_execution::id(), "Enables deployment and execution of SBPFv3 programs SIMD-0161"),
        (remove_accounts_executable_flag_checks::id(), "Remove checks of accounts is_executable flag SIMD-0162"),
        (lift_cpi_caller_restriction::id(), "Lift the restriction in CPI that the caller must have the callee as an instruction account #2202"),
        (disable_account_loader_special_case::id(), "Disable account loader special case #3513"),
        (accounts_lt_hash::id(), "enables lattice-based accounts hash SIMD-0215"),
        (snapshots_lt_hash::id(), "snapshots use lattice-based accounts hash SIMD-0220"),
        (enable_secp256r1_precompile::id(), "Enable secp256r1 precompile SIMD-0075"),
        (migrate_stake_program_to_core_bpf::id(), "Migrate Stake program to Core BPF SIMD-0196 #3655"),
        (deplete_cu_meter_on_vm_failure::id(), "Deplete compute meter for vm errors SIMD-0182 #3993"),
        (reserve_minimal_cus_for_builtin_instructions::id(), "Reserve minimal CUs for builtin instructions SIMD-170 #2562"),
        (raise_block_limits_to_50m::id(), "Raise block limit to 50M SIMD-0207"),
        (fix_alt_bn128_multiplication_input_length::id(), "fix alt_bn128 multiplication input length SIMD-0222 #3686"),
        /*************** ADD NEW FEATURES HERE ***************/
    ]
    .iter()
    .cloned()
    .collect();

    /// Unique identifier of the current software's feature set
    pub static ref ID: Hash = {
        let mut hasher = Hasher::default();
        let mut feature_ids = FEATURE_NAMES.keys().collect::<Vec<_>>();
        feature_ids.sort();
        for feature in feature_ids {
            hasher.hash(feature.as_ref());
        }
        hasher.result()
    };
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct FullInflationFeaturePair {
    pub vote_id: Pubkey, // Feature that grants the candidate the ability to enable full inflation
    pub enable_id: Pubkey, // Feature to enable full inflation by the candidate
}

lazy_static! {
    /// Set of feature pairs that once enabled will trigger full inflation
    pub static ref FULL_INFLATION_FEATURE_PAIRS: HashSet<FullInflationFeaturePair> = [
        FullInflationFeaturePair {
            vote_id: full_inflation::mainnet::certusone::vote::id(),
            enable_id: full_inflation::mainnet::certusone::enable::id(),
        },
    ]
    .iter()
    .cloned()
    .collect();
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

type Hash = [u8; 32];
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

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FeatureSet {
    pub active: HashMap<Pubkey, u64>,
    pub inactive: HashSet<Pubkey>,
}
impl Default for FeatureSet {
    fn default() -> Self {
        // All features disabled
        Self {
            active: HashMap::new(),
            inactive: FEATURE_NAMES.keys().cloned().collect(),
        }
    }
}
impl FeatureSet {
    pub fn is_active(&self, feature_id: &Pubkey) -> bool {
        self.active.contains_key(feature_id)
    }

    pub fn activated_slot(&self, feature_id: &Pubkey) -> Option<u64> {
        self.active.get(feature_id).copied()
    }

    /// List of enabled features that trigger full inflation
    pub fn full_inflation_features_enabled(&self) -> HashSet<Pubkey> {
        let mut hash_set = FULL_INFLATION_FEATURE_PAIRS
            .iter()
            .filter_map(|pair| {
                if self.is_active(&pair.vote_id) && self.is_active(&pair.enable_id) {
                    Some(pair.enable_id)
                } else {
                    None
                }
            })
            .collect::<HashSet<_>>();

        if self.is_active(&full_inflation::devnet_and_testnet::id()) {
            hash_set.insert(full_inflation::devnet_and_testnet::id());
        }
        hash_set
    }

    /// All features enabled, useful for testing
    pub fn all_enabled() -> Self {
        Self {
            active: FEATURE_NAMES.keys().cloned().map(|key| (key, 0)).collect(),
            inactive: HashSet::new(),
        }
    }

    /// Activate a feature
    pub fn activate(&mut self, feature_id: &Pubkey, slot: u64) {
        self.inactive.remove(feature_id);
        self.active.insert(*feature_id, slot);
    }

    /// Deactivate a feature
    pub fn deactivate(&mut self, feature_id: &Pubkey) {
        self.active.remove(feature_id);
        self.inactive.insert(*feature_id);
    }

    pub fn new_warmup_cooldown_rate_epoch(&self, epoch_schedule: &EpochSchedule) -> Option<u64> {
        self.activated_slot(&reduce_stake_warmup_cooldown::id())
            .map(|slot| epoch_schedule.get_epoch(slot))
    }
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
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

const FEES_ID: Pubkey = [
    6, 167, 213, 23, 24, 226, 90, 141, 131, 80, 60, 37, 26, 122, 240, 113, 38, 253, 114, 0, 223,
    111, 196, 237, 82, 106, 156, 144, 0, 0, 0, 0,
];
const RECENT_BLOCKHASHES_ID: Pubkey = [
    6, 167, 213, 23, 25, 44, 86, 142, 224, 138, 132, 95, 115, 210, 151, 136, 207, 3, 92, 49, 69,
    178, 26, 179, 68, 216, 6, 46, 169, 64, 0, 0,
];

pub mod sysvar {
    // Owner pubkey for sysvar accounts
    use crate::{pubkey_from_str, Pubkey};
    use lazy_static::lazy_static;
    lazy_static! {
        pub static ref ID: Pubkey = id();
    }
    pub fn id() -> Pubkey {
        pubkey_from_str("Sysvar1111111111111111111111111111111111111")
    }
    pub mod clock {
        use crate::{pubkey_from_str, Pubkey};
        pub const ID: Pubkey = [
            6, 167, 213, 23, 24, 199, 116, 201, 40, 86, 99, 152, 105, 29, 94, 182, 139, 94, 184,
            163, 155, 75, 109, 92, 115, 85, 91, 33, 0, 0, 0, 0,
        ];
        pub fn id() -> Pubkey {
            pubkey_from_str("SysvarC1ock11111111111111111111111111111111")
        }
        pub fn check_id(pk: &Pubkey) -> bool {
            *pk == ID
        }
    }
    pub mod epoch_rewards {
        use crate::{pubkey_from_str, Pubkey};
        pub const ID: Pubkey = [
            6, 167, 213, 23, 24, 220, 63, 238, 2, 165, 88, 191, 131, 206, 102, 225, 68, 66, 42, 28,
            52, 149, 11, 39, 193, 134, 155, 90, 156, 0, 0, 0,
        ];
        pub fn id() -> Pubkey {
            pubkey_from_str("SysvarEpochRewards1111111111111111111111111")
        }
    }
    pub mod epoch_schedule {
        use crate::{pubkey_from_str, Pubkey};
        pub const ID: Pubkey = [
            6, 167, 213, 23, 24, 220, 63, 238, 2, 211, 228, 127, 1, 0, 248, 176, 84, 247, 148, 46,
            96, 89, 30, 63, 80, 135, 25, 168, 5, 0, 0, 0,
        ];
        pub fn id() -> Pubkey {
            pubkey_from_str("SysvarEpochSchedu1e111111111111111111111111")
        }
    }
    pub mod fees {
        use crate::{pubkey_from_str, Pubkey};
        pub const ID: Pubkey = [
            6, 167, 213, 23, 24, 220, 63, 238, 2, 165, 88, 191, 131, 206, 102, 225, 68, 66, 42, 28,
            52, 149, 11, 39, 193, 134, 155, 90, 156, 0, 0, 0,
        ];
        pub fn id() -> Pubkey {
            pubkey_from_str("SysvarFees111111111111111111111111111111111")
        }
    }
    pub mod instructions {
        use crate::{pubkey_from_str, Pubkey};
        pub const ID: Pubkey = [
            6, 167, 213, 23, 24, 220, 63, 238, 2, 165, 88, 191, 131, 206, 102, 225, 68, 66, 42, 28,
            52, 149, 11, 39, 193, 134, 155, 90, 156, 0, 0, 0,
        ];
        pub fn id() -> Pubkey {
            pubkey_from_str("Sysvar1nstructions1111111111111111111111111")
        }
    }
    pub mod last_restart_slot {
        use crate::{pubkey_from_str, Pubkey};
        pub const ID: Pubkey = [
            6, 167, 213, 23, 25, 6, 221, 225, 205, 63, 148, 125, 202, 180, 200, 244, 244, 245, 27,
            173, 15, 152, 19, 184, 0, 210, 137, 71, 31, 192, 0, 0,
        ];
        pub fn id() -> Pubkey {
            pubkey_from_str("SysvarLastRestartS1ot1111111111111111111111")
        }
    }
    pub mod recent_blockhashes {
        use crate::{pubkey_from_str, Pubkey};
        pub const ID: Pubkey = [
            6, 167, 213, 23, 24, 220, 63, 238, 2, 165, 88, 191, 131, 206, 102, 225, 68, 66, 42, 28,
            52, 149, 11, 39, 193, 134, 155, 90, 156, 0, 0, 0,
        ];
        pub fn id() -> Pubkey {
            pubkey_from_str("SysvarRecentB1ockHashes11111111111111111111")
        }
    }
    pub mod rent {
        use crate::{pubkey_from_str, Pubkey};
        pub const ID: Pubkey = [
            6, 167, 213, 23, 25, 44, 92, 81, 33, 140, 201, 76, 61, 74, 241, 127, 88, 218, 238, 8,
            155, 161, 253, 68, 227, 219, 217, 138, 0, 0, 0, 0,
        ];
        pub fn id() -> Pubkey {
            pubkey_from_str("SysvarRent111111111111111111111111111111111")
        }
    }
    pub mod rewards {
        use crate::{pubkey_from_str, Pubkey};
        pub const ID: Pubkey = [
            6, 167, 213, 23, 25, 53, 132, 208, 254, 237, 155, 179, 67, 29, 19, 32, 107, 229, 68,
            40, 27, 87, 184, 86, 108, 197, 55, 95, 244, 0, 0, 0,
        ];
        pub fn id() -> Pubkey {
            pubkey_from_str("SysvarRewards111111111111111111111111111111")
        }
    }
    pub mod slot_hashes {
        use crate::{pubkey_from_str, Pubkey};
        pub const ID: Pubkey = [
            6, 167, 213, 23, 25, 47, 10, 175, 198, 242, 101, 227, 251, 119, 204, 122, 218, 130,
            197, 41, 208, 190, 59, 19, 110, 45, 0, 85, 32, 0, 0, 0,
        ];
        pub fn id() -> Pubkey {
            pubkey_from_str("SysvarS1otHashes111111111111111111111111111")
        }
    }
    pub mod slot_history {
        use crate::{pubkey_from_str, Pubkey};
        pub const ID: Pubkey = [
            6, 167, 213, 23, 25, 53, 132, 208, 254, 237, 155, 179, 67, 29, 19, 32, 107, 229, 68,
            40, 27, 87, 184, 86, 108, 197, 55, 95, 244, 0, 0, 0,
        ];
        pub fn id() -> Pubkey {
            pubkey_from_str("SysvarS1otHistory11111111111111111111111111")
        }
    }
    pub mod stake_history {
        use crate::{pubkey_from_str, Pubkey};
        pub const ID: Pubkey = [
            6, 167, 213, 23, 25, 53, 132, 208, 254, 237, 155, 179, 67, 29, 19, 32, 107, 229, 68,
            40, 27, 87, 184, 86, 108, 197, 55, 95, 244, 0, 0, 0,
        ];
        pub fn id() -> Pubkey {
            pubkey_from_str("SysvarStakeHistory1111111111111111111111111")
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
            _ => panic!("Unrecognized Sysvar ID: {sysvar_id:?}"),
        }
    }

    // this is exposed for SyscallGetSysvar and should not otherwise be used
    pub fn sysvar_id_to_buffer(&self, sysvar_id: &Pubkey) -> &Option<Vec<u8>> {
        if sysvar::clock::ID == *sysvar_id {
            &self.clock
        } else if sysvar::epoch_schedule::ID == *sysvar_id {
            &self.epoch_schedule
        } else if sysvar::epoch_rewards::ID == *sysvar_id {
            &self.epoch_rewards
        } else if sysvar::rent::ID == *sysvar_id {
            &self.rent
        } else if sysvar::slot_hashes::ID == *sysvar_id {
            &self.slot_hashes
        } else if sysvar::stake_history::ID == *sysvar_id {
            &self.stake_history
        } else if sysvar::last_restart_slot::ID == *sysvar_id {
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
        self.get_sysvar_obj(&sysvar::clock::ID)
    }

    pub fn get_epoch_schedule(&self) -> Result<Arc<EpochSchedule>, InstructionError> {
        self.get_sysvar_obj(&sysvar::epoch_schedule::ID)
    }

    pub fn get_epoch_rewards(&self) -> Result<Arc<EpochRewards>, InstructionError> {
        self.get_sysvar_obj(&sysvar::epoch_rewards::ID)
    }

    pub fn get_rent(&self) -> Result<Arc<Rent>, InstructionError> {
        self.get_sysvar_obj(&sysvar::rent::ID)
    }

    pub fn get_last_restart_slot(&self) -> Result<Arc<LastRestartSlot>, InstructionError> {
        self.get_sysvar_obj(&sysvar::last_restart_slot::ID)
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
            get_account_data(&sysvar::clock::ID, &mut |data: &[u8]| {
                if bincode::deserialize::<Clock>(data).is_ok() {
                    self.clock = Some(data.to_vec());
                }
            });
        }

        if self.epoch_schedule.is_none() {
            get_account_data(&sysvar::epoch_schedule::ID, &mut |data: &[u8]| {
                if bincode::deserialize::<EpochSchedule>(data).is_ok() {
                    self.epoch_schedule = Some(data.to_vec());
                }
            });
        }

        if self.epoch_rewards.is_none() {
            get_account_data(&sysvar::epoch_rewards::ID, &mut |data: &[u8]| {
                if bincode::deserialize::<EpochRewards>(data).is_ok() {
                    self.epoch_rewards = Some(data.to_vec());
                }
            });
        }

        if self.rent.is_none() {
            get_account_data(&sysvar::rent::ID, &mut |data: &[u8]| {
                if bincode::deserialize::<Rent>(data).is_ok() {
                    self.rent = Some(data.to_vec());
                }
            });
        }

        if self.slot_hashes.is_none() {
            get_account_data(&sysvar::slot_hashes::ID, &mut |data: &[u8]| {
                if let Ok(obj) = bincode::deserialize::<SlotHashes>(data) {
                    self.slot_hashes = Some(data.to_vec());
                    self.slot_hashes_obj = Some(Arc::new(obj));
                }
            });
        }

        if self.stake_history.is_none() {
            get_account_data(&sysvar::stake_history::ID, &mut |data: &[u8]| {
                if let Ok(obj) = bincode::deserialize::<StakeHistory>(data) {
                    self.stake_history = Some(data.to_vec());
                    self.stake_history_obj = Some(Arc::new(obj));
                }
            });
        }

        if self.last_restart_slot.is_none() {
            get_account_data(&sysvar::last_restart_slot::ID, &mut |data: &[u8]| {
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
