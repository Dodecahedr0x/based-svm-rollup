pub mod address_lookup_table {
    crate::declare_id!("AddressLookupTab1e1111111111111111111111111");
}

pub mod bpf_loader {
    crate::declare_id!("BPFLoader2111111111111111111111111111111111");
}

pub mod bpf_loader_deprecated {
    crate::declare_id!("BPFLoader1111111111111111111111111111111111");
}

pub mod bpf_loader_upgradeable {
    crate::declare_id!("BPFLoaderUpgradeab1e11111111111111111111111");

    pub fn is_upgrade_instruction(instruction_data: &[u8]) -> bool {
        !instruction_data.is_empty() && 3 == instruction_data[0]
    }

    pub fn is_set_authority_instruction(instruction_data: &[u8]) -> bool {
        !instruction_data.is_empty() && 4 == instruction_data[0]
    }

    pub fn is_close_instruction(instruction_data: &[u8]) -> bool {
        !instruction_data.is_empty() && 5 == instruction_data[0]
    }

    pub fn is_set_authority_checked_instruction(instruction_data: &[u8]) -> bool {
        !instruction_data.is_empty() && 7 == instruction_data[0]
    }
}

pub mod compute_budget {
    crate::declare_id!("ComputeBudget111111111111111111111111111111");
}

pub mod config {
    crate::declare_id!("Config1111111111111111111111111111111111111");
}

pub mod ed25519_program {
    crate::declare_id!("Ed25519SigVerify111111111111111111111111111");
}

pub mod feature {
    crate::declare_id!("Feature111111111111111111111111111111111111");
}

/// A designated address for burning lamports.
///
/// Lamports credited to this address will be removed from the total supply
/// (burned) at the end of the current block.
pub mod incinerator {
    crate::declare_id!("1nc1nerator11111111111111111111111111111111");
}

pub mod loader_v4 {
    crate::declare_id!("LoaderV411111111111111111111111111111111111");
}

pub mod native_loader {
    crate::declare_id!("NativeLoader1111111111111111111111111111111");
}

pub mod secp256k1_program {
    crate::declare_id!("KeccakSecp256k11111111111111111111111111111");
}

pub mod secp256r1_program {
    crate::declare_id!("Secp256r1SigVerify1111111111111111111111111");
}

pub mod stake {
    pub mod config {
        crate::declare_deprecated_id!("StakeConfig11111111111111111111111111111111");
    }
    crate::declare_id!("Stake11111111111111111111111111111111111111");
}

pub mod system_program {
    crate::declare_id!("11111111111111111111111111111111");
}

pub mod vote {
    crate::declare_id!("Vote111111111111111111111111111111111111111");
}

pub mod sysvar {
    // Owner pubkey for sysvar accounts
    crate::declare_id!("Sysvar1111111111111111111111111111111111111");
    pub mod clock {
        crate::declare_id!("SysvarC1ock11111111111111111111111111111111");
    }
    pub mod epoch_rewards {
        crate::declare_id!("SysvarEpochRewards1111111111111111111111111");
    }
    pub mod epoch_schedule {
        crate::declare_id!("SysvarEpochSchedu1e111111111111111111111111");
    }
    pub mod fees {
        crate::declare_id!("SysvarFees111111111111111111111111111111111");
    }
    pub mod instructions {
        use crate::{AccountInfo, ProgramError};

        crate::declare_id!("Sysvar1nstructions1111111111111111111111111");

        /// Load the current `Instruction`'s index in the currently executing
        /// `Transaction`.
        ///
        /// `data` is the instructions sysvar account data.
        ///
        /// Unsafe because the sysvar accounts address is not checked; only used
        /// internally after such a check.
        fn load_current_index(data: &[u8]) -> u16 {
            let mut instr_fixed_data = [0u8; 2];
            let len = data.len();
            instr_fixed_data.copy_from_slice(&data[len - 2..len]);
            u16::from_le_bytes(instr_fixed_data)
        }

        /// Load the current `Instruction`'s index in the currently executing
        /// `Transaction`.
        ///
        /// # Errors
        ///
        /// Returns [`ProgramError::UnsupportedSysvar`] if the given account's ID is not equal to [`ID`].
        pub fn load_current_index_checked(
            instruction_sysvar_account_info: &AccountInfo,
        ) -> Result<u16, ProgramError> {
            if !check_id(instruction_sysvar_account_info.key) {
                return Err(ProgramError::UnsupportedSysvar);
            }

            let instruction_sysvar = instruction_sysvar_account_info.try_borrow_data()?;
            let index = load_current_index(&instruction_sysvar);
            Ok(index)
        }

        /// Store the current `Instruction`'s index in the instructions sysvar data.
        pub fn store_current_index(data: &mut [u8], instruction_index: u16) {
            let last_index = data.len() - 2;
            data[last_index..last_index + 2].copy_from_slice(&instruction_index.to_le_bytes());
        }
    }
    pub mod last_restart_slot {
        crate::declare_id!("SysvarLastRestartS1ot1111111111111111111111");
    }
    pub mod recent_blockhashes {
        crate::declare_id!("SysvarRecentB1ockHashes11111111111111111111");
    }
    pub mod rent {
        crate::declare_id!("SysvarRent111111111111111111111111111111111");
    }
    pub mod rewards {
        crate::declare_id!("SysvarRewards111111111111111111111111111111");
    }
    pub mod slot_hashes {
        crate::declare_id!("SysvarS1otHashes111111111111111111111111111");
    }
    pub mod slot_history {
        crate::declare_id!("SysvarS1otHistory11111111111111111111111111");
    }
    pub mod stake_history {
        crate::declare_id!("SysvarStakeHistory1111111111111111111111111");
    }
}

pub mod zk_token_proof_program {
    crate::declare_id!("ZkTokenProof1111111111111111111111111111111");
}

pub mod zk_elgamal_proof_program {
    crate::declare_id!("ZkE1Gama1Proof11111111111111111111111111111");
}
