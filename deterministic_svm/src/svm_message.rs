use std::{
    collections::BTreeMap,
    fmt::{self, Debug},
    iter::zip,
    ops::Index,
};

use serde::{Deserialize, Serialize};

use crate::{
    ed25519_program, secp256k1_program, secp256r1_program, system_program, v0, CompiledInstruction,
    Hash, Instruction, Pubkey, SanitizedMessage,
};

const NONCED_TX_MARKER_IX_INDEX: u8 = 0;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SVMInstruction<'a> {
    /// Index into the transaction keys array indicating the program account that executes this instruction.
    pub program_id_index: u8,
    /// Ordered indices into the transaction keys array indicating which accounts to pass to the program.
    pub accounts: &'a [u8],
    /// The program input data.
    pub data: &'a [u8],
}

impl<'a> From<&'a CompiledInstruction> for SVMInstruction<'a> {
    fn from(ix: &'a CompiledInstruction) -> Self {
        Self {
            program_id_index: ix.program_id_index,
            accounts: ix.accounts.as_slice(),
            data: ix.data.as_slice(),
        }
    }
}

#[derive(Default, Debug, PartialEq, Eq, Clone, Copy, Deserialize, Serialize)]
pub struct MessageHeader {
    /// The number of signatures required for this message to be considered
    /// valid. The signers of those signatures must match the first
    /// `num_required_signatures` of [`Message::account_keys`].
    // NOTE: Serialization-related changes must be paired with the direct read at sigverify.
    pub num_required_signatures: u8,

    /// The last `num_readonly_signed_accounts` of the signed keys are read-only
    /// accounts.
    pub num_readonly_signed_accounts: u8,

    /// The last `num_readonly_unsigned_accounts` of the unsigned keys are
    /// read-only accounts.
    pub num_readonly_unsigned_accounts: u8,
}

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub(crate) struct CompiledKeys {
    payer: Option<Pubkey>,
    key_meta_map: BTreeMap<Pubkey, CompiledKeyMeta>,
}

#[derive(PartialEq, Debug, Eq, Clone)]
pub enum CompileError {
    AccountIndexOverflow,
    AddressTableLookupIndexOverflow,
    UnknownInstructionKey(Pubkey),
}

impl std::error::Error for CompileError {}

impl fmt::Display for CompileError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CompileError::AccountIndexOverflow => {
                f.write_str("account index overflowed during compilation")
            }
            CompileError::AddressTableLookupIndexOverflow => {
                f.write_str("address lookup table index overflowed during compilation")
            }
            CompileError::UnknownInstructionKey(key) => f.write_fmt(format_args!(
                "encountered unknown account key `{0}` during instruction compilation",
                key,
            )),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AddressLookupTableAccount {
    pub key: Pubkey,
    pub addresses: Vec<Pubkey>,
}

#[derive(Default, Debug, Clone, PartialEq, Eq)]
struct CompiledKeyMeta {
    is_signer: bool,
    is_writable: bool,
    is_invoked: bool,
}

impl CompiledKeys {
    /// Compiles the pubkeys referenced by a list of instructions and organizes by
    /// signer/non-signer and writable/readonly.
    pub(crate) fn compile(instructions: &[Instruction], payer: Option<Pubkey>) -> Self {
        let mut key_meta_map = BTreeMap::<Pubkey, CompiledKeyMeta>::new();
        for ix in instructions {
            let meta = key_meta_map.entry(ix.program_id).or_default();
            meta.is_invoked = true;
            for account_meta in &ix.accounts {
                let meta = key_meta_map.entry(account_meta.pubkey).or_default();
                meta.is_signer |= account_meta.is_signer;
                meta.is_writable |= account_meta.is_writable;
            }
        }
        if let Some(payer) = &payer {
            let meta = key_meta_map.entry(*payer).or_default();
            meta.is_signer = true;
            meta.is_writable = true;
        }
        Self {
            payer,
            key_meta_map,
        }
    }

    pub(crate) fn try_into_message_components(
        self,
    ) -> Result<(MessageHeader, Vec<Pubkey>), CompileError> {
        let try_into_u8 = |num: usize| -> Result<u8, CompileError> {
            u8::try_from(num).map_err(|_| CompileError::AccountIndexOverflow)
        };

        let Self {
            payer,
            mut key_meta_map,
        } = self;

        if let Some(payer) = &payer {
            key_meta_map.remove_entry(payer);
        }

        let writable_signer_keys: Vec<Pubkey> = payer
            .into_iter()
            .chain(
                key_meta_map
                    .iter()
                    .filter_map(|(key, meta)| (meta.is_signer && meta.is_writable).then_some(*key)),
            )
            .collect();
        let readonly_signer_keys: Vec<Pubkey> = key_meta_map
            .iter()
            .filter_map(|(key, meta)| (meta.is_signer && !meta.is_writable).then_some(*key))
            .collect();
        let writable_non_signer_keys: Vec<Pubkey> = key_meta_map
            .iter()
            .filter_map(|(key, meta)| (!meta.is_signer && meta.is_writable).then_some(*key))
            .collect();
        let readonly_non_signer_keys: Vec<Pubkey> = key_meta_map
            .iter()
            .filter_map(|(key, meta)| (!meta.is_signer && !meta.is_writable).then_some(*key))
            .collect();

        let signers_len = writable_signer_keys
            .len()
            .saturating_add(readonly_signer_keys.len());

        let header = MessageHeader {
            num_required_signatures: try_into_u8(signers_len)?,
            num_readonly_signed_accounts: try_into_u8(readonly_signer_keys.len())?,
            num_readonly_unsigned_accounts: try_into_u8(readonly_non_signer_keys.len())?,
        };

        let static_account_keys = std::iter::empty()
            .chain(writable_signer_keys)
            .chain(readonly_signer_keys)
            .chain(writable_non_signer_keys)
            .chain(readonly_non_signer_keys)
            .collect();

        Ok((header, static_account_keys))
    }

    pub(crate) fn try_extract_table_lookup(
        &mut self,
        lookup_table_account: &AddressLookupTableAccount,
    ) -> Result<Option<(v0::MessageAddressTableLookup, v0::LoadedAddresses)>, CompileError> {
        let (writable_indexes, drained_writable_keys) = self
            .try_drain_keys_found_in_lookup_table(&lookup_table_account.addresses, |meta| {
                !meta.is_signer && !meta.is_invoked && meta.is_writable
            })?;
        let (readonly_indexes, drained_readonly_keys) = self
            .try_drain_keys_found_in_lookup_table(&lookup_table_account.addresses, |meta| {
                !meta.is_signer && !meta.is_invoked && !meta.is_writable
            })?;

        // Don't extract lookup if no keys were found
        if writable_indexes.is_empty() && readonly_indexes.is_empty() {
            return Ok(None);
        }

        Ok(Some((
            v0::MessageAddressTableLookup {
                account_key: lookup_table_account.key,
                writable_indexes,
                readonly_indexes,
            },
            v0::LoadedAddresses {
                writable: drained_writable_keys,
                readonly: drained_readonly_keys,
            },
        )))
    }

    fn try_drain_keys_found_in_lookup_table(
        &mut self,
        lookup_table_addresses: &[Pubkey],
        key_meta_filter: impl Fn(&CompiledKeyMeta) -> bool,
    ) -> Result<(Vec<u8>, Vec<Pubkey>), CompileError> {
        let mut lookup_table_indexes = Vec::new();
        let mut drained_keys = Vec::new();

        for search_key in self
            .key_meta_map
            .iter()
            .filter_map(|(key, meta)| key_meta_filter(meta).then_some(key))
        {
            for (key_index, key) in lookup_table_addresses.iter().enumerate() {
                if key == search_key {
                    let lookup_table_index = u8::try_from(key_index)
                        .map_err(|_| CompileError::AddressTableLookupIndexOverflow)?;

                    lookup_table_indexes.push(lookup_table_index);
                    drained_keys.push(*search_key);
                    break;
                }
            }
        }

        for key in &drained_keys {
            self.key_meta_map.remove_entry(key);
        }

        Ok((lookup_table_indexes, drained_keys))
    }
}

#[derive(Clone, Default, Debug, Eq)]
pub struct AccountKeys<'a> {
    static_keys: &'a [Pubkey],
    dynamic_keys: Option<&'a v0::LoadedAddresses>,
}

impl Index<usize> for AccountKeys<'_> {
    type Output = Pubkey;
    #[inline]
    fn index(&self, index: usize) -> &Self::Output {
        self.get(index).expect("index is invalid")
    }
}

impl<'a> AccountKeys<'a> {
    pub fn new(static_keys: &'a [Pubkey], dynamic_keys: Option<&'a v0::LoadedAddresses>) -> Self {
        Self {
            static_keys,
            dynamic_keys,
        }
    }

    /// Returns an iterator of account key segments. The ordering of segments
    /// affects how account indexes from compiled instructions are resolved and
    /// so should not be changed.
    #[inline]
    fn key_segment_iter(&self) -> impl Iterator<Item = &'a [Pubkey]> + Clone {
        if let Some(dynamic_keys) = self.dynamic_keys {
            [
                self.static_keys,
                &dynamic_keys.writable,
                &dynamic_keys.readonly,
            ]
            .into_iter()
        } else {
            // empty segments added for branch type compatibility
            [self.static_keys, &[], &[]].into_iter()
        }
    }

    /// Returns the address of the account at the specified index of the list of
    /// message account keys constructed from static keys, followed by dynamically
    /// loaded writable addresses, and lastly the list of dynamically loaded
    /// readonly addresses.
    #[inline]
    pub fn get(&self, mut index: usize) -> Option<&'a Pubkey> {
        for key_segment in self.key_segment_iter() {
            if index < key_segment.len() {
                return Some(&key_segment[index]);
            }
            index = index.saturating_sub(key_segment.len());
        }

        None
    }

    /// Returns the total length of loaded accounts for a message
    #[inline]
    pub fn len(&self) -> usize {
        let mut len = 0usize;
        for key_segment in self.key_segment_iter() {
            len = len.saturating_add(key_segment.len());
        }
        len
    }

    /// Returns true if this collection of account keys is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Iterator for the addresses of the loaded accounts for a message
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = &'a Pubkey> + Clone {
        self.key_segment_iter().flatten()
    }

    /// Compile instructions using the order of account keys to determine
    /// compiled instruction account indexes.
    ///
    /// # Panics
    ///
    /// Panics when compiling fails. See [`AccountKeys::try_compile_instructions`]
    /// for a full description of failure scenarios.
    pub fn compile_instructions(&self, instructions: &[Instruction]) -> Vec<CompiledInstruction> {
        self.try_compile_instructions(instructions)
            .expect("compilation failure")
    }

    /// Compile instructions using the order of account keys to determine
    /// compiled instruction account indexes.
    ///
    /// # Errors
    ///
    /// Compilation will fail if any `instructions` use account keys which are not
    /// present in this account key collection.
    ///
    /// Compilation will fail if any `instructions` use account keys which are located
    /// at an index which cannot be cast to a `u8` without overflow.
    pub fn try_compile_instructions(
        &self,
        instructions: &[Instruction],
    ) -> Result<Vec<CompiledInstruction>, CompileError> {
        let mut account_index_map = BTreeMap::<&Pubkey, u8>::new();
        for (index, key) in self.iter().enumerate() {
            let index = u8::try_from(index).map_err(|_| CompileError::AccountIndexOverflow)?;
            account_index_map.insert(key, index);
        }

        let get_account_index = |key: &Pubkey| -> Result<u8, CompileError> {
            account_index_map
                .get(key)
                .cloned()
                .ok_or(CompileError::UnknownInstructionKey(*key))
        };

        instructions
            .iter()
            .map(|ix| {
                let accounts: Vec<u8> = ix
                    .accounts
                    .iter()
                    .map(|account_meta| get_account_index(&account_meta.pubkey))
                    .collect::<Result<Vec<u8>, CompileError>>()?;

                Ok(CompiledInstruction {
                    program_id_index: get_account_index(&ix.program_id)?,
                    data: ix.data.clone(),
                    accounts,
                })
            })
            .collect()
    }
}

impl PartialEq for AccountKeys<'_> {
    fn eq(&self, other: &Self) -> bool {
        zip(self.iter(), other.iter()).all(|(a, b)| a == b)
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SVMMessageAddressTableLookup<'a> {
    /// Address lookup table account key
    pub account_key: &'a Pubkey,
    /// List of indexes used to load writable account addresses
    pub writable_indexes: &'a [u8],
    /// List of indexes used to load readonly account addresses
    pub readonly_indexes: &'a [u8],
}

impl<'a> From<&'a v0::MessageAddressTableLookup> for SVMMessageAddressTableLookup<'a> {
    fn from(lookup: &'a v0::MessageAddressTableLookup) -> Self {
        Self {
            account_key: &lookup.account_key,
            writable_indexes: &lookup.writable_indexes,
            readonly_indexes: &lookup.readonly_indexes,
        }
    }
}

// - Debug to support legacy logging
pub trait SVMMessage: Debug {
    /// Return the number of transaction-level signatures in the message.
    fn num_transaction_signatures(&self) -> u64;
    /// Return the number of ed25519 precompile signatures in the message.
    fn num_ed25519_signatures(&self) -> u64 {
        default_precompile_signature_count(&ed25519_program::ID, self.program_instructions_iter())
    }
    /// Return the number of secp256k1 precompile signatures in the message.
    fn num_secp256k1_signatures(&self) -> u64 {
        default_precompile_signature_count(&secp256k1_program::ID, self.program_instructions_iter())
    }
    /// Return the number of secp256r1 precompile signatures in the message.
    fn num_secp256r1_signatures(&self) -> u64 {
        default_precompile_signature_count(&secp256r1_program::ID, self.program_instructions_iter())
    }

    /// Returns the number of requested write-locks in this message.
    /// This does not consider if write-locks are demoted.
    fn num_write_locks(&self) -> u64;

    /// Return the recent blockhash.
    fn recent_blockhash(&self) -> &Hash;

    /// Return the number of instructions in the message.
    fn num_instructions(&self) -> usize;

    /// Return an iterator over the instructions in the message.
    fn instructions_iter(&self) -> impl Iterator<Item = SVMInstruction>;

    /// Return an iterator over the instructions in the message, paired with
    /// the pubkey of the program.
    fn program_instructions_iter(&self) -> impl Iterator<Item = (&Pubkey, SVMInstruction)> + Clone;

    /// Return the account keys.
    fn account_keys(&self) -> AccountKeys;

    /// Return the fee-payer
    fn fee_payer(&self) -> &Pubkey;

    /// Returns `true` if the account at `index` is writable.
    fn is_writable(&self, index: usize) -> bool;

    /// Returns `true` if the account at `index` is signer.
    fn is_signer(&self, index: usize) -> bool;

    /// Returns true if the account at the specified index is invoked as a
    /// program in top-level instructions of this message.
    fn is_invoked(&self, key_index: usize) -> bool;

    /// Returns true if the account at the specified index is an input to some
    /// program instruction in this message.
    fn is_instruction_account(&self, key_index: usize) -> bool {
        if let Ok(key_index) = u8::try_from(key_index) {
            self.instructions_iter()
                .any(|ix| ix.accounts.contains(&key_index))
        } else {
            false
        }
    }

    /// If the message uses a durable nonce, return the pubkey of the nonce account
    fn get_durable_nonce(&self) -> Option<&Pubkey> {
        let account_keys = self.account_keys();
        self.instructions_iter()
            .nth(usize::from(NONCED_TX_MARKER_IX_INDEX))
            .filter(
                |ix| match account_keys.get(usize::from(ix.program_id_index)) {
                    Some(program_id) => system_program::check_id(program_id),
                    _ => false,
                },
            )
            .filter(|ix| {
                /// Serialized value of [`SystemInstruction::AdvanceNonceAccount`].
                const SERIALIZED_ADVANCE_NONCE_ACCOUNT: [u8; 4] = 4u32.to_le_bytes();
                const SERIALIZED_SIZE: usize = SERIALIZED_ADVANCE_NONCE_ACCOUNT.len();

                ix.data
                    .get(..SERIALIZED_SIZE)
                    .map(|data| data == SERIALIZED_ADVANCE_NONCE_ACCOUNT)
                    .unwrap_or(false)
            })
            .and_then(|ix| {
                ix.accounts.first().and_then(|idx| {
                    let index = usize::from(*idx);
                    if !self.is_writable(index) {
                        None
                    } else {
                        account_keys.get(index)
                    }
                })
            })
    }

    /// For the instruction at `index`, return an iterator over input accounts
    /// that are signers.
    fn get_ix_signers(&self, index: usize) -> impl Iterator<Item = &Pubkey> {
        self.instructions_iter()
            .nth(index)
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

    /// Get the number of lookup tables.
    fn num_lookup_tables(&self) -> usize;

    /// Get message address table lookups used in the message
    fn message_address_table_lookups(&self) -> impl Iterator<Item = SVMMessageAddressTableLookup>;
}

fn default_precompile_signature_count<'a>(
    precompile: &Pubkey,
    instructions: impl Iterator<Item = (&'a Pubkey, SVMInstruction<'a>)>,
) -> u64 {
    instructions
        .filter(|(program_id, _)| *program_id == precompile)
        .map(|(_, ix)| u64::from(ix.data.first().copied().unwrap_or(0)))
        .sum()
}

impl SVMMessage for SanitizedMessage {
    fn num_transaction_signatures(&self) -> u64 {
        u64::from(self.header().num_required_signatures)
    }

    fn num_write_locks(&self) -> u64 {
        SanitizedMessage::num_write_locks(self)
    }

    fn recent_blockhash(&self) -> &Hash {
        SanitizedMessage::recent_blockhash(self)
    }

    fn num_instructions(&self) -> usize {
        SanitizedMessage::instructions(self).len()
    }

    fn instructions_iter(&self) -> impl Iterator<Item = SVMInstruction> {
        SanitizedMessage::instructions(self)
            .iter()
            .map(SVMInstruction::from)
    }

    fn program_instructions_iter(&self) -> impl Iterator<Item = (&Pubkey, SVMInstruction)> + Clone {
        SanitizedMessage::program_instructions_iter(self)
            .map(|(pubkey, ix)| (pubkey, SVMInstruction::from(ix)))
    }

    fn account_keys(&self) -> AccountKeys {
        SanitizedMessage::account_keys(self)
    }

    fn fee_payer(&self) -> &Pubkey {
        SanitizedMessage::fee_payer(self)
    }

    fn is_writable(&self, index: usize) -> bool {
        SanitizedMessage::is_writable(self, index)
    }

    fn is_signer(&self, index: usize) -> bool {
        SanitizedMessage::is_signer(self, index)
    }

    fn is_invoked(&self, key_index: usize) -> bool {
        SanitizedMessage::is_invoked(self, key_index)
    }

    fn num_lookup_tables(&self) -> usize {
        SanitizedMessage::message_address_table_lookups(self).len()
    }

    fn message_address_table_lookups(&self) -> impl Iterator<Item = SVMMessageAddressTableLookup> {
        SanitizedMessage::message_address_table_lookups(self)
            .iter()
            .map(SVMMessageAddressTableLookup::from)
    }
}
