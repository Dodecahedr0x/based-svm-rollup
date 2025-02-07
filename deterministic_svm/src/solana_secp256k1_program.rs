use serde::{Deserialize, Serialize};
use sha3::digest::Digest;

use crate::{FeatureSet, PrecompileError};

pub const HASHED_PUBKEY_SERIALIZED_SIZE: usize = 20;
pub const SIGNATURE_SERIALIZED_SIZE: usize = 64;
pub const SIGNATURE_OFFSETS_SERIALIZED_SIZE: usize = 11;
pub const DATA_START: usize = SIGNATURE_OFFSETS_SERIALIZED_SIZE + 1;

/// Offsets of signature data within a secp256k1 instruction.
///
/// See the [module documentation][md] for a complete description.
///
/// [md]: self
#[derive(Default, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct SecpSignatureOffsets {
    /// Offset to 64-byte signature plus 1-byte recovery ID.
    pub signature_offset: u16,
    /// Within the transaction, the index of the instruction whose instruction data contains the signature.
    pub signature_instruction_index: u8,
    /// Offset to 20-byte Ethereum address.
    pub eth_address_offset: u16,
    /// Within the transaction, the index of the instruction whose instruction data contains the address.
    pub eth_address_instruction_index: u8,
    /// Offset to start of message data.
    pub message_data_offset: u16,
    /// Size of message data in bytes.
    pub message_data_size: u16,
    /// Within the transaction, the index of the instruction whose instruction data contains the message.
    pub message_instruction_index: u8,
}

/// Sign a message and create a secp256k1 program instruction to verify the signature.
///
/// This function is suitable for simple uses of the secp256k1 program.
/// More complex uses must encode the secp256k1 instruction data manually.
/// See the [module documentation][md] for examples.
///
/// [md]: self
///
/// The instruction generated by this function must be the first instruction
/// included in a transaction or it will not verify. The
/// [`SecpSignatureOffsets`] structure encoded in the instruction data specify
/// the instruction indexes as 0.
///
/// `message_arr` is hashed with the [`keccak`] hash function prior to signing.
///
/// [`keccak`]: https://docs.rs/solana-sdk/latest/solana_sdk/keccak/index.html
#[cfg(feature = "bincode")]
pub fn new_secp256k1_instruction(
    priv_key: &libsecp256k1::SecretKey,
    message_arr: &[u8],
) -> Instruction {
    let secp_pubkey = libsecp256k1::PublicKey::from_secret_key(priv_key);
    let eth_pubkey = construct_eth_pubkey(&secp_pubkey);
    let mut hasher = sha3::Keccak256::new();
    hasher.update(message_arr);
    let message_hash = hasher.finalize();
    let mut message_hash_arr = [0u8; 32];
    message_hash_arr.copy_from_slice(message_hash.as_slice());
    let message = libsecp256k1::Message::parse(&message_hash_arr);
    let (signature, recovery_id) = libsecp256k1::sign(&message, priv_key);
    let signature_arr = signature.serialize();
    assert_eq!(signature_arr.len(), SIGNATURE_SERIALIZED_SIZE);

    let instruction_data_len = DATA_START
        .saturating_add(eth_pubkey.len())
        .saturating_add(signature_arr.len())
        .saturating_add(message_arr.len())
        .saturating_add(1);
    let mut instruction_data = vec![0; instruction_data_len];

    let eth_address_offset = DATA_START;
    instruction_data[eth_address_offset..eth_address_offset.saturating_add(eth_pubkey.len())]
        .copy_from_slice(&eth_pubkey);

    let signature_offset = DATA_START.saturating_add(eth_pubkey.len());
    instruction_data[signature_offset..signature_offset.saturating_add(signature_arr.len())]
        .copy_from_slice(&signature_arr);

    instruction_data[signature_offset.saturating_add(signature_arr.len())] =
        recovery_id.serialize();

    let message_data_offset = signature_offset
        .saturating_add(signature_arr.len())
        .saturating_add(1);
    instruction_data[message_data_offset..].copy_from_slice(message_arr);

    let num_signatures = 1;
    instruction_data[0] = num_signatures;
    let offsets = SecpSignatureOffsets {
        signature_offset: signature_offset as u16,
        signature_instruction_index: 0,
        eth_address_offset: eth_address_offset as u16,
        eth_address_instruction_index: 0,
        message_data_offset: message_data_offset as u16,
        message_data_size: message_arr.len() as u16,
        message_instruction_index: 0,
    };
    let writer = std::io::Cursor::new(&mut instruction_data[1..DATA_START]);
    bincode::serialize_into(writer, &offsets).unwrap();

    Instruction {
        program_id: solana_sdk_ids::secp256k1_program::id(),
        accounts: vec![],
        data: instruction_data,
    }
}

/// Creates an Ethereum address from a secp256k1 public key.
pub fn construct_eth_pubkey(
    pubkey: &libsecp256k1::PublicKey,
) -> [u8; HASHED_PUBKEY_SERIALIZED_SIZE] {
    let mut addr = [0u8; HASHED_PUBKEY_SERIALIZED_SIZE];
    addr.copy_from_slice(&sha3::Keccak256::digest(&pubkey.serialize()[1..])[12..]);
    assert_eq!(addr.len(), HASHED_PUBKEY_SERIALIZED_SIZE);
    addr
}

/// Verifies the signatures specified in the secp256k1 instruction data.
///
/// This is the same as the verification routine executed by the runtime's secp256k1 native program,
/// and is primarily of use to the runtime.
///
/// `data` is the secp256k1 program's instruction data. `instruction_datas` is
/// the full slice of instruction datas for all instructions in the transaction,
/// including the secp256k1 program's instruction data.
///
/// `feature_set` is the set of active Solana features. It is used to enable or
/// disable a few minor additional checks that were activated on chain
/// subsequent to the addition of the secp256k1 native program. For many
/// purposes passing `FeatureSet::all_enabled()` is reasonable.
pub fn verify(
    data: &[u8],
    instruction_datas: &[&[u8]],
    _feature_set: &FeatureSet,
) -> Result<(), PrecompileError> {
    if data.is_empty() {
        return Err(PrecompileError::InvalidInstructionDataSize);
    }
    let count = data[0] as usize;
    if count == 0 && data.len() > 1 {
        // count is zero but the instruction data indicates that is probably not
        // correct, fail the instruction to catch probable invalid secp256k1
        // instruction construction.
        return Err(PrecompileError::InvalidInstructionDataSize);
    }
    let expected_data_size = count
        .saturating_mul(SIGNATURE_OFFSETS_SERIALIZED_SIZE)
        .saturating_add(1);
    if data.len() < expected_data_size {
        return Err(PrecompileError::InvalidInstructionDataSize);
    }
    for i in 0..count {
        let start = i
            .saturating_mul(SIGNATURE_OFFSETS_SERIALIZED_SIZE)
            .saturating_add(1);
        let end = start.saturating_add(SIGNATURE_OFFSETS_SERIALIZED_SIZE);

        let offsets: SecpSignatureOffsets = bincode::deserialize(&data[start..end])
            .map_err(|_| PrecompileError::InvalidSignature)?;

        // Parse out signature
        let signature_index = offsets.signature_instruction_index as usize;
        if signature_index >= instruction_datas.len() {
            return Err(PrecompileError::InvalidInstructionDataSize);
        }
        let signature_instruction = instruction_datas[signature_index];
        let sig_start = offsets.signature_offset as usize;
        let sig_end = sig_start.saturating_add(SIGNATURE_SERIALIZED_SIZE);
        if sig_end >= signature_instruction.len() {
            return Err(PrecompileError::InvalidSignature);
        }

        let signature = libsecp256k1::Signature::parse_standard_slice(
            &signature_instruction[sig_start..sig_end],
        )
        .map_err(|_| PrecompileError::InvalidSignature)?;

        let recovery_id = libsecp256k1::RecoveryId::parse(signature_instruction[sig_end])
            .map_err(|_| PrecompileError::InvalidRecoveryId)?;

        // Parse out pubkey
        let eth_address_slice = get_data_slice(
            instruction_datas,
            offsets.eth_address_instruction_index,
            offsets.eth_address_offset,
            HASHED_PUBKEY_SERIALIZED_SIZE,
        )?;

        // Parse out message
        let message_slice = get_data_slice(
            instruction_datas,
            offsets.message_instruction_index,
            offsets.message_data_offset,
            offsets.message_data_size as usize,
        )?;

        let mut hasher = sha3::Keccak256::new();
        hasher.update(message_slice);
        let message_hash = hasher.finalize();

        let pubkey = libsecp256k1::recover(
            &libsecp256k1::Message::parse_slice(&message_hash).unwrap(),
            &signature,
            &recovery_id,
        )
        .map_err(|_| PrecompileError::InvalidSignature)?;
        let eth_address = construct_eth_pubkey(&pubkey);

        if eth_address_slice != eth_address {
            return Err(PrecompileError::InvalidSignature);
        }
    }
    Ok(())
}

fn get_data_slice<'a>(
    instruction_datas: &'a [&[u8]],
    instruction_index: u8,
    offset_start: u16,
    size: usize,
) -> Result<&'a [u8], PrecompileError> {
    let signature_index = instruction_index as usize;
    if signature_index >= instruction_datas.len() {
        return Err(PrecompileError::InvalidDataOffsets);
    }
    let signature_instruction = &instruction_datas[signature_index];
    let start = offset_start as usize;
    let end = start.saturating_add(size);
    if end > signature_instruction.len() {
        return Err(PrecompileError::InvalidSignature);
    }

    Ok(&instruction_datas[signature_index][start..end])
}
