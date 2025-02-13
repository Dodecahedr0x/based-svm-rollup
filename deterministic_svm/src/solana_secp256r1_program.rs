use bytemuck::{Pod, Zeroable};
use p256::{
    ecdsa::{
        signature::{Signer, Verifier},
        Signature, SigningKey, VerifyingKey,
    },
    elliptic_curve::{
        bigint::{Encoding, U256},
        Curve,
    },
    EncodedPoint, NistP256,
};

use crate::{FeatureSet, PrecompileError};

pub const COMPRESSED_PUBKEY_SERIALIZED_SIZE: usize = 33;
pub const SIGNATURE_SERIALIZED_SIZE: usize = 64;
pub const SIGNATURE_OFFSETS_SERIALIZED_SIZE: usize = 14;
pub const SIGNATURE_OFFSETS_START: usize = 2;
pub const DATA_START: usize = SIGNATURE_OFFSETS_SERIALIZED_SIZE + SIGNATURE_OFFSETS_START;
pub const FIELD_SIZE: usize = 32;

#[derive(Default, Debug, Copy, Clone, Zeroable, Pod, Eq, PartialEq)]
#[repr(C)]
pub struct Secp256r1SignatureOffsets {
    pub signature_offset: u16,
    pub signature_instruction_index: u16,
    pub public_key_offset: u16,
    pub public_key_instruction_index: u16,
    pub message_data_offset: u16,
    pub message_data_size: u16,
    pub message_instruction_index: u16,
}

pub fn new_secp256r1_instruction(
    message: &[u8],
    signing_key: &SigningKey,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let verifying_key = VerifyingKey::from(signing_key);
    let pubkey = EncodedPoint::from(verifying_key).to_bytes();
    let signature: Signature = signing_key.sign(message);

    let (r, s) = signature.split_bytes();
    let mut signature_bytes = vec![0u8; SIGNATURE_SERIALIZED_SIZE];

    signature_bytes[..FIELD_SIZE].copy_from_slice(&r);
    signature_bytes[FIELD_SIZE..].copy_from_slice(&s);

    let order = NistP256::ORDER;
    let half_order = order.shr(1);
    let s_value = U256::from_be_bytes(s.into());

    if s_value > half_order {
        let new_s = NistP256::ORDER.wrapping_sub(&s_value);
        let new_s_bytes = new_s.to_be_bytes();
        signature_bytes[FIELD_SIZE..].copy_from_slice(&new_s_bytes);
    }

    let mut instruction_data = Vec::with_capacity(
        COMPRESSED_PUBKEY_SERIALIZED_SIZE + SIGNATURE_SERIALIZED_SIZE + message.len(),
    );

    instruction_data.extend_from_slice(&pubkey);
    instruction_data.extend_from_slice(&signature_bytes);
    instruction_data.extend_from_slice(message);

    Ok(instruction_data)
}

pub fn verify(
    data: &[u8],
    instruction_datas: &[&[u8]],
    _feature_set: &FeatureSet,
) -> Result<(), PrecompileError> {
    if data.len() < SIGNATURE_OFFSETS_START {
        return Err(PrecompileError::InvalidInstructionDataSize);
    }
    let num_signatures = data[0] as usize;
    if num_signatures == 0 {
        return Err(PrecompileError::InvalidInstructionDataSize);
    }
    if num_signatures > 8 {
        return Err(PrecompileError::InvalidInstructionDataSize);
    }

    let expected_data_size = num_signatures
        .saturating_mul(SIGNATURE_OFFSETS_SERIALIZED_SIZE)
        .saturating_add(SIGNATURE_OFFSETS_START);

    // We do not check or use the byte at data[1]
    if data.len() < expected_data_size {
        return Err(PrecompileError::InvalidInstructionDataSize);
    }

    // let verifying_key = VerifyingKey::from_encoded_point(
    //     &EncodedPoint::from_bytes(pubkey_bytes)
    //         .map_err(|_| PrecompileError::InvalidInstructionDataSize)?,
    // )
    // .map_err(|_| PrecompileError::InvalidInstructionDataSize)?;
    // let signature = Signature::from_bytes(
    //     signature_bytes
    //         .try_into()
    //         .map_err(|_| PrecompileError::InvalidInstructionDataSize)?,
    // )
    // .map_err(|_| PrecompileError::InvalidInstructionDataSize)?;

    // verifying_key
    //     .verify(message, &signature)
    //     .map_err(|_| PrecompileError::InvalidInstructionDataSize)?;
    Ok(())
}
