//! Instructions for the [ed25519 native program][np].
//!
//! [np]: https://docs.solanalabs.com/runtime/programs#ed25519-program

use bytemuck::{bytes_of, Pod, Zeroable};
use ed25519_dalek::{Signature, Signer, Verifier};
use thiserror::Error;

use crate::{features::ed25519_precompile_verify_strict, FeatureSet, Instruction, PrecompileError};

pub const PUBKEY_SERIALIZED_SIZE: usize = 32;
pub const SIGNATURE_SERIALIZED_SIZE: usize = 64;
pub const SIGNATURE_OFFSETS_SERIALIZED_SIZE: usize = 14;
// bytemuck requires structures to be aligned
pub const SIGNATURE_OFFSETS_START: usize = 2;
pub const DATA_START: usize = SIGNATURE_OFFSETS_SERIALIZED_SIZE + SIGNATURE_OFFSETS_START;

#[derive(Default, Debug, Copy, Clone, Zeroable, Pod, Eq, PartialEq)]
#[repr(C)]
pub struct Ed25519SignatureOffsets {
    signature_offset: u16,             // offset to ed25519 signature of 64 bytes
    signature_instruction_index: u16,  // instruction index to find signature
    public_key_offset: u16,            // offset to public key of 32 bytes
    public_key_instruction_index: u16, // instruction index to find public key
    message_data_offset: u16,          // offset to start of message data
    message_data_size: u16,            // size of message data
    message_instruction_index: u16,    // index of instruction data to get message data
}

pub fn new_ed25519_instruction(keypair: &ed25519_dalek::Keypair, message: &[u8]) -> Instruction {
    let signature = keypair.sign(message).to_bytes();
    let pubkey = keypair.public.to_bytes();

    assert_eq!(pubkey.len(), PUBKEY_SERIALIZED_SIZE);
    assert_eq!(signature.len(), SIGNATURE_SERIALIZED_SIZE);

    let mut instruction_data = Vec::with_capacity(
        DATA_START
            .saturating_add(SIGNATURE_SERIALIZED_SIZE)
            .saturating_add(PUBKEY_SERIALIZED_SIZE)
            .saturating_add(message.len()),
    );

    let num_signatures: u8 = 1;
    let public_key_offset = DATA_START;
    let signature_offset = public_key_offset.saturating_add(PUBKEY_SERIALIZED_SIZE);
    let message_data_offset = signature_offset.saturating_add(SIGNATURE_SERIALIZED_SIZE);

    // add padding byte so that offset structure is aligned
    instruction_data.extend_from_slice(bytes_of(&[num_signatures, 0]));

    let offsets = Ed25519SignatureOffsets {
        signature_offset: signature_offset as u16,
        signature_instruction_index: u16::MAX,
        public_key_offset: public_key_offset as u16,
        public_key_instruction_index: u16::MAX,
        message_data_offset: message_data_offset as u16,
        message_data_size: message.len() as u16,
        message_instruction_index: u16::MAX,
    };

    instruction_data.extend_from_slice(bytes_of(&offsets));

    debug_assert_eq!(instruction_data.len(), public_key_offset);

    instruction_data.extend_from_slice(&pubkey);

    debug_assert_eq!(instruction_data.len(), signature_offset);

    instruction_data.extend_from_slice(&signature);

    debug_assert_eq!(instruction_data.len(), message_data_offset);

    instruction_data.extend_from_slice(message);

    Instruction {
        program_id: crate::ed25519_program::id(),
        accounts: vec![],
        data: instruction_data,
    }
}

pub fn verify(
    data: &[u8],
    instruction_datas: &[&[u8]],
    feature_set: &FeatureSet,
) -> Result<(), PrecompileError> {
    if data.len() < SIGNATURE_OFFSETS_START {
        return Err(PrecompileError::InvalidInstructionDataSize);
    }
    let num_signatures = data[0] as usize;
    if num_signatures == 0 && data.len() > SIGNATURE_OFFSETS_START {
        return Err(PrecompileError::InvalidInstructionDataSize);
    }
    let expected_data_size = num_signatures
        .saturating_mul(SIGNATURE_OFFSETS_SERIALIZED_SIZE)
        .saturating_add(SIGNATURE_OFFSETS_START);
    // We do not check or use the byte at data[1]
    if data.len() < expected_data_size {
        return Err(PrecompileError::InvalidInstructionDataSize);
    }
    for i in 0..num_signatures {
        let start = i
            .saturating_mul(SIGNATURE_OFFSETS_SERIALIZED_SIZE)
            .saturating_add(SIGNATURE_OFFSETS_START);
        let end = start.saturating_add(SIGNATURE_OFFSETS_SERIALIZED_SIZE);

        // bytemuck wants structures aligned
        let offsets: &Ed25519SignatureOffsets = bytemuck::try_from_bytes(&data[start..end])
            .map_err(|_| PrecompileError::InvalidDataOffsets)?;

        // Parse out signature
        let signature = get_data_slice(
            data,
            instruction_datas,
            offsets.signature_instruction_index,
            offsets.signature_offset,
            SIGNATURE_SERIALIZED_SIZE,
        )?;

        let signature =
            Signature::from_bytes(signature).map_err(|_| PrecompileError::InvalidSignature)?;

        // Parse out pubkey
        let pubkey = get_data_slice(
            data,
            instruction_datas,
            offsets.public_key_instruction_index,
            offsets.public_key_offset,
            PUBKEY_SERIALIZED_SIZE,
        )?;

        let publickey = ed25519_dalek::PublicKey::from_bytes(pubkey)
            .map_err(|_| PrecompileError::InvalidPublicKey)?;

        // Parse out message
        let message = get_data_slice(
            data,
            instruction_datas,
            offsets.message_instruction_index,
            offsets.message_data_offset,
            offsets.message_data_size as usize,
        )?;

        if feature_set.is_active(&ed25519_precompile_verify_strict::id()) {
            publickey
                .verify_strict(message, &signature)
                .map_err(|_| PrecompileError::InvalidSignature)?;
        } else {
            publickey
                .verify(message, &signature)
                .map_err(|_| PrecompileError::InvalidSignature)?;
        }
    }
    Ok(())
}

fn get_data_slice<'a>(
    data: &'a [u8],
    instruction_datas: &'a [&[u8]],
    instruction_index: u16,
    offset_start: u16,
    size: usize,
) -> Result<&'a [u8], PrecompileError> {
    let instruction = if instruction_index == u16::MAX {
        data
    } else {
        let signature_index = instruction_index as usize;
        if signature_index >= instruction_datas.len() {
            return Err(PrecompileError::InvalidDataOffsets);
        }
        instruction_datas[signature_index]
    };

    let start = offset_start as usize;
    let end = start.saturating_add(size);
    if end > instruction.len() {
        return Err(PrecompileError::InvalidDataOffsets);
    }

    Ok(&instruction[start..end])
}

pub trait PointValidation {
    type Point;

    /// Verifies if a byte representation of a curve point lies in the curve.
    fn validate_point(&self) -> bool;
}

pub trait GroupOperations {
    type Point;
    type Scalar;

    /// Adds two curve points: P_0 + P_1.
    fn add(left_point: &Self::Point, right_point: &Self::Point) -> Option<Self::Point>;

    /// Subtracts two curve points: P_0 - P_1.
    ///
    /// NOTE: Altneratively, one can consider replacing this with a `negate` function that maps a
    /// curve point P -> -P. Then subtraction can be computed by combining `negate` and `add`
    /// syscalls. However, `subtract` is a much more widely used function than `negate`.
    fn subtract(left_point: &Self::Point, right_point: &Self::Point) -> Option<Self::Point>;

    /// Multiplies a scalar S with a curve point P: S*P
    fn multiply(scalar: &Self::Scalar, point: &Self::Point) -> Option<Self::Point>;
}

pub trait MultiScalarMultiplication {
    type Scalar;
    type Point;

    /// Given a vector of scalsrs S_1, ..., S_N, and curve points P_1, ..., P_N, computes the
    /// "inner product": S_1*P_1 + ... + S_N*P_N.
    ///
    /// NOTE: This operation can be represented by combining `add` and `multiply` functions in
    /// `GroupOperations`, but computing it in a single batch is significantly cheaper. Given how
    /// commonly used the multiscalar multiplication (MSM) is, it seems to make sense to have a
    /// designated trait for MSM support.
    ///
    /// NOTE: The inputs to the function is a non-fixed size vector and hence, there are some
    /// complications in computing the cost for the syscall. The computational costs should only
    /// depend on the length of the vectors (and the curve), so it would be ideal to support
    /// variable length inputs and compute the syscall cost as is done in eip-197:
    /// <https://github.com/ethereum/EIPs/blob/master/EIPS/eip-197.md#gas-costs>. If not, then we can
    /// consider bounding the length of the input and assigning worst-case cost.
    fn multiscalar_multiply(
        scalars: &[Self::Scalar],
        points: &[Self::Point],
    ) -> Option<Self::Point>;
}

pub trait Pairing {
    type G1Point;
    type G2Point;
    type GTPoint;

    /// Applies the bilinear pairing operation to two curve points P1, P2 -> e(P1, P2). This trait
    /// is only relevant for "pairing-friendly" curves such as BN254 and BLS12-381.
    fn pairing_map(
        left_point: &Self::G1Point,
        right_point: &Self::G2Point,
    ) -> Option<Self::GTPoint>;
}

pub const CURVE25519_EDWARDS: u64 = 0;
pub const CURVE25519_RISTRETTO: u64 = 1;

pub const ADD: u64 = 0;
pub const SUB: u64 = 1;
pub const MUL: u64 = 2;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
#[repr(transparent)]
pub struct PodEdwardsPoint(pub [u8; 32]);

pub mod target_arch {
    use {
        super::*,
        curve25519_dalek::{
            edwards::{CompressedEdwardsY, EdwardsPoint},
            ristretto::CompressedRistretto,
            scalar::Scalar,
            traits::VartimeMultiscalarMul,
            RistrettoPoint,
        },
    };

    pub fn validate_edwards(point: &PodEdwardsPoint) -> bool {
        point.validate_point()
    }

    pub fn add_edwards(
        left_point: &PodEdwardsPoint,
        right_point: &PodEdwardsPoint,
    ) -> Option<PodEdwardsPoint> {
        PodEdwardsPoint::add(left_point, right_point)
    }

    pub fn subtract_edwards(
        left_point: &PodEdwardsPoint,
        right_point: &PodEdwardsPoint,
    ) -> Option<PodEdwardsPoint> {
        PodEdwardsPoint::subtract(left_point, right_point)
    }

    pub fn multiply_edwards(
        scalar: &PodScalar,
        point: &PodEdwardsPoint,
    ) -> Option<PodEdwardsPoint> {
        PodEdwardsPoint::multiply(scalar, point)
    }

    pub fn multiscalar_multiply_edwards(
        scalars: &[PodScalar],
        points: &[PodEdwardsPoint],
    ) -> Option<PodEdwardsPoint> {
        PodEdwardsPoint::multiscalar_multiply(scalars, points)
    }

    impl From<&EdwardsPoint> for PodEdwardsPoint {
        fn from(point: &EdwardsPoint) -> Self {
            Self(point.compress().to_bytes())
        }
    }

    impl TryFrom<&PodEdwardsPoint> for EdwardsPoint {
        type Error = Curve25519Error;

        fn try_from(pod: &PodEdwardsPoint) -> Result<Self, Self::Error> {
            let Ok(compressed_edwards_y) = CompressedEdwardsY::from_slice(&pod.0) else {
                return Err(Curve25519Error::PodConversion);
            };
            compressed_edwards_y
                .decompress()
                .ok_or(Curve25519Error::PodConversion)
        }
    }

    impl PointValidation for PodEdwardsPoint {
        type Point = Self;

        fn validate_point(&self) -> bool {
            let Ok(compressed_edwards_y) = CompressedEdwardsY::from_slice(&self.0) else {
                return false;
            };
            compressed_edwards_y.decompress().is_some()
        }
    }

    impl GroupOperations for PodEdwardsPoint {
        type Scalar = PodScalar;
        type Point = Self;

        fn add(left_point: &Self, right_point: &Self) -> Option<Self> {
            let left_point: EdwardsPoint = left_point.try_into().ok()?;
            let right_point: EdwardsPoint = right_point.try_into().ok()?;

            let result = &left_point + &right_point;
            Some((&result).into())
        }

        fn subtract(left_point: &Self, right_point: &Self) -> Option<Self> {
            let left_point: EdwardsPoint = left_point.try_into().ok()?;
            let right_point: EdwardsPoint = right_point.try_into().ok()?;

            let result = &left_point - &right_point;
            Some((&result).into())
        }

        fn multiply(scalar: &PodScalar, point: &Self) -> Option<Self> {
            let scalar: Scalar = scalar.try_into().ok()?;
            let point: EdwardsPoint = point.try_into().ok()?;

            let result = &scalar * &point;
            Some((&result).into())
        }
    }

    impl MultiScalarMultiplication for PodEdwardsPoint {
        type Scalar = PodScalar;
        type Point = Self;

        fn multiscalar_multiply(scalars: &[PodScalar], points: &[Self]) -> Option<Self> {
            let scalars = scalars
                .iter()
                .map(|scalar| Scalar::try_from(scalar).ok())
                .collect::<Option<Vec<_>>>()?;

            EdwardsPoint::optional_multiscalar_mul(
                scalars,
                points
                    .iter()
                    .map(|point| EdwardsPoint::try_from(point).ok()),
            )
            .map(|result| PodEdwardsPoint::from(&result))
        }
    }

    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
    #[repr(transparent)]
    pub struct PodRistrettoPoint(pub [u8; 32]);

    pub fn validate_ristretto(point: &PodRistrettoPoint) -> bool {
        point.validate_point()
    }

    pub fn add_ristretto(
        left_point: &PodRistrettoPoint,
        right_point: &PodRistrettoPoint,
    ) -> Option<PodRistrettoPoint> {
        PodRistrettoPoint::add(left_point, right_point)
    }

    pub fn subtract_ristretto(
        left_point: &PodRistrettoPoint,
        right_point: &PodRistrettoPoint,
    ) -> Option<PodRistrettoPoint> {
        PodRistrettoPoint::subtract(left_point, right_point)
    }

    pub fn multiply_ristretto(
        scalar: &PodScalar,
        point: &PodRistrettoPoint,
    ) -> Option<PodRistrettoPoint> {
        PodRistrettoPoint::multiply(scalar, point)
    }

    pub fn multiscalar_multiply_ristretto(
        scalars: &[PodScalar],
        points: &[PodRistrettoPoint],
    ) -> Option<PodRistrettoPoint> {
        PodRistrettoPoint::multiscalar_multiply(scalars, points)
    }

    impl From<&RistrettoPoint> for PodRistrettoPoint {
        fn from(point: &RistrettoPoint) -> Self {
            PodRistrettoPoint(point.compress().to_bytes())
        }
    }

    impl TryFrom<&PodRistrettoPoint> for RistrettoPoint {
        type Error = Curve25519Error;

        fn try_from(pod: &PodRistrettoPoint) -> Result<Self, Self::Error> {
            let Ok(compressed_ristretto) = CompressedRistretto::from_slice(&pod.0) else {
                return Err(Curve25519Error::PodConversion);
            };
            compressed_ristretto
                .decompress()
                .ok_or(Curve25519Error::PodConversion)
        }
    }

    impl PointValidation for PodRistrettoPoint {
        type Point = Self;

        fn validate_point(&self) -> bool {
            let Ok(compressed_ristretto) = CompressedRistretto::from_slice(&self.0) else {
                return false;
            };
            compressed_ristretto.decompress().is_some()
        }
    }

    impl GroupOperations for PodRistrettoPoint {
        type Scalar = PodScalar;
        type Point = Self;

        fn add(left_point: &Self, right_point: &Self) -> Option<Self> {
            let left_point: RistrettoPoint = left_point.try_into().ok()?;
            let right_point: RistrettoPoint = right_point.try_into().ok()?;

            let result = &left_point + &right_point;
            Some((&result).into())
        }

        fn subtract(left_point: &Self, right_point: &Self) -> Option<Self> {
            let left_point: RistrettoPoint = left_point.try_into().ok()?;
            let right_point: RistrettoPoint = right_point.try_into().ok()?;

            let result = &left_point - &right_point;
            Some((&result).into())
        }

        fn multiply(scalar: &PodScalar, point: &Self) -> Option<Self> {
            let scalar: Scalar = scalar.try_into().ok()?;
            let point: RistrettoPoint = point.try_into().ok()?;

            let result = &scalar * &point;
            Some((&result).into())
        }
    }

    impl MultiScalarMultiplication for PodRistrettoPoint {
        type Scalar = PodScalar;
        type Point = Self;

        fn multiscalar_multiply(scalars: &[PodScalar], points: &[Self]) -> Option<Self> {
            let scalars = scalars
                .iter()
                .map(|scalar| Scalar::try_from(scalar).ok())
                .collect::<Option<Vec<_>>>()?;

            RistrettoPoint::optional_multiscalar_mul(
                scalars,
                points
                    .iter()
                    .map(|point| RistrettoPoint::try_from(point).ok()),
            )
            .map(|result| PodRistrettoPoint::from(&result))
        }
    }

    impl From<&Scalar> for PodScalar {
        fn from(scalar: &Scalar) -> Self {
            Self(scalar.to_bytes())
        }
    }

    impl TryFrom<&PodScalar> for Scalar {
        type Error = Curve25519Error;

        fn try_from(pod: &PodScalar) -> Result<Self, Self::Error> {
            Scalar::from_canonical_bytes(pod.0)
                .into_option()
                .ok_or(Curve25519Error::PodConversion)
        }
    }

    impl From<Scalar> for PodScalar {
        fn from(scalar: Scalar) -> Self {
            Self(scalar.to_bytes())
        }
    }

    impl TryFrom<PodScalar> for Scalar {
        type Error = Curve25519Error;

        fn try_from(pod: PodScalar) -> Result<Self, Self::Error> {
            Scalar::from_canonical_bytes(pod.0)
                .into_option()
                .ok_or(Curve25519Error::PodConversion)
        }
    }
}

#[derive(Error, Clone, Debug, Eq, PartialEq)]
pub enum Curve25519Error {
    #[error("pod conversion failed")]
    PodConversion,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
#[repr(transparent)]
pub struct PodScalar(pub [u8; 32]);
