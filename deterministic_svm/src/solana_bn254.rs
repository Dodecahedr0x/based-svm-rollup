use {
    bytemuck::{Pod, Zeroable},
    consts::*,
    thiserror::Error,
};

pub mod prelude {
    pub use super::{
        alt_bn128_compression_size::*, consts::*, target_arch::*, AltBn128CompressionError,
        AltBn128Error,
    };
}

mod alt_bn128_compression_size {
    pub const G1: usize = 64;
    pub const G2: usize = 128;
    pub const G1_COMPRESSED: usize = 32;
    pub const G2_COMPRESSED: usize = 64;
}

// AltBn128CompressionError must be removed once the
// simplify_alt_bn128_syscall_error_codes feature gets activated
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AltBn128CompressionError {
    #[error("Unexpected error")]
    UnexpectedError,
    #[error("Failed to decompress g1")]
    G1DecompressionFailed,
    #[error("Failed to decompress g2")]
    G2DecompressionFailed,
    #[error("Failed to compress affine g1")]
    G1CompressionFailed,
    #[error("Failed to compress affine g2")]
    G2CompressionFailed,
    #[error("Invalid input size")]
    InvalidInputSize,
}

impl From<u64> for AltBn128CompressionError {
    fn from(v: u64) -> AltBn128CompressionError {
        match v {
            1 => AltBn128CompressionError::G1DecompressionFailed,
            2 => AltBn128CompressionError::G2DecompressionFailed,
            3 => AltBn128CompressionError::G1CompressionFailed,
            4 => AltBn128CompressionError::G2CompressionFailed,
            5 => AltBn128CompressionError::InvalidInputSize,
            _ => AltBn128CompressionError::UnexpectedError,
        }
    }
}

impl From<AltBn128CompressionError> for u64 {
    fn from(v: AltBn128CompressionError) -> u64 {
        // note: should never return 0, as it risks to be confused with syscall success
        match v {
            AltBn128CompressionError::G1DecompressionFailed => 1,
            AltBn128CompressionError::G2DecompressionFailed => 2,
            AltBn128CompressionError::G1CompressionFailed => 3,
            AltBn128CompressionError::G2CompressionFailed => 4,
            AltBn128CompressionError::InvalidInputSize => 5,
            AltBn128CompressionError::UnexpectedError => 6,
        }
    }
}

mod consts {
    /// Input length for the add operation.
    pub const ALT_BN128_ADDITION_INPUT_LEN: usize = 128;

    /// Input length for the multiplication operation.
    pub const ALT_BN128_MULTIPLICATION_INPUT_LEN: usize = 96;

    /// Pair element length.
    pub const ALT_BN128_PAIRING_ELEMENT_LEN: usize = 192;

    /// Output length for the add operation.
    pub const ALT_BN128_ADDITION_OUTPUT_LEN: usize = 64;

    /// Output length for the multiplication operation.
    pub const ALT_BN128_MULTIPLICATION_OUTPUT_LEN: usize = 64;

    /// Output length for pairing operation.
    pub const ALT_BN128_PAIRING_OUTPUT_LEN: usize = 32;

    /// Size of the EC point field, in bytes.
    pub const ALT_BN128_FIELD_SIZE: usize = 32;

    /// Size of the EC point. `alt_bn128` point contains
    /// the consistently united x and y fields as 64 bytes.
    pub const ALT_BN128_POINT_SIZE: usize = 64;

    pub const ALT_BN128_ADD: u64 = 0;
    pub const ALT_BN128_SUB: u64 = 1;
    pub const ALT_BN128_MUL: u64 = 2;
    pub const ALT_BN128_PAIRING: u64 = 3;

    pub const ALT_BN128_G1_COMPRESS: u64 = 0;
    pub const ALT_BN128_G1_DECOMPRESS: u64 = 1;
    pub const ALT_BN128_G2_COMPRESS: u64 = 2;
    pub const ALT_BN128_G2_DECOMPRESS: u64 = 3;
}

// AltBn128Error must be removed once the
// simplify_alt_bn128_syscall_error_codes feature gets activated
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AltBn128Error {
    #[error("The input data is invalid")]
    InvalidInputData,
    #[error("Invalid group data")]
    GroupError,
    #[error("Slice data is going out of input data bounds")]
    SliceOutOfBounds,
    #[error("Unexpected error")]
    UnexpectedError,
    #[error("Failed to convert a byte slice into a vector {0:?}")]
    TryIntoVecError(Vec<u8>),
    #[error("Failed to convert projective to affine g1")]
    ProjectiveToG1Failed,
}

impl From<u64> for AltBn128Error {
    fn from(v: u64) -> AltBn128Error {
        match v {
            1 => AltBn128Error::InvalidInputData,
            2 => AltBn128Error::GroupError,
            3 => AltBn128Error::SliceOutOfBounds,
            4 => AltBn128Error::TryIntoVecError(Vec::new()),
            5 => AltBn128Error::ProjectiveToG1Failed,
            _ => AltBn128Error::UnexpectedError,
        }
    }
}

impl From<AltBn128Error> for u64 {
    fn from(v: AltBn128Error) -> u64 {
        // note: should never return 0, as it risks to be confused with syscall success
        match v {
            AltBn128Error::InvalidInputData => 1,
            AltBn128Error::GroupError => 2,
            AltBn128Error::SliceOutOfBounds => 3,
            AltBn128Error::TryIntoVecError(_) => 4,
            AltBn128Error::ProjectiveToG1Failed => 5,
            AltBn128Error::UnexpectedError => 6,
        }
    }
}

use consts::{ALT_BN128_FIELD_SIZE as FIELD_SIZE, ALT_BN128_POINT_SIZE as G1_POINT_SIZE};

/// The BN254 (BN128) group element in G1 as a POD type.
///
/// A group element in G1 consists of two field elements `(x, y)`. A `PodG1`
/// type expects a group element to be encoded as `[le(x), le(y)]` where
/// `le(..)` is the little-endian encoding of the input field element as used
/// in the `ark-bn254` crate. Note that this differs from the EIP-197 standard,
/// which specifies that the field elements are encoded as big-endian.
///
/// The Solana syscalls still expect the inputs to be encoded in big-endian as
/// specified in EIP-197. The type `PodG1` is an intermediate type that
/// facilitates the translation between the EIP-197 encoding and the arkworks
/// implementation encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(transparent)]
pub struct PodG1(pub [u8; G1_POINT_SIZE]);

const G2_POINT_SIZE: usize = FIELD_SIZE * 4;

/// The BN254 (BN128) group element in G2 as a POD type.
///
/// Elements in G2 is represented by 2 field-extension elements `(x, y)`. Each
/// field-extension element itself is a degree 1 polynomial `x = x0 + x1*X`,
/// `y = y0 + y1*X`. The EIP-197 standard encodes a G2 element as
/// `[be(x1), be(x0), be(y1), be(y0)]` where `be(..)` is the big-endian
/// encoding of the input field element. The `ark-bn254` crate encodes a G2
/// element as `[le(x0), le(x1), le(y0), le(y1)]` where `le(..)` is the
/// little-endian encoding of the input field element. Notably, in addition to
/// the differences in the big-endian vs. little-endian encodings of field
/// elements, the order of the polynomial field coefficients `x0`, `x1`, `y0`,
/// and `y1` are different.
///
/// THe Solana syscalls still expect the inputs to be encoded as specified in
/// EIP-197. The type `PodG2` is an intermediate type that facilitates the
/// translation between the `EIP-197 encoding and the encoding used in the
/// arkworks implementation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(transparent)]
pub struct PodG2(pub [u8; G2_POINT_SIZE]);

mod target_arch {
    use {
        super::*,
        ark_bn254::{self, Config},
        ark_ec::{self, models::bn::Bn, pairing::Pairing, AffineRepr},
        ark_ff::{BigInteger, BigInteger256, One},
        ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate},
    };

    type G1 = ark_bn254::g1::G1Affine;
    type G2 = ark_bn254::g2::G2Affine;

    impl PodG1 {
        /// Takes in an EIP-197 (big-endian) byte encoding of a group element in G1 and constructs a
        /// `PodG1` struct that encodes the same bytes in little-endian.
        fn from_be_bytes(be_bytes: &[u8]) -> Result<Self, AltBn128Error> {
            if be_bytes.len() != G1_POINT_SIZE {
                return Err(AltBn128Error::SliceOutOfBounds);
            }
            let mut pod_bytes = [0u8; G1_POINT_SIZE];
            reverse_copy(&be_bytes[..FIELD_SIZE], &mut pod_bytes[..FIELD_SIZE])?;
            reverse_copy(&be_bytes[FIELD_SIZE..], &mut pod_bytes[FIELD_SIZE..])?;
            Ok(Self(pod_bytes))
        }
    }

    impl PodG2 {
        /// Takes in an EIP-197 (big-endian) byte encoding of a group element in G2
        /// and constructs a `PodG2` struct that encodes the same bytes in
        /// little-endian.
        fn from_be_bytes(be_bytes: &[u8]) -> Result<Self, AltBn128Error> {
            if be_bytes.len() != G2_POINT_SIZE {
                return Err(AltBn128Error::SliceOutOfBounds);
            }
            // note the cross order
            const SOURCE_X1_INDEX: usize = 0;
            const SOURCE_X0_INDEX: usize = SOURCE_X1_INDEX.saturating_add(FIELD_SIZE);
            const SOURCE_Y1_INDEX: usize = SOURCE_X0_INDEX.saturating_add(FIELD_SIZE);
            const SOURCE_Y0_INDEX: usize = SOURCE_Y1_INDEX.saturating_add(FIELD_SIZE);

            const TARGET_X0_INDEX: usize = 0;
            const TARGET_X1_INDEX: usize = TARGET_X0_INDEX.saturating_add(FIELD_SIZE);
            const TARGET_Y0_INDEX: usize = TARGET_X1_INDEX.saturating_add(FIELD_SIZE);
            const TARGET_Y1_INDEX: usize = TARGET_Y0_INDEX.saturating_add(FIELD_SIZE);

            let mut pod_bytes = [0u8; G2_POINT_SIZE];
            reverse_copy(
                &be_bytes[SOURCE_X1_INDEX..SOURCE_X1_INDEX.saturating_add(FIELD_SIZE)],
                &mut pod_bytes[TARGET_X1_INDEX..TARGET_X1_INDEX.saturating_add(FIELD_SIZE)],
            )?;
            reverse_copy(
                &be_bytes[SOURCE_X0_INDEX..SOURCE_X0_INDEX.saturating_add(FIELD_SIZE)],
                &mut pod_bytes[TARGET_X0_INDEX..TARGET_X0_INDEX.saturating_add(FIELD_SIZE)],
            )?;
            reverse_copy(
                &be_bytes[SOURCE_Y1_INDEX..SOURCE_Y1_INDEX.saturating_add(FIELD_SIZE)],
                &mut pod_bytes[TARGET_Y1_INDEX..TARGET_Y1_INDEX.saturating_add(FIELD_SIZE)],
            )?;
            reverse_copy(
                &be_bytes[SOURCE_Y0_INDEX..SOURCE_Y0_INDEX.saturating_add(FIELD_SIZE)],
                &mut pod_bytes[TARGET_Y0_INDEX..TARGET_Y0_INDEX.saturating_add(FIELD_SIZE)],
            )?;
            Ok(Self(pod_bytes))
        }
    }

    impl TryFrom<PodG1> for G1 {
        type Error = AltBn128Error;

        fn try_from(bytes: PodG1) -> Result<Self, Self::Error> {
            if bytes.0 == [0u8; 64] {
                return Ok(G1::zero());
            }
            let g1 = Self::deserialize_with_mode(
                &*[&bytes.0[..], &[0u8][..]].concat(),
                Compress::No,
                Validate::Yes,
            );

            match g1 {
                Ok(g1) => {
                    if !g1.is_on_curve() {
                        Err(AltBn128Error::GroupError)
                    } else {
                        Ok(g1)
                    }
                }
                Err(_) => Err(AltBn128Error::InvalidInputData),
            }
        }
    }

    impl TryFrom<PodG2> for G2 {
        type Error = AltBn128Error;

        fn try_from(bytes: PodG2) -> Result<Self, Self::Error> {
            if bytes.0 == [0u8; 128] {
                return Ok(G2::zero());
            }
            let g2 = Self::deserialize_with_mode(
                &*[&bytes.0[..], &[0u8][..]].concat(),
                Compress::No,
                Validate::Yes,
            );

            match g2 {
                Ok(g2) => {
                    if !g2.is_on_curve() {
                        Err(AltBn128Error::GroupError)
                    } else {
                        Ok(g2)
                    }
                }
                Err(_) => Err(AltBn128Error::InvalidInputData),
            }
        }
    }

    pub fn alt_bn128_addition(input: &[u8]) -> Result<Vec<u8>, AltBn128Error> {
        if input.len() > ALT_BN128_ADDITION_INPUT_LEN {
            return Err(AltBn128Error::InvalidInputData);
        }

        let mut input = input.to_vec();
        input.resize(ALT_BN128_ADDITION_INPUT_LEN, 0);

        let p: G1 = PodG1::from_be_bytes(&input[..64])?.try_into()?;
        let q: G1 = PodG1::from_be_bytes(&input[64..ALT_BN128_ADDITION_INPUT_LEN])?.try_into()?;

        #[allow(clippy::arithmetic_side_effects)]
        let result_point = p + q;

        let mut result_point_data = [0u8; ALT_BN128_ADDITION_OUTPUT_LEN];
        let result_point_affine: G1 = result_point.into();
        result_point_affine
            .x
            .serialize_with_mode(&mut result_point_data[..32], Compress::No)
            .map_err(|_| AltBn128Error::InvalidInputData)?;
        result_point_affine
            .y
            .serialize_with_mode(&mut result_point_data[32..], Compress::No)
            .map_err(|_| AltBn128Error::InvalidInputData)?;

        Ok(convert_endianness_64(&result_point_data[..]))
    }

    pub fn alt_bn128_multiplication(input: &[u8]) -> Result<Vec<u8>, AltBn128Error> {
        alt_bn128_apply_multiplication(input, ALT_BN128_MULTIPLICATION_INPUT_LEN)
    }

    pub fn alt_bn128_multiplication_128(input: &[u8]) -> Result<Vec<u8>, AltBn128Error> {
        alt_bn128_apply_multiplication(input, 128) // hard-code length; we will remove this function in the future
    }

    fn alt_bn128_apply_multiplication(
        input: &[u8],
        expected_length: usize,
    ) -> Result<Vec<u8>, AltBn128Error> {
        if input.len() > expected_length {
            return Err(AltBn128Error::InvalidInputData);
        }

        let mut input = input.to_vec();
        input.resize(expected_length, 0);

        let p: G1 = PodG1::from_be_bytes(&input[..64])?.try_into()?;
        let mut fr_bytes = [0u8; 32];
        reverse_copy(&input[64..96], &mut fr_bytes)?;
        let fr = BigInteger256::deserialize_uncompressed_unchecked(fr_bytes.as_slice())
            .map_err(|_| AltBn128Error::InvalidInputData)?;

        let result_point: G1 = p.mul_bigint(fr).into();

        let mut result_point_data = [0u8; ALT_BN128_MULTIPLICATION_OUTPUT_LEN];

        result_point
            .x
            .serialize_with_mode(&mut result_point_data[..32], Compress::No)
            .map_err(|_| AltBn128Error::InvalidInputData)?;
        result_point
            .y
            .serialize_with_mode(&mut result_point_data[32..], Compress::No)
            .map_err(|_| AltBn128Error::InvalidInputData)?;

        Ok(convert_endianness_64(
            &result_point_data[..ALT_BN128_MULTIPLICATION_OUTPUT_LEN],
        ))
    }

    pub fn alt_bn128_pairing(input: &[u8]) -> Result<Vec<u8>, AltBn128Error> {
        if input
            .len()
            .checked_rem(consts::ALT_BN128_PAIRING_ELEMENT_LEN)
            .is_none()
        {
            return Err(AltBn128Error::InvalidInputData);
        }

        let ele_len = input.len().saturating_div(ALT_BN128_PAIRING_ELEMENT_LEN);

        let mut vec_pairs: Vec<(G1, G2)> = Vec::with_capacity(ele_len);
        for chunk in input.chunks(ALT_BN128_PAIRING_ELEMENT_LEN) {
            let (p_bytes, q_bytes) = chunk.split_at(G1_POINT_SIZE);

            let g1 = PodG1::from_be_bytes(p_bytes)?.try_into()?;
            let g2 = PodG2::from_be_bytes(q_bytes)?.try_into()?;

            vec_pairs.push((g1, g2));
        }

        let mut result = BigInteger256::from(0u64);
        let res = <Bn<Config> as Pairing>::multi_pairing(
            vec_pairs.iter().map(|pair| pair.0),
            vec_pairs.iter().map(|pair| pair.1),
        );

        if res.0 == ark_bn254::Fq12::one() {
            result = BigInteger256::from(1u64);
        }

        let output = result.to_bytes_be();
        Ok(output)
    }

    fn convert_endianness_64(bytes: &[u8]) -> Vec<u8> {
        bytes
            .chunks(32)
            .flat_map(|b| b.iter().copied().rev().collect::<Vec<u8>>())
            .collect::<Vec<u8>>()
    }

    /// Copies a `source` byte slice into a `destination` byte slice in reverse order.
    fn reverse_copy(source: &[u8], destination: &mut [u8]) -> Result<(), AltBn128Error> {
        if source.len() != destination.len() {
            return Err(AltBn128Error::SliceOutOfBounds);
        }
        for (source_index, destination_index) in source.iter().rev().zip(destination.iter_mut()) {
            *destination_index = *source_index;
        }
        Ok(())
    }

    pub fn alt_bn128_g1_decompress(
        g1_bytes: &[u8],
    ) -> Result<[u8; alt_bn128_compression_size::G1], AltBn128CompressionError> {
        let g1_bytes: [u8; alt_bn128_compression_size::G1_COMPRESSED] = g1_bytes
            .try_into()
            .map_err(|_| AltBn128CompressionError::InvalidInputSize)?;
        if g1_bytes == [0u8; alt_bn128_compression_size::G1_COMPRESSED] {
            return Ok([0u8; alt_bn128_compression_size::G1]);
        }
        let decompressed_g1 = G1::deserialize_with_mode(
            convert_endianness::<32, 32>(&g1_bytes).as_slice(),
            Compress::Yes,
            Validate::No,
        )
        .map_err(|_| AltBn128CompressionError::G1DecompressionFailed)?;
        let mut decompressed_g1_bytes = [0u8; alt_bn128_compression_size::G1];
        decompressed_g1
            .x
            .serialize_with_mode(&mut decompressed_g1_bytes[..32], Compress::No)
            .map_err(|_| AltBn128CompressionError::G1DecompressionFailed)?;
        decompressed_g1
            .y
            .serialize_with_mode(&mut decompressed_g1_bytes[32..], Compress::No)
            .map_err(|_| AltBn128CompressionError::G1DecompressionFailed)?;
        Ok(convert_endianness::<32, 64>(&decompressed_g1_bytes))
    }

    pub fn alt_bn128_g1_compress(
        g1_bytes: &[u8],
    ) -> Result<[u8; alt_bn128_compression_size::G1_COMPRESSED], AltBn128CompressionError> {
        let g1_bytes: [u8; alt_bn128_compression_size::G1] = g1_bytes
            .try_into()
            .map_err(|_| AltBn128CompressionError::InvalidInputSize)?;
        if g1_bytes == [0u8; alt_bn128_compression_size::G1] {
            return Ok([0u8; alt_bn128_compression_size::G1_COMPRESSED]);
        }
        let g1 = G1::deserialize_with_mode(
            convert_endianness::<32, 64>(&g1_bytes).as_slice(),
            Compress::No,
            Validate::No,
        )
        .map_err(|_| AltBn128CompressionError::G1CompressionFailed)?;
        let mut g1_bytes = [0u8; alt_bn128_compression_size::G1_COMPRESSED];
        G1::serialize_compressed(&g1, g1_bytes.as_mut_slice())
            .map_err(|_| AltBn128CompressionError::G1CompressionFailed)?;
        Ok(convert_endianness::<32, 32>(&g1_bytes))
    }

    pub fn alt_bn128_g2_decompress(
        g2_bytes: &[u8],
    ) -> Result<[u8; alt_bn128_compression_size::G2], AltBn128CompressionError> {
        let g2_bytes: [u8; alt_bn128_compression_size::G2_COMPRESSED] = g2_bytes
            .try_into()
            .map_err(|_| AltBn128CompressionError::InvalidInputSize)?;
        if g2_bytes == [0u8; alt_bn128_compression_size::G2_COMPRESSED] {
            return Ok([0u8; alt_bn128_compression_size::G2]);
        }
        let decompressed_g2 = G2::deserialize_with_mode(
            convert_endianness::<64, 64>(&g2_bytes).as_slice(),
            Compress::Yes,
            Validate::No,
        )
        .map_err(|_| AltBn128CompressionError::G2DecompressionFailed)?;
        let mut decompressed_g2_bytes = [0u8; alt_bn128_compression_size::G2];
        decompressed_g2
            .x
            .serialize_with_mode(&mut decompressed_g2_bytes[..64], Compress::No)
            .map_err(|_| AltBn128CompressionError::G2DecompressionFailed)?;
        decompressed_g2
            .y
            .serialize_with_mode(&mut decompressed_g2_bytes[64..128], Compress::No)
            .map_err(|_| AltBn128CompressionError::G2DecompressionFailed)?;
        Ok(convert_endianness::<64, 128>(&decompressed_g2_bytes))
    }

    pub fn alt_bn128_g2_compress(
        g2_bytes: &[u8],
    ) -> Result<[u8; alt_bn128_compression_size::G2_COMPRESSED], AltBn128CompressionError> {
        let g2_bytes: [u8; alt_bn128_compression_size::G2] = g2_bytes
            .try_into()
            .map_err(|_| AltBn128CompressionError::InvalidInputSize)?;
        if g2_bytes == [0u8; alt_bn128_compression_size::G2] {
            return Ok([0u8; alt_bn128_compression_size::G2_COMPRESSED]);
        }
        let g2 = G2::deserialize_with_mode(
            convert_endianness::<64, 128>(&g2_bytes).as_slice(),
            Compress::No,
            Validate::No,
        )
        .map_err(|_| AltBn128CompressionError::G2CompressionFailed)?;
        let mut g2_bytes = [0u8; alt_bn128_compression_size::G2_COMPRESSED];
        G2::serialize_compressed(&g2, g2_bytes.as_mut_slice())
            .map_err(|_| AltBn128CompressionError::G2CompressionFailed)?;
        Ok(convert_endianness::<64, 64>(&g2_bytes))
    }

    pub fn convert_endianness<const CHUNK_SIZE: usize, const ARRAY_SIZE: usize>(
        bytes: &[u8; ARRAY_SIZE],
    ) -> [u8; ARRAY_SIZE] {
        let reversed: [_; ARRAY_SIZE] = bytes
            .chunks_exact(CHUNK_SIZE)
            .flat_map(|chunk| chunk.iter().rev().copied())
            .enumerate()
            .fold([0u8; ARRAY_SIZE], |mut acc, (i, v)| {
                acc[i] = v;
                acc
            });
        reversed
    }
}
