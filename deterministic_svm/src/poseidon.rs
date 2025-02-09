//! Hashing with the [Poseidon] hash function.
//!
//! [Poseidon]: https://www.poseidon-hash.info/

use thiserror::Error;

/// Length of Poseidon hash result.
pub const HASH_BYTES: usize = 32;

// PoseidonSyscallError must be removed once the
// simplify_alt_bn128_syscall_error_codes feature gets activated
#[derive(Error, Debug)]
pub enum PoseidonSyscallError {
    #[error("Invalid parameters.")]
    InvalidParameters,
    #[error("Invalid endianness.")]
    InvalidEndianness,
    #[error("Invalid number of inputs. Maximum allowed is 12.")]
    InvalidNumberOfInputs,
    #[error("Input is an empty slice.")]
    EmptyInput,
    #[error(
        "Invalid length of the input. The length matching the modulus of the prime field is 32."
    )]
    InvalidInputLength,
    #[error("Failed to convert bytest into a prime field element.")]
    BytesToPrimeFieldElement,
    #[error("Input is larger than the modulus of the prime field.")]
    InputLargerThanModulus,
    #[error("Failed to convert a vector of bytes into an array.")]
    VecToArray,
    #[error("Failed to convert the number of inputs from u64 to u8.")]
    U64Tou8,
    #[error("Failed to convert bytes to BigInt")]
    BytesToBigInt,
    #[error("Invalid width. Choose a width between 2 and 16 for 1 to 15 inputs.")]
    InvalidWidthCircom,
    #[error("Unexpected error")]
    Unexpected,
}

impl From<u64> for PoseidonSyscallError {
    fn from(error: u64) -> Self {
        match error {
            1 => PoseidonSyscallError::InvalidParameters,
            2 => PoseidonSyscallError::InvalidEndianness,
            3 => PoseidonSyscallError::InvalidNumberOfInputs,
            4 => PoseidonSyscallError::EmptyInput,
            5 => PoseidonSyscallError::InvalidInputLength,
            6 => PoseidonSyscallError::BytesToPrimeFieldElement,
            7 => PoseidonSyscallError::InputLargerThanModulus,
            8 => PoseidonSyscallError::VecToArray,
            9 => PoseidonSyscallError::U64Tou8,
            10 => PoseidonSyscallError::BytesToBigInt,
            11 => PoseidonSyscallError::InvalidWidthCircom,
            _ => PoseidonSyscallError::Unexpected,
        }
    }
}

impl From<PoseidonSyscallError> for u64 {
    fn from(error: PoseidonSyscallError) -> Self {
        match error {
            PoseidonSyscallError::InvalidParameters => 1,
            PoseidonSyscallError::InvalidEndianness => 2,
            PoseidonSyscallError::InvalidNumberOfInputs => 3,
            PoseidonSyscallError::EmptyInput => 4,
            PoseidonSyscallError::InvalidInputLength => 5,
            PoseidonSyscallError::BytesToPrimeFieldElement => 6,
            PoseidonSyscallError::InputLargerThanModulus => 7,
            PoseidonSyscallError::VecToArray => 8,
            PoseidonSyscallError::U64Tou8 => 9,
            PoseidonSyscallError::BytesToBigInt => 10,
            PoseidonSyscallError::InvalidWidthCircom => 11,
            PoseidonSyscallError::Unexpected => 12,
        }
    }
}

/// Configuration parameters for the Poseidon hash function.
///
/// The parameters of each configuration consist of:
///
/// - **Elliptic curve type**: This defines the prime field in which the
///   cryptographic operations are conducted.
/// - **S-Box**: The substitution box used in the cryptographic rounds.
/// - **Full rounds**: The number of full transformation rounds in the hash
///   function.
/// - **Partial rounds**: The number of partial transformation rounds in the
///   hash function.
///
/// Each configuration variant's name is composed of its elliptic curve type
/// followed by its S-Box specification.
#[repr(u64)]
pub enum Parameters {
    /// Configuration using the Barreto–Naehrig curve with an embedding degree
    /// of 12, defined over a 254-bit prime field.
    ///
    /// Configuration Details:
    /// - **S-Box**: \( x^5 \)
    /// - **Width**: \( 2 \leq t \leq 13 \)
    /// - **Inputs**: \( 1 \leq n \leq 12 \)
    /// - **Full rounds**: 8
    /// - **Partial rounds**: Depending on width: [56, 57, 56, 60, 60, 63, 64,
    ///   63, 60, 66, 60, 65]
    Bn254X5 = 0,
}

impl TryFrom<u64> for Parameters {
    type Error = PoseidonSyscallError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            x if x == Parameters::Bn254X5 as u64 => Ok(Parameters::Bn254X5),
            _ => Err(PoseidonSyscallError::InvalidParameters),
        }
    }
}

impl From<Parameters> for u64 {
    fn from(value: Parameters) -> Self {
        match value {
            Parameters::Bn254X5 => 0,
        }
    }
}

/// Endianness of inputs and result.
#[repr(u64)]
pub enum Endianness {
    /// Big-endian inputs and result.
    BigEndian = 0,
    /// Little-endian inputs and result.
    LittleEndian,
}

impl TryFrom<u64> for Endianness {
    type Error = PoseidonSyscallError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            x if x == Endianness::BigEndian as u64 => Ok(Endianness::BigEndian),
            x if x == Endianness::LittleEndian as u64 => Ok(Endianness::LittleEndian),
            _ => Err(PoseidonSyscallError::InvalidEndianness),
        }
    }
}

impl From<Endianness> for u64 {
    fn from(value: Endianness) -> Self {
        match value {
            Endianness::BigEndian => 0,
            Endianness::LittleEndian => 1,
        }
    }
}

/// Poseidon hash result.
#[repr(transparent)]
pub struct PoseidonHash(pub [u8; HASH_BYTES]);

impl PoseidonHash {
    pub fn new(hash_array: [u8; HASH_BYTES]) -> Self {
        Self(hash_array)
    }

    pub fn to_bytes(&self) -> [u8; HASH_BYTES] {
        self.0
    }
}

#[cfg(target_os = "solana")]
pub use solana_define_syscall::definitions::sol_poseidon;

/// Return a Poseidon hash for the given data with the given elliptic curve and
/// endianness.
///
/// # Examples
///
/// ```rust
/// use solana_poseidon::{hashv, Endianness, Parameters};
///
/// # fn test() {
/// let input1 = [1u8; 32];
/// let input2 = [2u8; 32];
///
/// let hash = hashv(Parameters::Bn254X5, Endianness::BigEndian, &[&input1, &input2]).unwrap();
/// assert_eq!(
///     hash.to_bytes(),
///     [
///         13, 84, 225, 147, 143, 138, 140, 28, 125, 235, 94, 3, 85, 242, 99, 25, 32, 123,
///         132, 254, 156, 162, 206, 27, 38, 231, 53, 200, 41, 130, 25, 144
///     ]
/// );
///
/// let hash = hashv(Parameters::Bn254X5, Endianness::LittleEndian, &[&input1, &input2]).unwrap();
/// assert_eq!(
///     hash.to_bytes(),
///     [
///         144, 25, 130, 41, 200, 53, 231, 38, 27, 206, 162, 156, 254, 132, 123, 32, 25, 99,
///         242, 85, 3, 94, 235, 125, 28, 140, 138, 143, 147, 225, 84, 13
///     ]
/// );
/// # }
/// ```
#[allow(unused_variables)]
pub fn hashv(
    // This parameter is not used currently, because we support only one curve
    // (BN254). It should be used in case we add more curves in the future.
    parameters: Parameters,
    endianness: Endianness,
    vals: &[&[u8]],
) -> Result<PoseidonHash, PoseidonSyscallError> {
    // Perform the calculation inline, calling this from within a program is
    // not supported.

    use {
        ark_bn254::Fr,
        light_poseidon::{Poseidon, PoseidonBytesHasher, PoseidonError},
    };

    #[allow(non_local_definitions)]
    impl From<PoseidonError> for PoseidonSyscallError {
        fn from(error: PoseidonError) -> Self {
            match error {
                PoseidonError::InvalidNumberOfInputs { .. } => {
                    PoseidonSyscallError::InvalidNumberOfInputs
                }
                PoseidonError::EmptyInput => PoseidonSyscallError::EmptyInput,
                PoseidonError::InvalidInputLength { .. } => {
                    PoseidonSyscallError::InvalidInputLength
                }
                PoseidonError::BytesToPrimeFieldElement { .. } => {
                    PoseidonSyscallError::BytesToPrimeFieldElement
                }
                PoseidonError::InputLargerThanModulus => {
                    PoseidonSyscallError::InputLargerThanModulus
                }
                PoseidonError::VecToArray => PoseidonSyscallError::VecToArray,
                PoseidonError::U64Tou8 => PoseidonSyscallError::U64Tou8,
                PoseidonError::BytesToBigInt => PoseidonSyscallError::BytesToBigInt,
                PoseidonError::InvalidWidthCircom { .. } => {
                    PoseidonSyscallError::InvalidWidthCircom
                }
            }
        }
    }

    let mut hasher = Poseidon::<Fr>::new_circom(vals.len()).map_err(PoseidonSyscallError::from)?;
    let res = match endianness {
        Endianness::BigEndian => hasher.hash_bytes_be(vals),
        Endianness::LittleEndian => hasher.hash_bytes_le(vals),
    }
    .map_err(PoseidonSyscallError::from)?;

    Ok(PoseidonHash(res))
}

/// Return a Poseidon hash for the given data with the given elliptic curve and
/// endianness.
///
/// # Examples
///
/// ```rust
/// use solana_poseidon::{hash, Endianness, Parameters};
///
/// # fn test() {
/// let input = [1u8; 32];
///
/// let result = hash(Parameters::Bn254X5, Endianness::BigEndian, &input).unwrap();
/// assert_eq!(
///     result.to_bytes(),
///     [
///         5, 191, 172, 229, 129, 238, 97, 119, 204, 25, 198, 197, 99, 99, 166, 136, 130, 241,
///         30, 132, 7, 172, 99, 157, 185, 145, 224, 210, 127, 27, 117, 230
///     ],
/// );
///
/// let hash = hash(Parameters::Bn254X5, Endianness::LittleEndian, &input).unwrap();
/// assert_eq!(
///     hash.to_bytes(),
///     [
///         230, 117, 27, 127, 210, 224, 145, 185, 157, 99, 172, 7, 132, 30, 241, 130, 136,
///         166, 99, 99, 197, 198, 25, 204, 119, 97, 238, 129, 229, 172, 191, 5
///     ],
/// );
/// # }
/// ```
pub fn hash(
    parameters: Parameters,
    endianness: Endianness,
    val: &[u8],
) -> Result<PoseidonHash, PoseidonSyscallError> {
    hashv(parameters, endianness, &[val])
}
