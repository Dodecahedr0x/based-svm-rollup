#![allow(clippy::arithmetic_side_effects)]

use crate::{DecodeError, Sanitize};
use std::sync::atomic::{self, AtomicU64};
use {
    core::{
        array,
        convert::{Infallible, TryFrom},
        fmt, mem,
        str::{from_utf8, FromStr},
    },
    num_traits::{FromPrimitive, ToPrimitive},
};

/// Number of bytes in a pubkey
pub const PUBKEY_BYTES: usize = 32;
/// maximum length of derived `Pubkey` seed
pub const MAX_SEED_LEN: usize = 32;
/// Maximum number of seeds
pub const MAX_SEEDS: usize = 16;
/// Maximum string length of a base58 encoded pubkey
const MAX_BASE58_LEN: usize = 44;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PubkeyError {
    /// Length of the seed is too long for address generation
    MaxSeedLengthExceeded,
    InvalidSeeds,
    IllegalOwner,
}

impl ToPrimitive for PubkeyError {
    #[inline]
    fn to_i64(&self) -> Option<i64> {
        Some(match *self {
            PubkeyError::MaxSeedLengthExceeded => PubkeyError::MaxSeedLengthExceeded as i64,
            PubkeyError::InvalidSeeds => PubkeyError::InvalidSeeds as i64,
            PubkeyError::IllegalOwner => PubkeyError::IllegalOwner as i64,
        })
    }
    #[inline]
    fn to_u64(&self) -> Option<u64> {
        self.to_i64().map(|x| x as u64)
    }
}

impl FromPrimitive for PubkeyError {
    #[inline]
    fn from_i64(n: i64) -> Option<Self> {
        if n == PubkeyError::MaxSeedLengthExceeded as i64 {
            Some(PubkeyError::MaxSeedLengthExceeded)
        } else if n == PubkeyError::InvalidSeeds as i64 {
            Some(PubkeyError::InvalidSeeds)
        } else if n == PubkeyError::IllegalOwner as i64 {
            Some(PubkeyError::IllegalOwner)
        } else {
            None
        }
    }
    #[inline]
    fn from_u64(n: u64) -> Option<Self> {
        Self::from_i64(n as i64)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PubkeyError {}

impl fmt::Display for PubkeyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PubkeyError::MaxSeedLengthExceeded => {
                f.write_str("Length of the seed is too long for address generation")
            }
            PubkeyError::InvalidSeeds => {
                f.write_str("Provided seeds do not result in a valid address")
            }
            PubkeyError::IllegalOwner => f.write_str("Provided owner is not allowed"),
        }
    }
}

impl<T> DecodeError<T> for PubkeyError {
    fn type_of() -> &'static str {
        "PubkeyError"
    }
}
impl From<u64> for PubkeyError {
    fn from(error: u64) -> Self {
        match error {
            0 => PubkeyError::MaxSeedLengthExceeded,
            1 => PubkeyError::InvalidSeeds,
            2 => PubkeyError::IllegalOwner,
            _ => panic!("Unsupported PubkeyError"),
        }
    }
}

#[derive(Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Pubkey(pub(crate) [u8; 32]);

impl Sanitize for Pubkey {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsePubkeyError {
    WrongSize,
    Invalid,
}

impl ToPrimitive for ParsePubkeyError {
    #[inline]
    fn to_i64(&self) -> Option<i64> {
        Some(match *self {
            ParsePubkeyError::WrongSize => ParsePubkeyError::WrongSize as i64,
            ParsePubkeyError::Invalid => ParsePubkeyError::Invalid as i64,
        })
    }
    #[inline]
    fn to_u64(&self) -> Option<u64> {
        self.to_i64().map(|x| x as u64)
    }
}

impl FromPrimitive for ParsePubkeyError {
    #[inline]
    fn from_i64(n: i64) -> Option<Self> {
        if n == ParsePubkeyError::WrongSize as i64 {
            Some(ParsePubkeyError::WrongSize)
        } else if n == ParsePubkeyError::Invalid as i64 {
            Some(ParsePubkeyError::Invalid)
        } else {
            None
        }
    }
    #[inline]
    fn from_u64(n: u64) -> Option<Self> {
        Self::from_i64(n as i64)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParsePubkeyError {}

impl fmt::Display for ParsePubkeyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ParsePubkeyError::WrongSize => f.write_str("String is the wrong size"),
            ParsePubkeyError::Invalid => f.write_str("Invalid Base58 string"),
        }
    }
}

impl From<Infallible> for ParsePubkeyError {
    fn from(_: Infallible) -> Self {
        unreachable!("Infallible uninhabited");
    }
}

impl<T> DecodeError<T> for ParsePubkeyError {
    fn type_of() -> &'static str {
        "ParsePubkeyError"
    }
}

impl FromStr for Pubkey {
    type Err = ParsePubkeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() > MAX_BASE58_LEN {
            return Err(ParsePubkeyError::WrongSize);
        }
        let mut bytes = [0; PUBKEY_BYTES];
        let decoded_size = bs58::decode(s)
            .onto(&mut bytes)
            .map_err(|_| ParsePubkeyError::Invalid)?;
        if decoded_size != mem::size_of::<Pubkey>() {
            Err(ParsePubkeyError::WrongSize)
        } else {
            Ok(Pubkey(bytes))
        }
    }
}

impl From<[u8; 32]> for Pubkey {
    #[inline]
    fn from(from: [u8; 32]) -> Self {
        Self(from)
    }
}

impl TryFrom<&[u8]> for Pubkey {
    type Error = array::TryFromSliceError;

    #[inline]
    fn try_from(pubkey: &[u8]) -> Result<Self, Self::Error> {
        <[u8; 32]>::try_from(pubkey).map(Self::from)
    }
}

impl TryFrom<Vec<u8>> for Pubkey {
    type Error = Vec<u8>;

    #[inline]
    fn try_from(pubkey: Vec<u8>) -> Result<Self, Self::Error> {
        <[u8; 32]>::try_from(pubkey).map(Self::from)
    }
}

impl TryFrom<&str> for Pubkey {
    type Error = ParsePubkeyError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Pubkey::from_str(s)
    }
}

impl Pubkey {
    pub const fn new_from_array(pubkey_array: [u8; 32]) -> Self {
        Self(pubkey_array)
    }

    /// Decode a string into a Pubkey, usable in a const context
    pub const fn from_str_const(s: &str) -> Self {
        let id_array = five8_const::decode_32_const(s);
        Pubkey::new_from_array(id_array)
    }

    /// unique Pubkey for tests and benchmarks.
    pub fn new_unique() -> Self {
        static I: AtomicU64 = AtomicU64::new(1);

        let mut b = [0u8; 32];
        let i = I.fetch_add(1, atomic::Ordering::Relaxed);
        // use big endian representation to ensure that recent unique pubkeys
        // are always greater than less recent unique pubkeys
        b[0..8].copy_from_slice(&i.to_be_bytes());
        Self::from(b)
    }

    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Log a `Pubkey` from a program
    pub fn log(&self) {
        #[cfg(target_os = "solana")]
        unsafe {
            crate::syscalls::sol_log_pubkey(self.as_ref() as *const _ as *const u8)
        };

        #[cfg(all(not(target_os = "solana"), feature = "std"))]
        std::println!("{}", std::string::ToString::to_string(&self));
    }
}

impl AsRef<[u8]> for Pubkey {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl AsMut<[u8]> for Pubkey {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0[..]
    }
}

fn write_as_base58(f: &mut fmt::Formatter, p: &Pubkey) -> fmt::Result {
    let mut out = [0u8; MAX_BASE58_LEN];
    let out_slice: &mut [u8] = &mut out;
    // This will never fail because the only possible error is BufferTooSmall,
    // and we will never call it with too small a buffer.
    let len = bs58::encode(p.0).onto(out_slice).unwrap();
    let as_str = from_utf8(&out[..len]).unwrap();
    f.write_str(as_str)
}

impl fmt::Debug for Pubkey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write_as_base58(f, self)
    }
}

impl fmt::Display for Pubkey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write_as_base58(f, self)
    }
}

/// Convenience macro to declare a static public key and functions to interact with it.
///
/// Input: a single literal base58 string representation of a program's ID.
///
/// # Example
///
/// ```
/// # // wrapper is used so that the macro invocation occurs in the item position
/// # // rather than in the statement position which isn't allowed.
/// use std::str::FromStr;
/// use solana_pubkey::{declare_id, Pubkey};
///
/// # mod item_wrapper {
/// #   use solana_pubkey::declare_id;
/// declare_id!("My11111111111111111111111111111111111111111");
/// # }
/// # use item_wrapper::id;
///
/// let my_id = Pubkey::from_str("My11111111111111111111111111111111111111111").unwrap();
/// assert_eq!(id(), my_id);
/// ```
#[macro_export]
macro_rules! declare_id {
    ($address:expr) => {
        /// The const program ID.
        pub const ID: $crate::Pubkey = $crate::Pubkey::from_str_const($address);

        /// Returns `true` if given pubkey is the program ID.
        // TODO make this const once `derive_const` makes it out of nightly
        // and we can `derive_const(PartialEq)` on `Pubkey`.
        pub fn check_id(id: &$crate::Pubkey) -> bool {
            id == &ID
        }

        /// Returns the program ID.
        pub const fn id() -> $crate::Pubkey {
            ID
        }

        #[cfg(test)]
        #[test]
        fn test_id() {
            assert!(check_id(&id()));
        }
    };
}

/// Same as [`declare_id`] except that it reports that this ID has been deprecated.
#[macro_export]
macro_rules! declare_deprecated_id {
    ($address:expr) => {
        /// The const program ID.
        pub const ID: $crate::Pubkey = $crate::Pubkey::from_str_const($address);

        /// Returns `true` if given pubkey is the program ID.
        // TODO make this const once `derive_const` makes it out of nightly
        // and we can `derive_const(PartialEq)` on `Pubkey`.
        #[deprecated()]
        pub fn check_id(id: &$crate::Pubkey) -> bool {
            id == &ID
        }

        /// Returns the program ID.
        #[deprecated()]
        pub const fn id() -> $crate::Pubkey {
            ID
        }

        #[cfg(test)]
        #[test]
        #[allow(deprecated)]
        fn test_id() {
            assert!(check_id(&id()));
        }
    };
}

/// Convenience macro to define a static public key.
///
/// Input: a single literal base58 string representation of a Pubkey.
///
/// # Example
///
/// ```
/// use std::str::FromStr;
/// use solana_pubkey::{pubkey, Pubkey};
///
/// static ID: Pubkey = pubkey!("My11111111111111111111111111111111111111111");
///
/// let my_id = Pubkey::from_str("My11111111111111111111111111111111111111111").unwrap();
/// assert_eq!(ID, my_id);
/// ```
#[macro_export]
macro_rules! pubkey {
    ($input:literal) => {
        $crate::Pubkey::from_str_const($input)
    };
}
