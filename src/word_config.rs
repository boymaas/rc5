use {
  crate::error::Error,
  num::{
    traits::{WrappingAdd, WrappingSub, Zero},
    NumCast,
    PrimInt,
  },
  std::{mem::size_of, ops::BitXor},
};

/// This trait implements the word configuration aspect of the RC5
/// algorithm, which is separate from the configuration of the rounds and
/// the key size.
///
/// The parameters for these aspects (rounds and keysize) can be customized
/// based on the specific use case of the algorithm. This trait solely focuses
/// on the parameters associated with the chosen word size. To obtain an
/// RC5Config that can be utilized for encryption/decryption, the config
/// module can be used.
pub trait Rc5WordConfig {
  type Type: BitXor + WrappingAdd + WrappingSub + PrimInt + NumCast + Zero;

  /// This is the version of the RC5 algorithm.
  const VERSION: u8 = 0x10;

  /// Word size in bits. The W parameter of the RC5 algorithm
  const WORD_SIZE_IN_BYTES: usize = size_of::<Self::Type>();
  const WORD_SIZE_IN_BITS: usize = size_of::<Self::Type>() * 8;

  const P: Self::Type; // Odd((e − 2)2^w)
  const Q: Self::Type; // Odd((φ − 1)2^w)

  /// Converts a little-endian byte slice to a word.
  fn from_le_bytes(bytes: &[u8]) -> Result<Self::Type, Error>;

  /// Converts a word into a little-endian byte slice.
  fn to_le_bytes(t: Self::Type) -> Vec<u8>;
}

macro_rules! impl_word_config {
  ($config:tt, $type:tt, $q:expr, $p:expr) => {
    pub struct $config;

    impl Rc5WordConfig for $config {
      type Type = $type;

      const P: Self::Type = $p;
      const Q: Self::Type = $q;

      fn from_le_bytes(bytes: &[u8]) -> Result<Self::Type, Error> {
        if bytes.len() != Self::WORD_SIZE_IN_BYTES {
          return Err(Error::BytesLengthMismatch);
        }

        Ok(Self::Type::from_le_bytes(
          bytes.try_into().map_err(|_| Error::BytesLengthMismatch)?,
        ))
      }

      fn to_le_bytes(t: Self::Type) -> Vec<u8> {
        $type::to_le_bytes(t).to_vec()
      }
    }
  };
}

// Provides implementations of various commonly used word sizes.
impl_word_config!(Rc5_8, u8, 0x9F, 0xB7);
impl_word_config!(Rc5_16, u16, 0x9E37, 0xB7E1);
impl_word_config!(Rc5_32, u32, 0x9E3779B9, 0xB7E15163);
impl_word_config!(Rc5_64, u64, 0x9E3779B97F4A7C15, 0xB7E151628AED2A6B);
impl_word_config!(
  Rc5_128,
  u128,
  0x9E3779B97F4A7C15F39CC0605CEDC835,
  0xB7E151628AED2A6ABF7158809CF4F3C7
);
