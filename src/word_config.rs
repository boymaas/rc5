use {
  num::{
    traits::{WrappingAdd, WrappingSub},
    Num,
    NumCast,
    PrimInt,
  },
  std::{mem::size_of, ops::BitXor},
};

/// This trait defines the minimal set of operations that a type must conform to
/// in order to work with our encryption and decryption algorithm.
pub trait AdvancedNumeric =
  Num + BitXor + WrappingAdd + WrappingSub + PrimInt + NumCast;

/// This trait implements the word configuration aspect of the RC5
/// algorithm, which is separate from the configuration of the rounds and
/// the key size.
///
/// The parameters for these aspects (rounds and keysize) can be customized
/// based on the specific use case of the algorithm. This trait solely focuses
/// on the parameters associated with the chosen word size. To obtain an
/// RC5Config that can be utilized for encryption/decryption, the config
/// module can be used.
pub trait RC5WordConfig {
  type Type: AdvancedNumeric;

  /// This is the version of the RC5 algorithm.
  const VERSION: u8 = 0x10;

  /// Word size in bits. The W parameter of the RC5 algorithm
  const WORD_SIZE_IN_BITS: usize = size_of::<Self::Type>() * 8;

  const P: Self::Type; // Odd((e − 2)2^w)
  const Q: Self::Type; // Odd((φ − 1)2^w)
}

macro_rules! impl_word_config {
  ($config:tt, $type:tt, $q:expr, $p:expr) => {
    pub struct $config;

    impl RC5WordConfig for $type {
      type Type = $type;

      const P: Self::Type = $p;
      const Q: Self::Type = $q;
    }
  };
}

// Provides implementations of various commonly used word sizes.
impl_word_config!(Rc5_16, u16, 0xB7E1, 0x9E37);
impl_word_config!(Rc5_32, u32, 0xB7E15163, 0x9E3779B9);
impl_word_config!(Rc5_64, u64, 0x9E3779B97F4A7C15, 0xB7E151628AED2A6B);
impl_word_config!(
  Rc5_128,
  u128,
  0x9E3779B97F4A7C15F39CC0605CEDC835,
  0xB7E151628AED2A6ABF7158809CF4F3C7
);
