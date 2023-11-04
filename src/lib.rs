mod cipher;
mod config;
mod error;
mod secret_key;
mod word_config;

use error::Rc5Result;
pub use {
  config::Rc5Config,
  secret_key::{ExpandedKey, SecretKey},
  word_config::{Rc5WordConfig, Rc5_128, Rc5_16, Rc5_32, Rc5_64, Rc5_8},
};

/// This is an encode function that can be configured with the Rc5WordConfig,
/// rounds, and key sizes.
pub fn encode<W: Rc5WordConfig>(
  rounds: usize,
  keysize: usize,
  key: &[u8],
  plaintext: &[u8],
) -> Rc5Result<Vec<u8>> {
  SecretKey::new(Rc5Config::<W>::build(rounds, keysize)?, key)?
    .expand()?
    .encrypt(&plaintext)
}

/// This is a decode function that can be configured with the Rc5WordConfig,
/// rounds, and key sizes.
pub fn decode<W: Rc5WordConfig>(
  rounds: usize,
  keysize: usize,
  key: &[u8],
  plaintext: &[u8],
) -> Rc5Result<Vec<u8>> {
  SecretKey::new(Rc5Config::<W>::build(rounds, keysize)?, &key)?
    .expand()?
    .decrypt(&plaintext)
}

/// Returns a cipher text for a given key and plaintext.
/// This function utilizes the default RC5 configuration: rc5_32_12_16.
pub fn encode_default(key: Vec<u8>, plaintext: Vec<u8>) -> Rc5Result<Vec<u8>> {
  SecretKey::new(config::rc5_32_12_16(), &key)?
    .expand()?
    .encrypt(&plaintext)
}

// This function returns the plaintext for a given key and ciphertext. It
// uses the default configuration: rc5_32_12_16.
pub fn decode_default(key: Vec<u8>, ciphertext: Vec<u8>) -> Rc5Result<Vec<u8>> {
  SecretKey::new(config::rc5_32_12_16(), &key)?
    .expand()?
    .decrypt(&ciphertext)
}
