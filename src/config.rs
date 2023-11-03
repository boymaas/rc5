use {
  crate::{
    error::{Error, Rc5Result},
    word_config::{Rc5WordConfig, Rc5_32},
  },
  std::marker::PhantomData,
};

const MAX_ROUNDS: usize = 256;
const MAX_KEY_SIZE: usize = 256;

/// Takes a `RC5WordConfig` and adds the rounds and keysize to produce an
/// `RC5Config`, which can be used to encrypt/decrypt data.
pub struct Rc5Config<W: Rc5WordConfig> {
  pub rounds: usize,
  pub keysize: usize,
  pub _phantom: PhantomData<W>,
}

impl<W: Rc5WordConfig> Rc5Config<W> {
  pub fn build(rounds: usize, keysize: usize) -> Rc5Result<Self> {
    if rounds > MAX_ROUNDS {
      return Err(Error::RoundsCountTooLarge);
    }
    if keysize > MAX_KEY_SIZE {
      return Err(Error::KeySizeTooLarge);
    }

    Ok(Self {
      rounds,
      keysize,
      _phantom: PhantomData,
    })
  }
}

/// Convenience function for building an `RC5Config` with the suggested defaults
pub fn rc5_32_12_16() -> Rc5Config<Rc5_32> {
  Rc5Config::<Rc5_32>::build(12, 16).unwrap()
}

#[cfg(test)]
mod test {
  use {super::*, crate::word_config::Rc5_32};

  #[test]
  fn test_build() {
    let config = Rc5Config::<Rc5_32>::build(12, 16).unwrap();
    assert_eq!(config.rounds, 12);
    assert_eq!(config.keysize, 16);
  }
}
