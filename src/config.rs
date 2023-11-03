use crate::word_config::RC5WordConfig;

/// Takes a `RC5WordConfig` and adds the rounds and keysize to produce an
/// `RC5Config`, which can be used to encrypt/decrypt data.
pub struct RC5Config<W: RC5WordConfig> {
  pub rounds: usize,
  pub keysize: usize,
  pub word_config: W,
}

impl<W: RC5WordConfig> RC5Config<W> {
  pub fn build(word_config: W, rounds: usize, keysize: usize) -> Self {
    Self {
      rounds,
      keysize,
      word_config,
    }
  }
}

#[cfg(test)]
mod test {
  use {super::*, crate::word_config::Rc5_32};
  #[test]
  fn test_build() {
    let config = RC5Config::build(Rc5_32, 12, 16);
    assert_eq!(config.rounds, 12);
    assert_eq!(config.keysize, 16);
  }
}
