use {
  crate::{
    config::Rc5Config,
    error::{Error, Rc5Result},
    word_config::Rc5WordConfig,
  },
  num::{
    integer::div_ceil,
    traits::{NumCast, PrimInt, ToPrimitive, WrappingAdd, Zero},
  },
  std::cmp::max,
};

pub struct SecretKey<W: Rc5WordConfig> {
  config: Rc5Config<W>,
  key: Vec<u8>,
}

impl<W: Rc5WordConfig> SecretKey<W> {
  pub fn new(config: Rc5Config<W>, key: &[u8]) -> Rc5Result<Self> {
    // ensure key size is correct confirming our configuration
    if key.len() != config.keysize {
      return Err(Error::WrongKeySize(config.keysize, key.len()));
    }

    Ok(Self {
      config,
      key: key.into(),
    })
  }

  /// Key expansion algorithm
  pub fn expand_key(&self) -> Rc5Result<ExpandedSecretKey<W>> {
    // 1. key bytes to words:
    let mut words: Vec<W::Type> = Self::key_to_words(&self.key);

    // 2. Initialize the key-independent array S
    let mut subkeys: Vec<W::Type> =
      Self::initialize_subkeys(self.config.rounds);

    // i = j = 0
    // A = B = 0
    // do 3 * max(t, c) times:
    //    A = S[i] = (S[i] + A + B) <<< 3
    //    B = L[j] = (L[j] + A + B) <<< (A + B)
    //    i = (i + 1) mod t
    //    j = (j + 1) mod c
    let mut i = 0;
    let mut j = 0;
    let mut a = W::Type::zero();
    let mut b = W::Type::zero();

    // 3 * max(t, c)
    let iters = max(subkeys.len(), words.len()) * 3;

    for _ in 0..iters {
      subkeys[i] = subkeys[i].wrapping_add(&a).wrapping_add(&b).rotate_left(3);
      a = subkeys[i];

      // this could be larger than the word size, so we need to mod it
      let rotation =
        a.wrapping_add(&b).to_u128().ok_or(Error::InvalidWordSize)?
          % W::WORD_SIZE_IN_BITS as u128;

      words[j] = words[j]
        .wrapping_add(&a)
        .wrapping_add(&b)
        .rotate_left(rotation as u32);
      b = words[j];

      i = (i + 1) % subkeys.len();
      j = (j + 1) % words.len();
    }

    Ok(ExpandedSecretKey { subkeys })
  }

  /// c = [max(b, 1) / u]
  /// for i = b - 1 downto 0 do
  ///   L[i/u] = (L[i/u] <<< 8) + K[i]
  fn key_to_words(key: &[u8]) -> Vec<W::Type> {
    let b = key.len();
    let c = div_ceil(max(b, 1), W::WORD_SIZE_IN_BYTES);
    let mut l = vec![W::Type::zero(); c];
    for i in (0..key.len()).rev() {
      let idx = i / W::WORD_SIZE_IN_BYTES;
      let word = <W::Type as NumCast>::from(key[i]).expect("numcast problem");
      l[idx] = l[idx].rotate_left(8).wrapping_add(&word);
    }
    l
  }

  /// S[0] = Pw;
  /// for i = 1 to t − 1 do
  ///  S[i] = S[i − 1] + Qw;
  fn initialize_subkeys(rounds: usize) -> Vec<W::Type> {
    let subkey_count = 2 * (rounds + 1); // t
    let mut subkeys = vec![W::Type::zero(); subkey_count];

    subkeys[0] = W::P;
    for i in 1..subkey_count {
      subkeys[i] = subkeys[i - 1].wrapping_add(&W::Q);
    }

    subkeys
  }
}

#[derive(Debug)]
pub struct ExpandedSecretKey<W: Rc5WordConfig> {
  subkeys: Vec<W::Type>,
}

#[cfg(test)]
mod test {
  use {super::*, crate::word_config::Rc5_32};

  #[test]
  fn test_key_to_words() {
    let key = vec![0x01, 0x02, 0x03, 0x04];
    let words = SecretKey::<Rc5_32>::key_to_words(&key);
    assert_eq!(words.len(), 1);
    assert_eq!(words[0], 0x04030201);
  }

  #[test]
  fn test_intialize_subkeys() {
    let subkeys = SecretKey::<Rc5_32>::initialize_subkeys(12);
    assert_eq!(subkeys.len(), 26);
  }

  #[test]
  fn test_expanding_key() {
    let cfg = Rc5Config::<Rc5_32>::build(12, 16).unwrap();
    let key = SecretKey::new(cfg, b"i_am_a_good_key!").unwrap();
    let expanded_key = key.expand_key().unwrap();
    assert_eq!(expanded_key.subkeys.len(), 26);
  }
}
