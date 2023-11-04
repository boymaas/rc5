use thiserror::Error;

/// Possible errors that can be returned by the RC5 algorithm.
#[derive(Error, Debug)]
pub enum Error {
  #[error("bytes provided do not match word size")]
  BytesLengthMismatch,
  #[error("plaintext should be multiple of block size")]
  PlaintextBlockSizeMismatch,
  #[error("invalid word size")]
  UnsupportedWordSize,
  #[error("rounds count too large")]
  RoundsCountTooLarge,
  #[error("keysize too large")]
  KeySizeTooLarge,
  #[error("wrong keysize, expected {0}, got {1}")]
  WrongKeySize(usize, usize),
  #[error("rounds count is too large")]
  WrongRoundsCount,
}

pub type Rc5Result<T> = Result<T, Error>;
