use {
  crate::{error::Error, word_config::Rc5WordConfig},
  num::traits::{PrimInt, ToPrimitive, WrappingAdd, WrappingSub},
  std::ops::BitXor,
};

/// Block Encryption
///
/// This function assumes that the input block is given in two w-bit registers,
/// A and B. It also assumes that key expansion has already been performed,
/// resulting in the computation of the array S[0...t−1].
///
/// A = A + S[0];
/// B = B + S[1];
/// for i = 1 to r do
///   A = ((A ⊕ B) < B) + S[2 ∗ i];
///   B = ((B ⊕ A) < A) + S[2 ∗ i + 1];
/// end for
///
/// The output is in the registers A and B.
pub fn encrypt_block<W: Rc5WordConfig>(
  expanded_key: &[W::Type],
  mut block: [W::Type; 2], // A and B
) -> Result<[W::Type; 2], Error> {
  let num_rounds = (expanded_key.len() / 2) - 1;
  block[0] = block[0].wrapping_add(&expanded_key[0]);
  block[1] = block[1].wrapping_add(&expanded_key[1]);

  for i in 1..=num_rounds {
    let rotation = block[1].to_u128().ok_or(Error::InvalidWordSize)?
      % W::WORD_SIZE_IN_BITS as u128;
    block[0] = (block[0].bitxor(block[1]))
      .rotate_left(rotation as u32)
      .wrapping_add(&expanded_key[2 * i]);

    let rotation = block[0].to_u128().ok_or(Error::InvalidWordSize)?
      % W::WORD_SIZE_IN_BITS as u128;
    block[1] = (block[1].bitxor(block[0]))
      .rotate_left(rotation as u32)
      .wrapping_add(&expanded_key[2 * i + 1]);
  }

  Ok(block)
}

/// Block Decryption
///
/// for i=r downto 1 do
///   B = ((B − S[2 ∗ i + 1]) > A) ⊕ A;
///   A = ((A − S[2 ∗ i]) > B) ⊕ B;
///   
/// B = B − S[1];
/// A = A − S[0];
pub fn decrypt_block<W: Rc5WordConfig>(
  expanded_key: &[W::Type],
  mut block: [W::Type; 2],
) -> Result<[W::Type; 2], Error> {
  let num_rounds = (expanded_key.len() / 2) - 1;

  for i in (1..=num_rounds).rev() {
    let rotation = block[0].to_u128().ok_or(Error::InvalidWordSize)?
      % W::WORD_SIZE_IN_BITS as u128;

    block[1] = (block[1].wrapping_sub(&expanded_key[2 * i + 1]))
      .rotate_right(rotation as u32)
      .bitxor(block[0]);

    let rotation = block[1].to_u128().ok_or(Error::InvalidWordSize)?
      % W::WORD_SIZE_IN_BITS as u128;
    block[0] = (block[0].wrapping_sub(&expanded_key[2 * i]))
      .rotate_right(rotation as u32)
      .bitxor(block[1]);
  }

  block[1] = block[1].wrapping_sub(&expanded_key[1]);
  block[0] = block[0].wrapping_sub(&expanded_key[0]);

  Ok(block)
}
