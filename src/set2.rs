use openssl::error::ErrorStack;
use openssl::symm::{Cipher, Crypter, Mode};
use std::iter;

//
// Challenge 9: Implement PKCS#7 padding.
//
pub fn pkcs7_pad(data: &mut Vec<u8>, block_len: u8) {
  let block_len = block_len as usize;
  let pad_byte = block_len - (data.len() % block_len);
  data.extend(iter::repeat(pad_byte as u8).take(pad_byte));
}

//
// Challenge 10: Implement CBC mode.
//
/// Decrypts AES-128-CBC just using ECB mode as primitive.
pub fn decrypt_aes_128_cbc(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, ErrorStack> {
  let keylen = key.len();
  assert_eq!(keylen, iv.len());
  assert_eq!(0, data.len() % keylen); // FIXME: drop this requirement?

  let cipher = Cipher::aes_128_ecb();
  let mut ret = Vec::new();
  let mut prev = iv.to_owned();
  let mut buf = vec![0; keylen + cipher.block_size()];
  let mut crypt = Crypter::new(cipher, Mode::Decrypt, key, None)?;

  for block in data.chunks(keylen) {
    assert_eq!(block.len(), keylen);
    let mut n = 0;
    crypt.pad(false);

    n += crypt.update(block, &mut buf)?;
    n += crypt.finalize(&mut buf[n..])?;

    assert!(crate::set1::xor_zip(&mut buf[..n], &prev));

    ret.extend(&buf[..n]);
    prev.splice(.., block.iter().cloned());
  }

  // Undo PKCS#7 padding.
  if let Some(&b) = ret.last() {
    let start = ret.len() - b as usize;
    if ret[start..].iter().all(|&c| c == b) {
      ret.truncate(start);
    }
  }

  Ok(ret)
}
