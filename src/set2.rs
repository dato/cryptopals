use openssl::symm::{Cipher, Crypter, Mode};
use std::error::Error;
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
pub fn decrypt_aes_128_cbc(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, Box<Error>> {
  let keylen = key.len();

  assert_eq!(keylen, iv.len());
  assert_eq!(0, data.len() % keylen);

  let cipher = Cipher::aes_128_ecb();
  let mut ret = Vec::with_capacity(data.len());
  let mut prev = iv.to_owned();
  let mut buf = vec![0; keylen + cipher.block_size()];

  // Technically this should be inside the loop, because API docs
  // mandate that update() not be called after finalize().
  let mut crypt = Crypter::new(cipher, Mode::Decrypt, key, None)?;
  crypt.pad(false);

  for block in data.chunks(keylen) {
    assert_eq!(block.len(), keylen);
    let mut n = 0;

    n += crypt.update(block, &mut buf)?;
    n += crypt.finalize(&mut buf[n..])?;

    // Must check xor_zip() return value because it does nothing
    // if the slices are different in size.
    if !crate::set1::xor_zip(&mut buf[..n], &prev) {
      bail!("xor_zip() returned false");
    }

    ret.extend(&buf[..n]);

    // This hopefully doesn't allocate.
    prev.truncate(0);
    prev.extend_from_slice(block); /* It's certainly more readable than:
                                    * prev.splice(.., block.iter().cloned()); */
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
