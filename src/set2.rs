use openssl::error::ErrorStack;
use openssl::symm::{Cipher, Crypter, Mode};
use rand::{random, Rng};
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

    // Put xor_zip() inside an assert because it returns false
    // without XOR'ing anything if slices are different in size.
    assert!(crate::set1::xor_zip(&mut buf[..n], &prev));

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

//
// Challenge 11: An ECB/CBC detection oracle.
//
type AesChaos = fn(&[u8]) -> Result<AesMonkey, ErrorStack>;

pub struct AesMonkey {
  cipher: Cipher,
  ciphertext: Vec<u8>,
}

// This function generates a random key, and encrypts data with it. Half
// of the time it will use AES-128-ECB, the other half AES-128-CBC. It's
// the “encryption oracle” from the challenge writeup.
//
// Returns the ciphertext _and_ the used cipher:
fn aes_chaos_monkey(plaintext: &[u8]) -> Result<AesMonkey, ErrorStack> {
  // (1) Generate a random key and encrypt under it.
  let mut rng = rand::thread_rng();
  let key = random::<[u8; 16]>();

  // (2) Have the function choose to encrypt under ECB 1/2 the time, and under
  //     CBC the other half.
  let cipher;
  let iv_arr;
  let iv: Option<&[u8]>; // Specify type to easily coerce array to slice below.

  if rng.gen() {
    iv = None;
    cipher = Cipher::aes_128_ecb();
  } else {
    cipher = Cipher::aes_128_cbc();
    iv_arr = random::<[u8; 16]>();
    iv = Some(&iv_arr);
  }

  // (3) Have the function append 5-10 bytes (count chosen randomly)
  // before the plaintext and 5-10 bytes after the plaintext.
  let n = rng.gen_range(5, 11);
  let m = rng.gen_range(5, 11);
  let mid = n + plaintext.len();
  let mut data = Vec::with_capacity(mid + m);

  // (3a) Add the ‘n’ preamble bytes.
  data.resize(n, 0);
  rng.fill(&mut data[..]);

  // (3b) Add the actual plaintext.
  data.extend_from_slice(plaintext);
  assert_eq!(data.len(), mid);

  // (3c) Add the ‘m’ postamble bytes.
  data.resize(mid + m, 0);
  rng.fill(&mut data[mid..]);

  // (4) Profit.
  let mut n = 0;
  let mut buf = vec![0; data.len() + cipher.block_size()];
  let mut crypt = Crypter::new(cipher, Mode::Encrypt, &key, iv)?;

  n += crypt.update(&data, &mut buf)?;
  n += crypt.finalize(&mut buf[n..])?;

  buf.truncate(n);

  Ok(AesMonkey {
    cipher,
    ciphertext: buf,
  })
}
