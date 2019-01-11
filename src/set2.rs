use openssl::symm::{Cipher, Crypter, Mode};
use rand::{random, Rng};
use simple_error::bail;

use std::collections::HashMap;
use std::error::Error;
use std::iter;

mod oracle;
pub use self::oracle::AesOracle;

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
  let mut crypt = Crypter::new(cipher, Mode::Decrypt, key, None)?;
  crypt.pad(false);

  let mut n = 0;
  let mut tot = 0;
  let mut buf = vec![0; data.len() + cipher.block_size()];
  let mut prev = iv.to_owned();

  for block in data.chunks(keylen) {
    assert_eq!(block.len(), keylen);

    n += crypt.update(block, &mut buf[tot..])?;

    // Must check xor_zip() return value because it does nothing
    // if the slices are different in size.
    if !crate::set1::xor_zip(&mut buf[tot..n], &prev) {
      bail!("xor_zip() returned false");
    }

    // This hopefully doesn't allocate.
    prev.truncate(0);
    prev.extend_from_slice(block); /* It's certainly more readable than:
                                    * prev.splice(.., block.iter().cloned()); */
    tot = n;
  }

  n += crypt.finalize(&mut buf[tot..])?;
  buf.truncate(n);

  // Undo PKCS#7 padding.
  if let Some(&b) = buf.last() {
    let start = buf.len() - b as usize;
    if buf[start..].iter().all(|&c| c == b) {
      buf.truncate(start);
    }
  }

  Ok(buf)
}

//
// Challenge 11: An ECB/CBC detection oracle.
//
type RandomEnc = fn(&[u8]) -> Result<Ciphertext, Box<Error>>;

pub struct Ciphertext {
  cipher: Cipher,
  ciphertext: Vec<u8>,
}

pub struct OracleGuess {
  pub actual: Cipher,
  pub guessed: Cipher,
}

// Guesses if an oracle encrypted in EBC or CBC mode.
// Returns a tuple (guessed_cipher, actual_cipher) so that
// accuracy can be verified.
pub fn discern_ecb_cbc(oracle: Option<RandomEnc>) -> OracleGuess {
  let input = "A".repeat(1024); // ¯\_(ツ)_/¯
  let oracle = oracle.unwrap_or(aes_random_enc);
  let result = oracle(input.as_bytes()).unwrap();
  let count = crate::set1::max_repeat_count(&result.ciphertext, 16);

  if count >= 10 {
    OracleGuess {
      actual: result.cipher,
      guessed: Cipher::aes_128_ecb(),
    }
  } else {
    OracleGuess {
      actual: result.cipher,
      guessed: Cipher::aes_128_cbc(),
    }
  }
}

// This function generates a random key, and encrypts data with it. Half
// of the time it will use AES-128-ECB, the other half AES-128-CBC. It's
// the “encryption oracle” from the challenge writeup.
//
// Returns the ciphertext _and_ the used cipher:
fn aes_random_enc(plaintext: &[u8]) -> Result<Ciphertext, Box<Error>> {
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

  Ok(Ciphertext {
    cipher,
    ciphertext: buf,
  })
}

//
// Challenge 12: Byte-at-a-time ECB decryption (Simple).
//
pub fn break_ecb_simple(oracle: &AesOracle) -> Vec<u8> {
  // (1) Discover the block size of the cipher. (You know it,
  // but do this step anyway.)
  let bsize = oracle_block_size(oracle);
  assert_eq!(16, bsize);

  // (2) Detect that the function is using ECB. (You already know,
  // but do this step anyway.)
  let repeat = "A".repeat(bsize * 2);
  let ecb_data = oracle.encrypt_with_controlled(repeat.as_bytes()).unwrap();
  assert_eq!(ecb_data[..bsize], ecb_data[bsize..bsize * 2]);

  let mut deciphered = vec![];
  let paylen = oracle.encrypt_with_controlled(&[]).unwrap().len();
  let craft_byte = 0u8; // Any value will do.

  for i in 0..paylen {
    // (3) Knowing the block size [and how many bytes you've uncovered],
    // craft an input block that is exactly 1 byte short.
    let input = vec![craft_byte; bsize - (i % bsize) - 1];
    if let Some(byte) = dictionary_attack(oracle, input, &deciphered) {
      deciphered.push(byte);
    } else {
      // Hopefully this is the _second_ padding byte (PKCS#7).
      deciphered.pop();
      break;
    }
  }

  deciphered
}

fn dictionary_attack(oracle: &AesOracle, mut input: Vec<u8>, known: &[u8]) -> Option<u8> {
  let totlen = input.len() + known.len() + 1;
  let mut dict = HashMap::new();
  let mut want = oracle.encrypt_with_controlled(&input).unwrap();

  assert_eq!(totlen % 16, 0);

  want.truncate(totlen);
  input.extend_from_slice(known);

  // (4) Make a dictionary of very possible last byte by feeding different
  // strings to the oracle.
  input.push(0);
  assert_eq!(totlen, input.len());

  for c in 0..=255 {
    input[totlen - 1] = c;
    let mut have = oracle.encrypt_with_controlled(&input).unwrap();
    have.truncate(totlen);
    dict.insert(have, c);
  }

  // (5) Match the output of the one-byte-short input to one of the entries in
  // your dictionary. You've now discovered the first byte of unknown-string.
  dict.get(&want).cloned()
}

fn oracle_block_size(oracle: &AesOracle) -> usize {
  let paylen = |pfx: &Vec<u8>| oracle.encrypt_with_controlled(pfx).unwrap().len();

  let mut pfx = vec![];
  let mut len = paylen(&pfx);
  let mut newlen;

  loop {
    // This loop could hangs if oracle misbehaves.
    pfx.push(0);
    newlen = paylen(&pfx);

    if newlen > len {
      break newlen - len;
    }
    len = newlen;
  }
}
