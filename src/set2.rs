use openssl::symm::{Cipher, Crypter, Mode};
use rand::{random, Rng};
use simple_error::bail;

use std::collections::HashMap;
use std::error::Error;
use std::iter;

mod oracle;
pub use self::oracle::*;

// The byte value to use when breaking ECB. I used to use 0u8, but then
// challenges like #13 end up URL-quoting it. So we choose a safer one.
const PAD_BYTE: u8 = 'A' as u8;

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
  if let Some(n) = pkcs7_padding_len(&buf) {
    buf.truncate(buf.len() - n);
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
pub fn break_ecb_simple<O: Oracle>(oracle: &O) -> Vec<u8> {
  // (1) Discover the block size of the cipher. (You know it,
  // but do this step anyway.)
  let bsize = oracle_block_size(oracle);
  assert_eq!(16, bsize);

  // (2) Detect that the function is using ECB. (You already know,
  // but do this step anyway.)
  let repeat = vec![PAD_BYTE; bsize * 2];
  let ecb_data = oracle.encrypt_with_controlled(&repeat).unwrap();
  assert_eq!(ecb_data[..bsize], ecb_data[bsize..bsize * 2]);

  let mut deciphered = vec![];
  let paylen = oracle.encrypt_with_controlled(&[]).unwrap().len();

  for i in 0..paylen {
    // (3) Knowing the block size [and how many bytes you've uncovered],
    // craft an input block that is exactly 1 byte short.
    let input = vec![PAD_BYTE; bsize - (i % bsize) - 1];
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

fn dictionary_attack<O: Oracle>(oracle: &O, mut input: Vec<u8>, known: &[u8]) -> Option<u8> {
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

fn oracle_block_size<O: Oracle>(oracle: &O) -> usize {
  let paylen = |pfx: &Vec<u8>| oracle.encrypt_with_controlled(pfx).unwrap().len();

  let mut pfx = vec![];
  let mut len = paylen(&pfx);
  let mut newlen;

  loop {
    // This loop could hang if oracle misbehaves.
    pfx.push(PAD_BYTE);
    newlen = paylen(&pfx);

    if newlen > len {
      break newlen - len;
    }
    len = newlen;
  }
}

//
// Challenge 14: Byte-at-a-time ECB decryption (Harder).
//
pub fn break_ecb_hard(oracle: &RndAesOracle) -> Vec<u8> {
  // We can use break_ecb_simple() if we wrap RndAesOracle with a
  // wrapper that strips the prepended random bytes in every call
  // to encrypt_with_controlled().
  let oracle = RndAesWrap::new(oracle);
  break_ecb_simple(&oracle)
}

struct RndAesWrap<'a> {
  oracle: &'a RndAesOracle,
  block_size: usize,
  poison_len: usize,
}

impl<'a> RndAesWrap<'a> {
  fn new(oracle: &'a RndAesOracle) -> RndAesWrap {
    let block_size = oracle_block_size(oracle);
    let poison_len = oracle_poison_len(oracle, block_size).unwrap();
    RndAesWrap {
      oracle,
      block_size,
      poison_len,
    }
  }
}

impl<'a> Oracle for RndAesWrap<'a> {
  fn encrypt_with_controlled(&self, prefix: &[u8]) -> Result<Vec<u8>, Box<Error>> {
    // Neuters the poisoning bytes by padding them up to a block boundary, and
    // stripping that amount after the call to AesOracle::encrypt_with_controlled.
    let padsize = self.block_size - self.poison_len % self.block_size;
    let mut vec = vec![PAD_BYTE; padsize];
    vec.extend_from_slice(prefix);
    let ecb = self.oracle.encrypt_with_controlled(&vec);
    ecb.map(|mut v| {
      v.drain(0..self.poison_len + padsize);
      v
    })
  }
}

/// Finds out the length of the “prefix poison” (prepended random bytes).
pub fn oracle_poison_len(oracle: &RndAesOracle, bsize: usize) -> Option<usize> {
  // This verifies whether a given fill length produces two
  // identical ECB blocks at the right position.
  let verify_ecb_blocks = |bytes: &[u8], beg: usize| {
    // The encrypted data.
    let ecb = oracle.encrypt_with_controlled(&bytes).unwrap();
    let mid = beg + bsize;
    let end = mid + bsize;

    if ecb[beg..mid] != ecb[mid..end] {
      return false;
    }

    // Once we find two equal ECB blocks, we need to re-verify using
    // a different fill byte. Otherwise, our result would be incorrect
    // if the plaintext matched our fill.
    let bytes: Vec<_> = bytes.iter().map(|b| b + 1).collect();
    let ecb = oracle.encrypt_with_controlled(&bytes).unwrap();

    ecb[beg..mid] == ecb[mid..end]
  };

  let totlen = oracle.encrypt_with_controlled(&[]).unwrap().len();
  let maxblock = totlen / bsize;
  let mut bytes = vec![PAD_BYTE; bsize * 2];

  for blk in 0..maxblock {
    bytes.truncate(bsize * 2);
    for n in (0..=bsize).rev() {
      let pos = bsize * (blk + (bsize + n - 1) / bsize);
      if verify_ecb_blocks(&bytes, pos) {
        let plen = blk * bsize + n;
        return Some(plen);
      }
      bytes.push(bytes[0]);
    }
  }

  None
}

//
// Challenge 15: PKCS#7 padding validation.
//
// Returns the length of PKCS#7 padding, or None if buf is not PKCS#7-padded.
pub fn pkcs7_padding_len(buf: &[u8]) -> Option<usize> {
  match buf.last() {
    None => Some(0),
    Some(0) => None,
    Some(&b) => {
      let n = b as usize;
      let start = buf.len() - n;
      if buf[start..].iter().all(|&c| c == b) {
        Some(n)
      } else {
        None
      }
    }
  }
}
