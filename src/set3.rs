use self::challenge17::*;
use crate::set2::pkcs7_padding_len;

//
// Challenge 17: The CBC padding oracle.
// https://cryptopals.com/sets/3/challenges/17
//
pub fn break_padding_oracle(oracle: &PaddingOracle) -> Vec<u8> {
  let bsize = 16;
  let ciphertext = oracle.encrypt_some();

  let mut prev = oracle.iv().to_vec();
  let mut plaintext = vec![];
  assert_eq!(ciphertext.len() % bsize, 0);

  for block in ciphertext.chunks(bsize) {
    plaintext.append(&mut break_padding_block(oracle, block, &prev));
    prev.truncate(0);
    prev.extend_from_slice(block);
  }

  plaintext
}

fn break_padding_block(oracle: &PaddingOracle, block: &[u8], iv: &[u8]) -> Vec<u8> {
  let bsize = block.len();
  let mut cipher = vec![0; bsize]; // Why the advice to initialize with random bytes?
  let mut plaintext = Vec::new();

  // Concatenate the block we're interested in.
  cipher.extend_from_slice(block);

  // Modify cipher[..bsize] to generate valid paddings of increasing
  // length. Variable ‘plen’ is our padding length so far.
  let mut p = 0;
  let mut plen = 0;

  while p < bsize {
    let i = bsize - p - 1;

    // Increase padding byte for all affected bytes. (No-op first time.)
    for j in 1..=plen {
      cipher[i + j as usize] ^= plen ^ (plen + 1);
    }

    while !oracle.has_valid_padding(&cipher) {
      cipher[i] += 1; // Panics by overflow if oracle misbehaves.
    }

    let prev = plen;
    plen = padding_length(oracle, &cipher, prev + 1);

    if plen != prev + 1 {
      assert_eq!(p, 0); // Should only happen in the first round.
      println!("Went from padding {} to padding {} in one step", prev, plen);
    }

    // Normally we would have just one byte to cecipher, but we need
    // a loop in case the padding was longer than expected.
    let diff = (plen - prev) as usize;

    for j in 0..diff {
      plaintext.push(plen ^ cipher[i - j] ^ iv[i - j]); // plen is also padding byte.
    }

    p += diff;
  }

  // Reverse plaintext, because ciphertext was processed latest bytes first.
  plaintext.reverse();

  // Undo PKCS#7 padding.
  if let Some(n) = pkcs7_padding_len(&plaintext) {
    plaintext.truncate(plaintext.len() - n);
  }

  plaintext
}

fn padding_length(oracle: &PaddingOracle, cipher: &[u8], hint: u8) -> u8 {
  // Determine length of padding.
  let bsize = 16;
  let mut cipher = cipher.to_vec();

  assert!(oracle.has_valid_padding(&cipher));
  assert_ne!(hint, 0);

  if hint < bsize {
    // Check the byte immediately before the first padding byte. If
    // changing it doesn't break the padding, then ‘hint’ was right.
    let pos = (bsize - hint - 1) as usize;
    cipher[pos] ^= 1;

    if oracle.has_valid_padding(&cipher) {
      return hint;
    } else {
      cipher[pos] ^= 1; // Revert change and go check all bytes.
    }
  }

  // Otherwise go breaking bytes one by one.
  for i in 0..bsize {
    cipher[i as usize] ^= 1;
    if !oracle.has_valid_padding(&cipher) {
      return bsize - i;
    }
  }
  0
}

mod challenge17 {
  use super::break_padding_oracle;
  use crate::set2::*;

  use data_encoding::BASE64;
  use openssl::symm::{Cipher, Crypter, Mode};
  use rand::seq::SliceRandom;

  //
  // For challenge 17.
  //
  pub struct PaddingOracle {
    iv: Vec<u8>,
    key: Vec<u8>,
  }

  impl PaddingOracle {
    pub fn new() -> PaddingOracle {
      let iv = rand::random::<[u8; 16]>().to_vec();
      let key = rand::random::<[u8; 16]>().to_vec();
      PaddingOracle { key, iv }
    }

    // Hardcodes key and plaintext to force a padding longer than one byte. This
    // allows us to verify that this case, albeit rare, is handled correctly.
    // NOTE: break_padding_oracle() initializes the random block with zeroes;
    // anything different will break this. (An appropriate plaintext is also
    // provided.)
    fn with_lucky_padding() -> (PaddingOracle, &'static [u8]) {
      let iv = (0..16).collect();
      let key = (16..32).collect();
      (PaddingOracle { key, iv }, b"ABCDEFGHIJKLMN\x0CP")
    }

    pub fn iv(&self) -> &[u8] {
      &self.iv
    }

    // Returns the ciphertext and IV.
    pub fn encrypt_some(&self) -> Vec<u8> {
      // FIXME: Challenge says “pick one of the 10 strings at random”, but
      // this hinders testeability.
      let mut rng = rand::thread_rng();
      let base64 = C17_STR.choose(&mut rng).unwrap().as_bytes();
      let plaintext = BASE64.decode(base64).unwrap();
      encrypt_aes_128_cbc(&plaintext, &self.key, &self.iv).unwrap()
    }

    fn encrypt_this(&self, plaintext: &[u8]) -> Vec<u8> {
      encrypt_aes_128_cbc(&plaintext, &self.key, &self.iv).unwrap()
    }

    pub fn has_valid_padding(&self, ciphertext: &[u8]) -> bool {
      // Cannot use set2::decrypt_aes_128_cbc() because it strips padding.
      let cipher = Cipher::aes_128_cbc();
      let mut crypt = Crypter::new(cipher, Mode::Decrypt, &self.key, Some(&self.iv)).unwrap();
      crypt.pad(false);

      let mut n = 0;
      let mut buf = vec![0; ciphertext.len() + cipher.block_size()];

      n += crypt.update(ciphertext, &mut buf[n..]).unwrap();
      n += crypt.finalize(&mut buf[n..]).unwrap();

      buf.truncate(n);
      pkcs7_padding_len(&buf).is_some()
    }
  }

  const C17_STR: [&str; 10] = [
    "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
    "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
    "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
    "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
    "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
    "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
    "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
    "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
    "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
    "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
  ];

  #[test]
  fn test() {
    let oracle = PaddingOracle::new();
    let plaintext = break_padding_oracle(&oracle);
    assert!(plaintext.starts_with(b"00000")); // XXX
  }

  #[test]
  fn test_long_padding() {
    let (oracle, plaintext) = PaddingOracle::with_lucky_padding();
    let ciphertext = oracle.encrypt_this(plaintext);

    assert_eq!(
      super::break_padding_block(&oracle, &ciphertext, &oracle.iv()),
      plaintext
    );
  }
}
