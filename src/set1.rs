use data_encoding::BASE64;
use data_encoding::HEXLOWER_PERMISSIVE as HEX;
use openssl::symm::{Cipher, Crypter, Mode};

use std::cmp::Eq;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fs;
use std::hash::Hash;

#[derive(Debug)]
pub struct XorResult {
  pub key: u8,
  pub distance: f64,
  pub result: String,
}

//
// Challenge 1: Convert hex to base64.
//
/// Converts a hexadecimal string to BASE64.
pub fn hex_to_base64(hex: &str) -> Option<String> {
  let hex = HEX.decode(hex.as_bytes()).ok()?;
  Some(BASE64.encode(&hex))
}

//
// Challenge 2: Fixed XOR.
//
/// Destructively applies XOR: a[i] ^= b[i]. Slices must be equal size.
pub fn xor_zip(a: &mut [u8], b: &[u8]) {
  assert_eq!(a.len(), b.len());

  for (i, x) in a.iter_mut().enumerate() {
    *x ^= b[i];
  }
}

//
// Challenge 3: Single-byte XOR cipher.
//
/// Returns the most likely decoding of a single-byte XOR encoding.
// TODO: do not hard-code FREQ_EN.
pub fn break_xor_byte(data: &[u8]) -> XorResult {
  let mut ret = XorResult {
    distance: std::f64::MAX,
    key: 0,
    result: String::new(),
  };
  let mut dec_data = data.to_vec();

  for key in 0..=255 {
    // Compute the XOR decoding. We use an explicit loop and not map() plus
    // min() to avoid creating too many String objects.
    xor_byte_into(data, key, &mut dec_data);
    // Compute distance.
    let s = String::from_utf8_lossy(&dec_data);
    let d = freq_distance(&s, &FREQ_EN);
    // Update if necessary.
    if d < ret.distance {
      ret = XorResult {
        key,
        distance: d,
        result: s.to_string(),
      };
    }
  }
  ret
}

/// Leaves in ‘dst’ the result of `src ^ byte`.
fn xor_byte_into(src: &[u8], byte: u8, dst: &mut [u8]) {
  for (i, c) in src.iter().enumerate() {
    dst[i] = c ^ byte;
  }
}

///
/// Challenge 4: Detect single-character XOR
///
/// Detects which line in a file was single-byte XOR'd.
pub fn find_xor_byte(filename: &str) -> String {
  fs::read_to_string(filename)
    .unwrap()
    .lines()
    .map(|l| break_xor_byte(&HEX.decode(l.as_bytes()).unwrap()))
    .min_by_key(|&XorResult { distance: d, .. }| ImplOrd(d))
    .unwrap()
    .result
}

/// Computes the distance between a string and a table of frequencies.
fn freq_distance(data: &str, freqs: &[(char, f64)]) -> f64 {
  let mut counts = HashMap::new();
  let mut unknown_count = 0u32;
  let known_chars: HashSet<char> = freqs.iter().map(|&(c, _)| c).collect();
  let ignore_chars: HashSet<char> = r#" ,;:.!?()-'""#.chars().collect();

  for c in data.chars() {
    let c = c.to_ascii_lowercase();
    if known_chars.contains(&c) {
      *counts.entry(c).or_insert(0) += 1;
    } else if !ignore_chars.contains(&c) {
      unknown_count += 1;
    }
  }

  let len = data.len() as f64;
  let mut distance = f64::from(unknown_count.pow(2));

  for (c, freq) in freqs {
    let freq = freq * len;
    distance += match counts.get(c) {
      Some(&x) => (freq - f64::from(x)).powi(2),
      None => freq.powi(2),
    };
  }

  distance.sqrt()
}

//
// Challenge 5: Implement repeating-key XOR
//
pub fn xor_cycle(buf: &mut [u8], key: &[u8]) {
  for (dst, &byte) in buf.iter_mut().zip(key.iter().cycle()) {
    *dst ^= byte;
  }
}

//
// Challenge 6: Break repeating-key XOR.
//
/// Returns the XOR key. File should be in base64.
pub fn break_xor_cycle(data: &[u8]) -> Vec<u8> {
  let mut klen: Vec<usize> = (2..=40).collect();

  // This is inefficient. Better use sort_by_cached_key() when stabilized:
  // https://doc.rust-lang.org/nightly/std/primitive.slice.html#method.sort_by_cached_key.
  klen.sort_by_key(|&k| ImplOrd(keysize_distance(data, k, 4)));

  (&klen[0..3])
    .iter()
    .map(|&keysize| break_xor_cycle_keylen(data, keysize))
    .min_by_key(|&(_, distance)| ImplOrd(distance))
    .unwrap()
    .0
}

/// Computes the Hamming distance.
pub fn hamming_distance(a: &[u8], b: &[u8]) -> u32 {
  a.iter().zip(b).map(|(x, y)| (x ^ y).count_ones()).sum()
}

/// Compute the distance for a number of KEYSIZE blocks.
///
/// The first ‘num_slices’ blocks are compared to the one following them. NOTE:
/// good values for ‘num_slices’ seem to be 3 or 4; they place the appropriate
/// KEYSIZE (29 for challenge 1-6) at the third place. See sort_by_key() above.
fn keysize_distance(data: &[u8], keysize: usize, num_slices: usize) -> f64 {
  let dist = |n| {
    hamming_distance(
      &data[keysize * n..keysize * (n + 1)],
      &data[keysize * (n + 1)..keysize * (n + 2)],
    )
  };
  let sum = f64::from((0..num_slices).map(dist).sum::<u32>());
  let normsize = (keysize * num_slices) as f64;

  sum / normsize
}

/// Finds cycling-XOR key of ‘keysize’ bytes; returns key and distance.
fn break_xor_cycle_keylen(data: &[u8], keysize: usize) -> (Vec<u8>, f64) {
  let mut distance = 0.0;
  let mut key = Vec::with_capacity(keysize);
  let mut bytes = Vec::with_capacity(data.len() / keysize);

  for k in 0..keysize {
    // Guess the key for all characters with the same `mod key` value.
    bytes.truncate(0);
    bytes.extend(data.iter().skip(k).step_by(keysize));
    let XorResult {
      key: k,
      distance: d,
      ..
    } = break_xor_byte(&bytes);
    key.push(k);
    distance += d;
  }

  (key, distance)
}

//
// Challenge 7: AES in ECB mode.
//
pub fn decrypt_aes_128_ecb(data: &[u8], key: &[u8]) -> Result<Vec<u8>, Box<Error>> {
  let cipher = Cipher::aes_128_ecb();
  let mut crypt = Crypter::new(cipher, Mode::Decrypt, key, None)?;
  let mut ret = vec![0; data.len() + cipher.block_size()];
  let mut tot = 0;

  tot += crypt.update(&data, &mut ret)?;
  tot += crypt.finalize(&mut ret[tot..])?;

  ret.truncate(tot);

  Ok(ret)
}

pub fn encrypt_aes_128_ecb(data: &[u8], key: &[u8]) -> Result<Vec<u8>, Box<Error>> {
  let cipher = Cipher::aes_128_ecb();
  let mut crypt = Crypter::new(cipher, Mode::Encrypt, key, None)?;
  let mut ret = vec![0; data.len() + cipher.block_size()];
  let mut tot = 0;

  tot += crypt.update(&data, &mut ret)?;
  tot += crypt.finalize(&mut ret[tot..])?;
  ret.truncate(tot);
  Ok(ret)
}

//
// Challenge 8: Detect AES in ECB mode.
//
pub fn find_aes_ecb(filename: &str) -> Option<String> {
  fs::read_to_string(filename)
    .unwrap()
    .lines()
    .map(|hex| {
      // We needn't decode if we use blocks of 32 chars.
      (hex, max_repeat_count(hex.as_bytes(), 32))
    })
    .max_by_key(|&(_, count)| count)
    .map(|(hex, _)| hex.to_owned())
}

pub fn max_repeat_count<T: Hash + Eq>(data: &[T], block_size: usize) -> usize {
  let mut counts = HashMap::new();
  for block in data.chunks(block_size) {
    *counts.entry(block).or_insert(0) += 1;
  }
  *counts.values().max().unwrap_or(&0)
}

const FREQ_EN: [(char, f64); 26] = [
  // From: https://en.wikipedia.org/wiki/Letter_frequency
  ('a', 0.08167),
  ('b', 0.01492),
  ('c', 0.02782),
  ('d', 0.04253),
  ('e', 0.12702),
  ('f', 0.02228),
  ('g', 0.02015),
  ('h', 0.06094),
  ('i', 0.06966),
  ('j', 0.00153),
  ('k', 0.00772),
  ('l', 0.04025),
  ('m', 0.02406),
  ('n', 0.06749),
  ('o', 0.07507),
  ('p', 0.01929),
  ('q', 0.00095),
  ('r', 0.05987),
  ('s', 0.06327),
  ('t', 0.09056),
  ('u', 0.02758),
  ('v', 0.00978),
  ('w', 0.02361),
  ('x', 0.00150),
  ('y', 0.01974),
  ('z', 0.00074),
];

/// ImplOrd takes a PartialOrd and coerces it into Ord.
///
/// Unlike BurntSushi’s original implementation, it panics when a comparison
/// yields None.
///
/// Stolen from https://github.com/BurntSushi/rust-stats/blob/0.1.27/src/lib.rs#L12.

#[derive(PartialEq, PartialOrd)]
struct ImplOrd<T>(T);

impl<T: PartialEq> Eq for ImplOrd<T> {}

impl<T: PartialOrd> Ord for ImplOrd<T> {
  fn cmp(&self, other: &ImplOrd<T>) -> std::cmp::Ordering {
    self.partial_cmp(other).unwrap() // Will panic on failure.
  }
}

mod challenge01 {
  #[test]
  fn test() {
    // Convert hex to base64.
    // https://cryptopals.com/sets/1/challenges/1
    let hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    assert_eq!(
      super::hex_to_base64(hex).unwrap(),
      "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    );
  }
}

mod challenge02 {
  use data_encoding::HEXLOWER_PERMISSIVE as HEX;

  #[test]
  fn test() {
    // Fixed XOR.
    // https://cryptopals.com/sets/1/challenges/2
    let mut a = HEX.decode(b"1c0111001f010100061a024b53535009181c").unwrap();
    let b = HEX.decode(b"686974207468652062756c6c277320657965").unwrap();
    super::xor_zip(&mut a, &b);
    assert_eq!(HEX.encode(&a), "746865206b696420646f6e277420706c6179");
  }
}

mod challenge03 {
  use data_encoding::HEXLOWER_PERMISSIVE as HEX;

  #[test]
  fn test() {
    // Single-byte XOR cipher
    // https://cryptopals.com/sets/1/challenges/3
    let bytes = HEX
      .decode(b"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
      .unwrap();
    assert_eq!(
      super::break_xor_byte(&bytes).result,
      "Cooking MC's like a pound of bacon"
    );
  }
}

mod challenge04 {
  #[test]
  fn test() {
    // Detect single-character XOR
    // https://cryptopals.com/sets/1/challenges/4
    assert_eq!(
      super::find_xor_byte("input/04"),
      "Now that the party is jumping\n"
    );
  }
}

mod challenge05 {
  use data_encoding::HEXLOWER_PERMISSIVE as HEX;

  #[test]
  fn test() {
    // Implement repeating-key XOR
    // https://cryptopals.com/sets/1/challenges/5
    let mut bytes =
      b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal".to_vec();
    super::xor_cycle(&mut bytes, b"ICE");
    assert_eq!(
      HEX.encode(&bytes),
      concat!(
        "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272",
        "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
      )
    );
  }
}

mod challenge06 {
  #[test]
  fn test() {
    // Break repeating-key XOR
    // https://cryptopals.com/sets/1/challenges/6
    assert_eq!(
      super::hamming_distance(b"this is a test", b"wokka wokka!!!"),
      37
    );
    assert_eq!(
      super::break_xor_cycle(&crate::read_base64("input/06")),
      b"Terminator X: Bring the noise"
    );
  }
}

mod challenge07 {
  #[test]
  fn test() {
    // AES in ECB mode.
    // https://cryptopals.com/sets/1/challenges/7
    let data = crate::read_base64("input/07");
    let key = b"YELLOW SUBMARINE";
    let res = super::decrypt_aes_128_ecb(&data, key).unwrap();
    assert_eq!(res.len(), 2876);
    assert_eq!(
      String::from_utf8_lossy(&res).lines().last().unwrap(),
      "Play that funky music "
    );
    let newdata = super::encrypt_aes_128_ecb(&res, key).unwrap();
    assert_eq!(newdata, data);
  }
}

mod challenge08 {
  #[test]
  fn test() {
    // Detect AES in ECB mode.
    // https://cryptopals.com/sets/1/challenges/8
    assert_eq!(
      super::find_aes_ecb("input/08").unwrap(),
      "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a");
  }
}
