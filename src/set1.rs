use data_encoding::BASE64;
use data_encoding::HEXLOWER_PERMISSIVE as HEX;

use std::collections::{HashMap, HashSet};
use std::fs;

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
/// Destructively applies XOR: a[i] ^= b[i].
pub fn xor_zip(a: &mut [u8], b: &[u8]) -> bool {
  if a.len() != b.len() {
    return false;
  }
  for (i, x) in a.iter_mut().enumerate() {
    *x ^= b[i];
  }
  true
}

//
// Challenge 3: Single-byte XOR cipher.
//
/// Returns the most likely decoding of a single-byte XOR encoding.
// TODO: do not hard-code FREQ_EN.
pub fn unscramble_byte_xor(data: &[u8]) -> XorResult {
  let mut ret = XorResult {
    distance: std::f64::MAX,
    key: 0,
    result: String::new(),
  };
  let mut dec_data = data.to_owned();

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
        key: key,
        distance: d,
        result: s.to_string(),
      };
    }
  }
  ret
}

/// Leaves in ‘dst’ the result of `src ^ byte`.
fn xor_byte_into(src: &[u8], byte: u8, dst: &mut [u8]) {
  for (i, c) in src.into_iter().enumerate() {
    dst[i] = c ^ byte;
  }
}

///
/// Challenge 4: Detect single-character XOR
///
/// Detects which line in a file was single-byte XOR'd.
pub fn find_xor_str(filename: &str) -> String {
  fs::read_to_string(filename)
    .unwrap()
    .lines()
    .map(|l| unscramble_byte_xor(&HEX.decode(l.as_bytes()).unwrap()))
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
  let mut distance = unknown_count.pow(2) as f64;

  for (c, freq) in freqs {
    let freq = freq * len;
    distance += match counts.get(c) {
      Some(&x) => (freq - x as f64).powi(2),
      None => freq.powi(2),
    };
  }

  distance.sqrt()
}

//
// Challenge 5: Implement repeating-key XOR
//
pub fn xor_cycle(buf: &mut [u8], key: &[u8]) {
  for (dst, &byte) in buf.iter_mut().zip(key.into_iter().cycle()) {
    *dst ^= byte;
  }
}

//
// Challenge 6: Break repeating-key XOR.
//
/// Returns the XOR key. File should be in base64.
pub fn break_cycling_xor(filename: &str) -> Vec<u8> {
  let data = crate::read_base64(filename);
  let mut klen: Vec<usize> = (1..40).collect();

  // This is slightly inefficient because sort_by_key() does not implement a
  // Schwartzian transform. See <rust-lang/rust#34447>.
  klen.sort_by_key(|&k| ImplOrd(keysize_distance(&data, k, 4)));

  (&klen[0..3])
    .iter()
    .map(|&keysize| guess_xor_transposed(&data, keysize))
    .min_by_key(|&(_, distance)| ImplOrd(distance))
    .unwrap()
    .0
}

/// Computes the Hamming distance.
pub fn hamming_distance(a: &[u8], b: &[u8]) -> u32 {
  a.into_iter()
    .zip(b)
    .map(|(x, y)| (x ^ y).count_ones())
    .sum()
}

/// Compute the distance for a number of KEYSIZE blocks.
///
/// The first ‘num_slices’ blocks are compared to the one following them. NOTE:
/// good values for ‘num_slices’ seem to be 3 or 4; they place the appropriate
/// KEYSIZE (29 for challenge 1-6) at the third place. See sort_by_key() above.
fn keysize_distance(data: &[u8], keysize: usize, num_slices: usize) -> f64 {
  let f = |n| {
    hamming_distance(
      &data[keysize * n..keysize * (n + 1)],
      &data[keysize * (n + 1)..keysize * (n + 2)],
    ) as f64
  };
  let mut sum = 0.0;
  let num_bytes = keysize * num_slices;

  // TODO: use fold()
  for i in 0..num_slices {
    sum += f(i)
  }

  sum / num_bytes as f64
}

/// Finds out each byte of a cycling-XOR key of ‘keysize’ bytes.
fn guess_xor_transposed(data: &[u8], keysize: usize) -> (Vec<u8>, f64) {
  let mut distance = 0.0;
  let mut key = Vec::with_capacity(keysize);
  let mut bytes = Vec::with_capacity(data.len() / keysize);

  for k in 0..keysize {
    // Guess the key for all characters with the same `mod key` value.
    bytes.truncate(0);
    bytes.extend(
      data
        .into_iter()
        .enumerate()
        // Use iter::Step when available.
        .filter(|&(i, _)| i % keysize == k)
        .map(|(_, &c)| c),
    );
    let XorResult {
      key: k,
      distance: d,
      ..
    } = unscramble_byte_xor(&bytes);
    key.push(k);
    distance += d;
  }

  (key, distance)
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

#[derive(Clone, PartialEq, PartialOrd)]
struct ImplOrd<T>(T);

impl<T: PartialEq> Eq for ImplOrd<T> {}

impl<T: PartialOrd> Ord for ImplOrd<T> {
  fn cmp(&self, other: &ImplOrd<T>) -> std::cmp::Ordering {
    self.partial_cmp(other).unwrap() // Will panic on failure.
  }
}
