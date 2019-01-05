use data_encoding::HEXLOWER_PERMISSIVE as hex;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

use crate::bytes::Bytes;

#[derive(Debug)]
struct XorResult {
  key: u8,
  distance: f64,
  result: String,
}

/// Returns the most likely decoding of a single-byte XOR.
// TODO: do not hard-code FREQ_EN.
fn decode_single_byte(data: &[u8]) -> XorResult {
  let mut ret = XorResult {
    distance: ::std::f64::MAX,
    key: 0,
    result: String::new(),
  };
  let mut dec_data = data.to_owned();

  for key in 0..255 {
    // Compute the XOR decoding. We use an explicit loop and not map() plus
    // min() to avoid creating too many String objects.
    xor_byte_inplace(data, &mut dec_data, key);
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

/// Solves https://cryptopals.com/sets/1/challenges/4.
pub fn find_xor_str(filename: &str) -> String {
  fs::read_to_string(filename)
    .unwrap()
    .lines()
    .map(|l| decode_single_byte(&hex.decode(l.as_bytes()).unwrap()))
    .min_by_key(|&XorResult { distance: d, .. }| ImplOrd(d))
    .unwrap()
    .result
}

/// Leaves in ‘dst’ the result of `src ^ byte`.
// TODO: use Bytes::xor_cycle() instead.
fn xor_byte_inplace(src: &[u8], dst: &mut [u8], byte: u8) {
  for (i, c) in src.into_iter().enumerate() {
    dst[i] = c ^ byte;
  }
}

/// Computes the distance between a string and a table of frequencies.
/// TODO: uppercase, spaces, punctuation.
fn freq_distance(data: &str, freqs: &[(char, f64)]) -> f64 {
  let mut counts = HashMap::new();
  let mut unknown_count = 0u32;
  let known_chars: HashSet<char> = freqs.iter().map(|&(c, _)| c).collect();

  // TODO: use sort + group_by instead?
  for c in data.chars() {
    let val = if known_chars.contains(&c) {
      counts.entry(c).or_insert(0)
    } else {
      &mut unknown_count
    };
    *val += 1;
  }

  let len = data.len() as f64;
  let mut distance = unknown_count.pow(2) as f64;

  for &(c, freq) in freqs {
    let freq = freq * len;
    distance += match counts.get(&c) {
      Some(&x) => (freq - x as f64).powi(2),
      None => freq.powi(2),
    };
  }

  distance.sqrt()
}

/// Solves https://cryptopals.com/sets/1/challenges/6.
/// Returns the XOR key. File should be in base64.
pub fn break_cycling_xor(filename: &str) -> Vec<u8> {
  let data = crate::read_base64(Path::new(filename)).unwrap();
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

/// Compute the distance for a number of KEYSIZE blocks.
///
/// The first ‘num_slices’ blocks are compared to the one following them. NOTE:
/// good values for ‘num_slices’ seem to be 3 or 4; they place the appropriate
/// KEYSIZE (29 for challenge 1-6) at the third place. See sort_by_key() above.
fn keysize_distance(data: &[u8], keysize: usize, num_slices: usize) -> f64 {
  let f = |n| {
    Bytes::hamming_distance(
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
    } = decode_single_byte(&bytes);
    key.push(k);
    distance += d;
  }

  (key, distance)
}

#[cfg(test)]
mod test {
  use super::decode_single_byte;
  use super::*;
  use crate::bytes::Bytes;

  #[test]
  fn challenge_3() {
    assert_eq!(
      "Cooking MC's like a pound of bacon",
      decode_single_byte(
        &Bytes::from_hex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
          .data()
      )
      .result
    );
  }

  #[test]
  fn challenge_4() {
    assert_eq!(
      "Now that the party is jumping\n",
      find_xor_str("challenge-data/4.txt")
    );
  }

  #[test]
  fn challenge_6() {
    assert_eq!(
      break_cycling_xor("challenge-data/6.txt"),
      b"Terminator X: Bring the noise"
    );
  }
}

const FREQ_EN: [(char, f64); 27] = [
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
  (' ', 0.13000), // XXX this is approx but breaks the distribution
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
  fn cmp(&self, other: &ImplOrd<T>) -> ::std::cmp::Ordering {
    self.partial_cmp(other).unwrap() // Will panic on failure.
  }
}
