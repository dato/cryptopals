use std::collections::{HashMap, HashSet};
use bytes::Bytes;

pub fn decode_single_byte(b: &Bytes) -> String {
  let orig_data = b.data();
  let candidates = single_xor_candidates(&orig_data);

  // Return the minimum-distance string.
  candidates
    .into_iter()
    .min_by_key(|&(_, ref s)| ImplOrd(freq_distance(s, &FREQ_EN)))
    .unwrap()
    .1
}

/// Returns all possible xor-decodings of ‘data’, keyed by byte.
fn single_xor_candidates(data: &[u8]) -> Vec<(u8, String)> {
  (0..255)
    .map(|byte| (byte,
                 String::from_utf8_lossy(&xor_byte(data, byte)).to_string()))
    .collect()
}

/// Applies (^ byte) to all the bytes in ‘data’
fn xor_byte(data: &[u8], byte: u8) -> Vec<u8> {
  data.into_iter().map(|c| c ^ byte).collect()
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
      None     => freq.powi(2)
    };
  }

  distance.sqrt()
}

#[cfg(test)]
mod test {
  use super::*;
  use ::bytes::Bytes;

  #[test]
  fn single_byte() {
    assert_eq!("Cooking MC's like a pound of bacon",
               decode_single_byte(&Bytes::from_hex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")));
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
  (' ', 0.13000),  // XXX this is approx but breaks the distribution
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
        self.partial_cmp(other).unwrap() //_or(Ordering::Less)
    }
}
