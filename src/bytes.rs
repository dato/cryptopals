use rustc_serialize::hex::*;

#[derive(Clone)]
pub struct Bytes(Vec<u8>);

impl Bytes {
  pub fn new(xs: &[u8]) -> Bytes {
    Bytes(xs.to_vec())
  }

  pub fn from_hex(s: &str) -> Bytes {
    // TODO(dato): allow unpadded.
    Bytes(s.from_hex().unwrap())
  }

  pub fn to_hex(&self) -> String {
    self.0.to_hex()
  }

  /// Applies cyclic XOR.
  pub fn xor_cycle(&mut self, bytes: &[u8]) {
    for (dst, &byte) in self.0.iter_mut().zip(bytes.into_iter().cycle()) {
      *dst ^= byte;
    }
  }

  /// Applies XOR against a slice of the same exact size.
  pub fn xor_bytes(&mut self, bytes: &[u8]) {
    if self.0.len() != bytes.len() {
      panic!("wrong size for slice received in xor_bytes(): {} bytes, expected {}",
             bytes.len(), self.0.len());
    }
    self.xor_cycle(bytes);
  }

  /// Computes the Hamming distance
  pub fn hamming_distance(a: &[u8], b: &[u8]) -> u32 {
    let mut distance = 0;
    for (x, y) in a.into_iter().zip(b) {
      distance += (x ^ y).count_ones();
    }
    distance
  }

  pub fn data(&self) -> Vec<u8> {
    self.0.clone()
  }

  pub fn reset(&mut self, other: &Bytes) {
    (&mut self.0).copy_from_slice(&other.0);
  }
}

#[cfg(test)]
mod test {
  use super::Bytes;

  #[test]
  fn decode_hex() {
    assert_eq!(vec![14, 10], Bytes::from_hex("0E0A").0);
    assert_eq!(vec![254, 10], Bytes::from_hex("FE0A").0);
  }

  #[test]
  fn xor() {
    // https://cryptopals.com/sets/1/challenges/2
    let mut b = Bytes::from_hex("1c0111001f010100061a024b53535009181c");
    b.xor_bytes(&Bytes::from_hex("686974207468652062756c6c277320657965").data());
    assert_eq!("746865206b696420646f6e277420706c6179", b.to_hex());
  }

  #[test]
  fn xor_bytes() {
    // https://cryptopals.com/sets/1/challenges/5
    let mut b = Bytes::new(
      concat!("Burning 'em, if you ain't quick and nimble\n",
              "I go crazy when I hear a cymbal").as_bytes());
    b.xor_cycle(b"ICE");
    assert_eq!(concat!("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272",
                       "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"),
               b.to_hex());
  }

  #[test]
  fn hamming_distance() {
    assert_eq!(37, Bytes::hamming_distance(b"this is a test",
                                           b"wokka wokka!!!"));
  }
}
