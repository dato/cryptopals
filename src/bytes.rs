pub struct Bytes(Vec<u8>);

impl Bytes {
  pub fn new(xs: &[u8]) -> Bytes {
    Bytes(xs.to_vec())
  }

  /// Applies cyclic XOR.
  pub fn xor_cycle(&mut self, bytes: &[u8]) {
    for (dst, &byte) in self.0.iter_mut().zip(bytes.into_iter().cycle()) {
      *dst ^= byte;
    }
  }

  /// Computes the Hamming distance
  pub fn hamming_distance(a: &[u8], b: &[u8]) -> u32 {
    let mut distance = 0;
    for (x, y) in a.into_iter().zip(b) {
      distance += (x ^ y).count_ones();
    }
    distance
  }

  pub fn data(&self) -> &[u8] {
    &self.0
  }
}

#[cfg(test)]
mod test {
  use super::Bytes;
  use data_encoding::HEXLOWER_PERMISSIVE as HEX;

  #[test]
  fn xor_bytes() {
    // https://cryptopals.com/sets/1/challenges/5
    let mut b = Bytes::new(
      concat!(
        "Burning 'em, if you ain't quick and nimble\n",
        "I go crazy when I hear a cymbal"
      )
      .as_bytes(),
    );
    b.xor_cycle(b"ICE");
    assert_eq!(
      concat!(
        "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272",
        "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
      ),
      HEX.encode(b.data())
    );
  }

  #[test]
  fn hamming_distance() {
    assert_eq!(
      37,
      Bytes::hamming_distance(b"this is a test", b"wokka wokka!!!")
    );
  }
}
