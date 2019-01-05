pub struct Bytes(Vec<u8>);

impl Bytes {
  pub fn new(xs: &[u8]) -> Bytes {
    Bytes(xs.to_vec())
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

  #[test]
  fn hamming_distance() {
    assert_eq!(
      37,
      Bytes::hamming_distance(b"this is a test", b"wokka wokka!!!")
    );
  }
}
