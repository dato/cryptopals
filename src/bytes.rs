use std::collections::HashMap;

const BASE64_CHARS: &'static [u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

#[derive(Clone)]
pub struct Bytes(Vec<u8>);

impl Bytes {
  pub fn new(xs: &[u8]) -> Bytes {
    Bytes(xs.to_vec())
  }

  pub fn from_hex(s: &str) -> Bytes {
    let mut ret = Vec::new();
    let len = s.len();
    let odd = len % 2;

    for i in 0 .. (len+1)/2 {
      let (beg, end) = match i {
        0 => (0, 2 - odd),
        _ => (i*2 - odd, i*2 - odd + 2),
      };
      ret.push(u8::from_str_radix(&s[beg..end], 16).unwrap());
    }
    Bytes(ret)
  }

  pub fn to_hex(&self) -> String {
    let v = &self.0;
    let mut ret = String::with_capacity(v.len() * 2);

    let chr = |i: u8| match i {
      0...9 => '0' as u8 + i,
      10...15 => 'a' as u8 + i - 10,
      _ => panic!("out of range!"),
    } as char;

    for i in v {
      ret.push(chr(i >> 4));
      ret.push(chr(i & 0xF));
    }
    ret
  }

  // Accepts only correctly padded input (with '=').
  pub fn from_base64(s: &str) -> Bytes {
    let indexes: HashMap<char, u8> = BASE64_CHARS
      .into_iter()
      .enumerate()
      .map(|(i, &c)| (c as char, i as u8))
      .collect();

    let mut next: u8 = 0;
    let mut ret = Vec::new();

    // XXX: we're silently ignoring *all* invalid character; should only let
    // '\n' and trailing '=' pass.
    for (i, val) in s.chars().filter_map(|c| indexes.get(&c)).enumerate() {
      next = match i % 4 {
        0 => val << 2,
        1 => { ret.push(next | val >> 4);
               val << 4 },
        2 => { ret.push(next | val >> 2);
               val << 6 },
        _ => { ret.push(next | val); 0 },
      };
    }

    Bytes(ret)
  }

  pub fn to_base64(&self) -> String {
    let v = &self.0;
    let mut ret = String::new();
    let chr = |i| BASE64_CHARS[i as usize] as char;
    let pad = '=';

    for c in v.chunks(3) {
      let a = chr(c[0] >> 2);

      let (b, c, d) = match c.len() {
        1 => (chr((c[0] & 0x3) << 4), pad, pad),

        2 => (chr((c[0] & 0x3) << 4 | c[1] >> 4),
              chr((c[1] & 0xF) << 2), pad),

        _ => (chr((c[0] & 0x3) << 4 | c[1] >> 4),
              chr((c[1] & 0xF) << 2 | c[2] >> 6), chr(c[2] & 0x3F)),
      };

      ret.push(a);
      ret.push(b);
      ret.push(c);
      ret.push(d);
    }
    ret
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
      panic!("wrong size for slice received in xor_bytes()");
    }
    self.xor_cycle(bytes);
  }

  /// Computes the Hamming distance
  pub fn hamming_distance(a: &str, b: &str) -> u32 {
    let a = a.as_bytes();
    let b = b.as_bytes();
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
    assert_eq!(vec![14, 10], Bytes::from_hex("E0A").0);
    assert_eq!(vec![254, 10], Bytes::from_hex("FE0A").0);
  }

  #[test]
  fn enc_base64() {
    assert_eq!("YQ==", Bytes::new(b"a").to_base64());
    assert_eq!("emE=", Bytes::new(b"za").to_base64());
    assert_eq!("b3ph", Bytes::new(b"oza").to_base64());
    assert_eq!("bm96YQ==", Bytes::new(b"noza").to_base64());
    assert_eq!("aW5vemE=", Bytes::new(b"inoza").to_base64());
    assert_eq!("cGlub3ph", Bytes::new(b"pinoza").to_base64());
    assert_eq!("U3Bpbm96YQ==", Bytes::new(b"Spinoza").to_base64());

    // https://cryptopals.com/sets/1/challenges/1
    assert_eq!("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
               Bytes::from_hex("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d").to_base64());
  }

  #[test]
  fn dec_base64() {
    assert_eq!(Bytes::from_base64("YQ==").data(), b"a");
    assert_eq!(Bytes::from_base64("emE=").data(), b"za");
    assert_eq!(Bytes::from_base64("b3ph").data(), b"oza");
    assert_eq!(Bytes::from_base64("bm96YQ=").data(), b"noza");
    assert_eq!(Bytes::from_base64("aW5vemE").data(), b"inoza");
    assert_eq!(Bytes::from_base64("cGlub3ph").data(), b"pinoza");
    assert_eq!(Bytes::from_base64("U3Bpbm96YQ").data(), b"Spinoza");

    assert_eq!(Bytes::from_base64("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t").data(),
               Bytes::from_hex("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d").data());
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
    assert_eq!(37, Bytes::hamming_distance("this is a test",
                                           "wokka wokka!!!"));
  }
}
