const BASE64_CHARS: &'static [u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

#[derive(Clone)]
pub struct Bytes(Vec<u8>);

impl Bytes {
  pub fn new(d: &[u8]) -> Bytes {
    Bytes(d.to_vec())
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

  pub fn xor(&self, other: &Bytes) -> Bytes {
    let a = &self.0;
    let b = &other.0;
    let mut ret = Vec::new();

    if a.len() != b.len() {
      panic!("distinct sized Bytes passed to xor()");
    }

    for (x, y) in a.iter().zip(b) {
      ret.push(x ^ y)
    }

    Bytes(ret)
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
  fn xor() {
    // https://cryptopals.com/sets/1/challenges/2
    assert_eq!(Bytes::from_hex("1c0111001f010100061a024b53535009181c")
               .xor(&Bytes::from_hex("686974207468652062756c6c277320657965"))
               .to_hex(), "746865206b696420646f6e277420706c6179");
  }
}
