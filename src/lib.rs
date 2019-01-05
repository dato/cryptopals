#[macro_use]
extern crate lazy_static;

mod set1;

use data_encoding::BASE64;
use std::fs;

lazy_static! {
  // The default BASE64 encoding is not permissive and
  // does not accept newline characters.
  static ref BASE64_NL: data_encoding::Encoding = {
    let mut spec = BASE64.specification();
    spec.ignore.push('\n');
    spec.encoding().unwrap()
  };
}

pub fn read_base64(filename: &str) -> Vec<u8> {
  let data = fs::read_to_string(filename).unwrap();
  BASE64_NL.decode(data.as_bytes()).unwrap()
}

#[cfg(test)]
mod test {
  use crate::set1::*;
  use data_encoding::HEXLOWER_PERMISSIVE as HEX;

  #[test]
  fn challenge_1() {
    // https://cryptopals.com/sets/1/challenges/1
    let hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    assert_eq!(
      "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
      hex_to_base64(hex).unwrap()
    );
  }

  #[test]
  fn challenge_2() {
    // https://cryptopals.com/sets/1/challenges/2
    let mut a = HEX.decode(b"1c0111001f010100061a024b53535009181c").unwrap();
    let b = HEX.decode(b"686974207468652062756c6c277320657965").unwrap();
    assert!(xor_zip(&mut a, &b));
    assert_eq!("746865206b696420646f6e277420706c6179", HEX.encode(&a));
  }

  #[test]
  fn challenge_3() {
    // Single-byte XOR cipher
    // https://cryptopals.com/sets/1/challenges/3
    let bytes = HEX
      .decode(b"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
      .unwrap();
    assert_eq!(
      "Cooking MC's like a pound of bacon",
      unscramble_byte_xor(&bytes).result
    );
  }

  #[test]
  fn challenge_4() {
    // Detect single-character XOR
    // https://cryptopals.com/sets/1/challenges/4
    assert_eq!("Now that the party is jumping\n", find_xor_str("input/04"));
  }

  #[test]
  fn challenge_5() {
    // Implement repeating-key XOR
    // https://cryptopals.com/sets/1/challenges/5
    let mut bytes =
      b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal".to_owned();
    xor_cycle(&mut bytes, b"ICE");
    assert_eq!(
      concat!(
        "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272",
        "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
      ),
      HEX.encode(&bytes)
    );
  }

  #[test]
  fn challenge_6() {
    // Break repeating-key XOR
    // https://cryptopals.com/sets/1/challenges/6
    assert_eq!(37, hamming_distance(b"this is a test", b"wokka wokka!!!"));
    assert_eq!(
      break_cycling_xor("input/06"),
      b"Terminator X: Bring the noise"
    );
  }
}
