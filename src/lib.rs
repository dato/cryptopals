#[macro_use]
extern crate lazy_static;

mod set1;

pub mod bytes;

use data_encoding::BASE64;
use std::path::Path;
use std::{fs, io};

lazy_static! {
  // The default BASE64 encoding is not permissive and
  // does not accept newline characters.
  static ref BASE64_NL: data_encoding::Encoding = {
    let mut spec = BASE64.specification();
    spec.ignore.push('\n');
    spec.encoding().unwrap()
  };
}

pub fn read_base64(path: &Path) -> io::Result<Vec<u8>> {
  let data = fs::read_to_string(path)?;
  Ok(BASE64_NL.decode(data.as_bytes()).unwrap())
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
    assert!(xor_bytes(&mut a, &b));
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
    assert_eq!(
      "Now that the party is jumping\n",
      find_xor_str("input/4.txt")
    );
  }

  #[test]
  fn challenge_6() {
    // Break repeating-key XOR
    // https://cryptopals.com/sets/1/challenges/6
    assert_eq!(
      break_cycling_xor("input/6.txt"),
      b"Terminator X: Bring the noise"
    );
  }
}
