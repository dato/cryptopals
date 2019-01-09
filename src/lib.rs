mod set1;
mod set2;

use data_encoding::BASE64;
use lazy_static::lazy_static;

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
  use crate::set2::*;
  use data_encoding::HEXLOWER_PERMISSIVE as HEX;

  #[test]
  fn challenge_01() {
    // https://cryptopals.com/sets/1/challenges/1
    let hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    assert_eq!(
      "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
      hex_to_base64(hex).unwrap()
    );
  }

  #[test]
  fn challenge_02() {
    // https://cryptopals.com/sets/1/challenges/2
    let mut a = HEX.decode(b"1c0111001f010100061a024b53535009181c").unwrap();
    let b = HEX.decode(b"686974207468652062756c6c277320657965").unwrap();
    assert!(xor_zip(&mut a, &b));
    assert_eq!("746865206b696420646f6e277420706c6179", HEX.encode(&a));
  }

  #[test]
  fn challenge_03() {
    // Single-byte XOR cipher
    // https://cryptopals.com/sets/1/challenges/3
    let bytes = HEX
      .decode(b"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
      .unwrap();
    assert_eq!(
      "Cooking MC's like a pound of bacon",
      break_xor_byte(&bytes).result
    );
  }

  #[test]
  fn challenge_04() {
    // Detect single-character XOR
    // https://cryptopals.com/sets/1/challenges/4
    assert_eq!("Now that the party is jumping\n", find_xor_byte("input/04"));
  }

  #[test]
  fn challenge_05() {
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
  fn challenge_06() {
    // Break repeating-key XOR
    // https://cryptopals.com/sets/1/challenges/6
    assert_eq!(37, hamming_distance(b"this is a test", b"wokka wokka!!!"));
    assert_eq!(
      break_xor_cycle(&crate::read_base64("input/06")),
      b"Terminator X: Bring the noise"
    );
  }

  #[test]
  fn challenge_07() {
    // AES in ECB mode.
    // https://cryptopals.com/sets/1/challenges/7
    let res = decrypt_aes_128_ecb("input/07", b"YELLOW SUBMARINE").unwrap();
    assert_eq!(2876, res.len());
    assert_eq!(
      "Play that funky music ",
      String::from_utf8_lossy(&res).lines().last().unwrap()
    );
  }

  #[test]
  fn challenge_08() {
    // Detect AES in ECB mode.
    // https://cryptopals.com/sets/1/challenges/8
    assert_eq!(
      "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a",
      find_aes_ecb("input/08").unwrap());
  }

  #[test]
  fn challenge_09() {
    // Implement PKCS#7 padding.
    // https://cryptopals.com/sets/2/challenges/9
    let mut a = b"01".to_vec();
    let mut b = b"ABC".to_vec();
    let mut c = b"YELLOW".to_vec();
    pkcs7_pad(&mut a, 2);
    pkcs7_pad(&mut b, 6);
    pkcs7_pad(&mut c, 10);
    assert_eq!(a, b"01\x02\x02");
    assert_eq!(b, b"ABC\x03\x03\x03");
    assert_eq!(c, b"YELLOW\x04\x04\x04\x04");
  }

  #[test]
  fn challenge_10() {
    // Implement CBC mode.
    // https://cryptopals.com/sets/2/challenges/10
    let data = crate::read_base64("input/10");
    let key = b"YELLOW SUBMARINE";
    let iv = vec![0; 16];
    let res = decrypt_aes_128_cbc(&data, key, &iv).unwrap();
    assert_eq!(
      "Play that funky music ",
      String::from_utf8_lossy(&res).lines().last().unwrap()
    );
    assert_eq!(2876, res.len());
  }

  #[test]
  fn challenge_11() {
    // An ECB/CBC detection oracle.
    // https://cryptopals.com/sets/2/challenges/11
    for _ in 0..10 {
      let result = discern_ecb_cbc(None);
      if result.guessed != result.actual {
        assert!(false, "discern_ecb_cbc() failed");
      }
    }
    let data = crate::read_base64("input/10");
    let key = b"YELLOW SUBMARINE";
    let iv = vec![0; 16];
    let res = decrypt_aes_128_cbc(&data, key, &iv).unwrap();
    assert_eq!(
      "Play that funky music ",
      String::from_utf8_lossy(&res).lines().last().unwrap()
    );
    assert_eq!(2876, res.len());
  }
}
