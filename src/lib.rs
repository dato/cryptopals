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
  use super::BASE64_NL;
  use crate::set2::*;
  use indoc::indoc;

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
      String::from_utf8_lossy(&res).lines().last().unwrap(),
      "Play that funky music "
    );
    assert_eq!(res.len(), 2876);
    let newdata = encrypt_aes_128_cbc(&res, key, &iv).unwrap();
    assert_eq!(newdata, data);
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
  }

  #[test]
  fn challenge_12() {
    // Byte-at-a-time ECB decryption (Simple)
    // https://cryptopals.com/sets/2/challenges/12
    let plaintext = BASE64_NL
      .decode(indoc!(
        b"
              Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
              aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
              dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
              YnkK"
      ))
      .unwrap();
    let oracle = AesOracle::new(&plaintext);
    assert_eq!(break_ecb_simple(&oracle), plaintext);
  }

  #[test]
  fn challenge_13() {
    let auth = EcbAuth::new();
    let jane = auth.profile_for("jane@hackers.com");
    assert!(!auth.is_role_admin(&jane));
    assert!(auth.is_role_admin(&break_ecb_auth(&auth)));
  }

  #[test]
  fn challenge_14() {
    // Byte-at-a-time ECB decryption (Harder).
    // https://cryptopals.com/sets/2/challenges/14
    let plaintext = BASE64_NL
      .decode(indoc!(
        b"
              Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
              aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
              dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
              YnkK"
      ))
      .unwrap();
    let oracle = RndAesOracle::new(&plaintext);
    assert_eq!(break_ecb_hard(&oracle), plaintext);
  }

  #[test]
  fn challenge_15() {
    // PKCS#7 padding validation.
    // https://cryptopals.com/sets/2/challenges/15
    assert_eq!(pkcs7_padding_len(b"ICE ICE BABY\x04\x04\x04\x04"), Some(4));
    assert_eq!(pkcs7_padding_len(b"ICE ICE BABY\x05\x05\x05\x05"), None);
    assert_eq!(pkcs7_padding_len(b"ICE ICE BABY\x01\x02\x03\x04"), None);
    assert_eq!(pkcs7_padding_len(b"ICE ICE BABY\x00"), None);
    assert_eq!(pkcs7_padding_len(b""), Some(0));
  }

  #[test]
  fn challenge_16() {
    // Challenge 16: CBC bitflipping attacks.
    // https://cryptopals.com/sets/2/challenges/16
    let cbc = CbcAuth::new();
    let query = cbc.encrypt_userdata("hah;admin=true;bye=");
    assert!(!cbc.is_admin_true(&query));
    assert!(cbc.is_admin_true(&break_cbc_auth(&cbc)));
  }
}
