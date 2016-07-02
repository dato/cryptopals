use std::path::Path;
use openssl::crypto::symm::*;

pub fn challenge_7(filename: &str, key: &[u8]) -> Vec<u8> {
  let data = ::read_base64(Path::new(filename)).unwrap();
  let crypter = Crypter::new(Type::AES_128_ECB);
  crypter.init(Mode::Decrypt, key, &[]);
  let mut ret = crypter.update(&data);
  ret.extend(crypter.finalize());
  ret
}

pub fn pad_pkcs7(data: &mut Vec<u8>, block_len: usize) {
  let len = data.len();
  let num_bytes = pkcs7_size(len, block_len) - len;
  for _ in 0..num_bytes {
    data.push(0x4);
  }
}

fn pkcs7_size(len: usize, block_len: usize) -> usize {
  if len % block_len == 0 {
    len
  } else {
    block_len * (1 + len / block_len)
  }
}

#[cfg(test)]
mod test {
  #[test]
  fn challenge_7() {
    let res = super::challenge_7("challenge-data/7.txt", b"YELLOW SUBMARINE");
    assert_eq!(2876, res.len());
    assert_eq!("Play that funky music ",
               String::from_utf8_lossy(&res).lines().last().unwrap());
  }

  use super::pad_pkcs7;
  use super::pkcs7_size;

  #[test]
  fn pkcs7_padding() {
    let mut v = String::from("YELLOW SUBMARINE").into_bytes();
    pad_pkcs7(&mut v, 20);
    assert_eq!(v, b"YELLOW SUBMARINE\x04\x04\x04\x04");
    pad_pkcs7(&mut v, 15);
    assert_eq!(30, v.len());
  }

  #[test]
  fn pkcs7_padding_size() {
    assert_eq!(20, pkcs7_size(16, 20));
    assert_eq!(30, pkcs7_size(16, 15));
    assert_eq!(80, pkcs7_size(80, 40));
  }
}
