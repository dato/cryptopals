use bytes::Bytes;
use openssl::crypto::symm::*;
use std::path::Path;

/// Encrypt in CBC mode, using only ECB as primitive.
///
/// Should be padded lala.
pub fn encrypt_aes_128_cbc(data: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
  let mut ret = Vec::new();
  let mut iv = iv.to_vec();

  for s in data.chunks(key.len()) {
    let mut b = Bytes::new(s);
    let crypter = Crypter::new(Type::AES_128_ECB);
    b.xor_bytes(&iv);
    crypter.init(Mode::Encrypt, key, &[]);
    iv = crypter.update(&b.data());
    iv.extend(crypter.finalize());
    ret.extend(&iv);
  }
  ret
}

/// Decrypt CBC, using only ECB as primitive.
///
/// Should be padded lala.
pub fn decrypt_aes_128_cbc(data: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
  let mut ret = Vec::new();
  let mut iv = iv;

  for s in data.chunks(key.len()) {
    let crypter = Crypter::new(Type::AES_128_ECB);
    crypter.init(Mode::Decrypt, key, &[]);
    crypter.pad(false);
    let mut d = crypter.update(s);
    d.extend(crypter.finalize());
    let mut b = Bytes::new(&d);
    b.xor_bytes(iv);
    ret.extend(b.data());
    iv = s;
  }
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
  // Or:
  // ((len + block_len - 1) / block_len) * block_len
}

#[cfg(test)]
mod test {
  use super::decrypt_aes_128_cbc;
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

  #[test]
  fn cbc_decrypt() {
    let mut data = crate::read_base64("challenge-data/10.txt");
    pad_pkcs7(&mut data, 16);
    let text = decrypt_aes_128_cbc(
      &data,
      b"YELLOW SUBMARINE",
      &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    );
    println!("{}", String::from_utf8_lossy(&text));
  }
}
