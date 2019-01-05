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

#[cfg(test)]
mod test {
  use super::decrypt_aes_128_cbc;

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
