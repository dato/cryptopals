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
