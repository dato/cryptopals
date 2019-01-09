use openssl::symm::{Cipher, Crypter, Mode};
use std::error::Error;

// This is in a separate module so that members remain private.
pub struct AesOracle {
  key: Vec<u8>,
  plaintext: Vec<u8>,
}

impl AesOracle {
  pub fn new(plaintext: &[u8]) -> AesOracle {
    let key = rand::random::<[u8; 16]>();
    AesOracle::new_with_key(plaintext, &key)
  }

  pub fn new_with_key(plaintext: &[u8], key: &[u8]) -> AesOracle {
    let key = key.to_owned();
    let plaintext = plaintext.to_owned();
    AesOracle { key, plaintext }
  }

  pub fn encrypt_with_prefix(&self, prefix: &[u8]) -> Result<Vec<u8>, Box<Error>> {
    let cipher = Cipher::aes_128_ecb();
    let mut crypt = Crypter::new(cipher, Mode::Encrypt, &self.key, None)?;

    let datalen = prefix.len() + self.plaintext.len();
    let mut n = 0;
    let mut buf = vec![0; datalen + cipher.block_size()];

    n += crypt.update(&prefix, &mut buf)?;
    n += crypt.update(&self.plaintext, &mut buf[n..])?;
    n += crypt.finalize(&mut buf[n..])?;

    assert!(n <= buf.len());
    assert!(n - datalen <= 16);

    buf.truncate(n);
    Ok(buf)
  }
}
