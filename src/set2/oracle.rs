use openssl::symm::{Cipher, Crypter, Mode};
use rand::Rng;

use std::error::Error;

// This is in a separate module so that members remain private.
pub struct AesOracle {
  key: Vec<u8>,
  plaintext: Vec<u8>,
}

// Like AesOracle, but prepends some random bytes to the controlled part.
pub struct RndAesOracle {
  poison: Vec<u8>,
  oracle: AesOracle,
}

// To generalize both oracles into a single method.
pub trait Oracle {
  fn encrypt_with_controlled(&self, prefix: &[u8]) -> Result<Vec<u8>, Box<Error>>;
}

// For challenge 13: encrypts a username's metadata (email, uid, role).
pub struct EcbAuth {
  key: Vec<u8>,
}

// For challenge 16: encrypts userdata in a query string.
pub struct CbcAuth {
  iv: Vec<u8>,
  key: Vec<u8>,
  prefix: &'static str,
  suffix: &'static str,
}

/*
 * Implementations follow.
 *
 */

impl AesOracle {
  pub fn new(plaintext: &[u8]) -> AesOracle {
    let key = rand::random::<[u8; 16]>();
    AesOracle::new_with_key(plaintext, &key)
  }

  pub fn new_with_key(plaintext: &[u8], key: &[u8]) -> AesOracle {
    let key = key.to_vec();
    let plaintext = plaintext.to_vec();
    AesOracle { key, plaintext }
  }
}

impl RndAesOracle {
  pub fn new(plaintext: &[u8]) -> RndAesOracle {
    let mut rng = rand::thread_rng();
    RndAesOracle::new_with_poison_len(plaintext, rng.gen_range(3, 16))
  }

  // This constructor is for ease of testing oracle_poison_len() below.
  fn new_with_poison_len(plaintext: &[u8], len: usize) -> RndAesOracle {
    let mut rng = rand::thread_rng();
    let mut poison = vec![0; len];
    let oracle = AesOracle::new(plaintext);
    rng.fill(&mut poison[..]);
    RndAesOracle { poison, oracle }
  }
}

impl Oracle for AesOracle {
  fn encrypt_with_controlled(&self, prefix: &[u8]) -> Result<Vec<u8>, Box<Error>> {
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

impl Oracle for RndAesOracle {
  fn encrypt_with_controlled(&self, prefix: &[u8]) -> Result<Vec<u8>, Box<Error>> {
    let combined: Vec<_> = self.poison.iter().chain(prefix).cloned().collect();
    self.oracle.encrypt_with_controlled(&combined)
  }
}

impl EcbAuth {
  pub fn new() -> EcbAuth {
    let key = rand::random::<[u8; 16]>();
    EcbAuth { key: key.to_vec() }
  }

  /// Takes an address, returns the encrypted profile.
  pub fn profile_for(&self, email: &str) -> Vec<u8> {
    let email = email.replace('&', "").replace('=', "");
    let query = format!("email={}&uid=10&role=user", email);

    crate::set1::encrypt_aes_128_ecb(query.as_bytes(), &self.key).unwrap()
  }

  /// Takes an encrypted profile, searches for role=admin.
  pub fn is_role_admin(&self, ciphertext: &[u8]) -> bool {
    let bytes = crate::set1::decrypt_aes_128_ecb(ciphertext, &self.key).unwrap();
    let query = String::from_utf8_lossy(&bytes);

    for param in query.split('&') {
      if let Some(pos) = param.find('=') {
        let key = &param[..pos];
        let val = &param[pos + 1..];
        if key == "role" && val == "admin" {
          return true;
        }
      }
    }
    false
  }
}

impl CbcAuth {
  pub fn new() -> CbcAuth {
    let iv = rand::random::<[u8; 16]>().to_vec();
    let key = rand::random::<[u8; 16]>().to_vec();
    let prefix = "comment1=cooking%20MCs;userdata=";
    let suffix = ";comment2=%20like%20a%20pound%20of%20bacon";
    CbcAuth {
      iv,
      key,
      prefix,
      suffix,
    }
  }

  /// Takes userdata as a strings and encrypts it with the rest of the query.
  pub fn encrypt_userdata(&self, userdata: &str) -> Vec<u8> {
    let data = userdata.replace(';', "%3B").replace('=', "%3D");
    let query = format!("{}{}{}", self.prefix, data, self.suffix);
    super::encrypt_aes_128_cbc(query.as_bytes(), &self.key, &self.iv).unwrap()
  }

  /// Takes encrypted query and checks if ‘admin’ param is true.
  pub fn is_admin_true(&self, ciphertext: &[u8]) -> bool {
    let bytes = super::decrypt_aes_128_cbc(ciphertext, &self.key, &self.iv).unwrap();
    // We're not verifying that the plaintext is a valid query string. In a real
    // world scenario, we might—making the attack unfeasible?
    let query = String::from_utf8_lossy(&bytes);
    query.find(";admin=true;").is_some()
  }
}

mod test {
  use super::*;
  use crate::set2;

  #[test]
  #[ignore]
  fn oracle_poison_len() {
    let plaintext = vec![set2::PAD_BYTE; 256];
    for len in 0..=256 {
      let oracle = RndAesOracle::new_with_poison_len(&plaintext, len);
      assert_eq!(
        set2::oracle_poison_len(&oracle, 16).unwrap(),
        oracle.poison.len()
      );
    }
  }
}
