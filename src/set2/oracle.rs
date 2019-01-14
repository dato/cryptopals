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
pub struct EcbProfiles {
  key: Vec<u8>,
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
    let key = key.to_owned();
    let plaintext = plaintext.to_owned();
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

impl EcbProfiles {
  pub fn new() -> EcbProfiles {
    let key = rand::random::<[u8; 16]>();
    EcbProfiles { key: key.to_vec() }
  }

  /// Takes an address, returns the encrypted profile.
  pub fn profile_for(&self, email: &str) -> Vec<u8> {
    let mut email = String::from(email);
    email.replace("&", "");
    email.replace("=", "");

    let query = format!("email={}&uid=10&role=user", email);

    let data = query.as_bytes();
    let cipher = Cipher::aes_128_ecb();
    let mut crypt = Crypter::new(cipher, Mode::Encrypt, &self.key, None).unwrap();
    let mut ret = vec![0; data.len() + cipher.block_size()];
    let mut tot = 0;
    tot += crypt.update(data, &mut ret).unwrap();
    tot += crypt.finalize(&mut ret[tot..]).unwrap();
    ret.truncate(tot);
    ret
  }

  /// Takes an encrypted profile, searches for role=admin.
  pub fn is_role_admin(&self, ciphertext: &[u8]) -> bool {
    let bytes = crate::set1::decrypt_aes_128_ecb(ciphertext, &self.key).unwrap();
    let query = String::from_utf8_lossy(&bytes).to_owned();

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

mod test {
  use super::*;
  use crate::set2;

  #[test]
  #[ignore]
  fn oracle_poison_len() {
    let plaintext = vec![0; 256]; // Ideally same pad byte as in oracle_poison_len() impl.
    for len in 0..=256 {
      let oracle = RndAesOracle::new_with_poison_len(&plaintext, len);
      assert_eq!(
        set2::oracle_poison_len(&oracle, 16).unwrap(),
        oracle.poison.len()
      );
    }
  }
}
