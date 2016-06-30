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

#[cfg(test)]
mod test {
  #[test]
  fn challenge_7() {
    let res = super::challenge_7("challenge-data/7.txt", b"YELLOW SUBMARINE");
    assert_eq!(2876, res.len());
    assert_eq!("Play that funky music ",
               String::from_utf8_lossy(&res).lines().last().unwrap());
  }
}
