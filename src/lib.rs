#[macro_use]
extern crate lazy_static;

pub mod bytes;
pub mod xor_cypher;

use data_encoding::BASE64;
use std::path::Path;
use std::{fs, io};

lazy_static! {
  // The default BASE64 encoding is not permissive and
  // does not accept newline characters.
  static ref BASE64_NL: data_encoding::Encoding = {
    let mut spec = BASE64.specification();
    spec.ignore.push('\n');
    spec.encoding().unwrap()
  };
}

pub fn read_base64(path: &Path) -> io::Result<Vec<u8>> {
  let data = fs::read_to_string(path)?;
  Ok(BASE64_NL.decode(data.as_bytes()).unwrap())
}
