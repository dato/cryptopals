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
