#[macro_use]
extern crate lazy_static;
extern crate data_encoding;

pub mod bytes;
pub mod xor_cypher;

use data_encoding::BASE64;
use std::io::Read;
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
  let mut contents = String::new();

  try!(fs::File::open(path).and_then(|mut f| f.read_to_string(&mut contents)));

  Ok(BASE64_NL.decode(contents.as_bytes()).unwrap())
}

pub fn read_contents(path: &Path) -> io::Result<String> {
  let mut contents = String::new();

  try!(fs::File::open(path)
    .map(io::BufReader::new)
    .and_then(|mut f| f.read_to_string(&mut contents)));

  Ok(contents)
}
