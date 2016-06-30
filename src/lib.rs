extern crate openssl;
extern crate rustc_serialize;

pub mod bytes;
pub mod ecb_mode;
pub mod xor_cypher;

use std::{io, fs};
use std::io::Read;
use std::path::Path;
use rustc_serialize::base64::FromBase64;

pub fn read_base64(path: &Path) -> io::Result<Vec<u8>> {
  let mut contents = String::new();

  try!(fs::File::open(path)
       .and_then(|mut f| f.read_to_string(&mut contents)));

  Ok(contents.as_str().from_base64().unwrap())
}

pub fn read_contents(path: &Path) -> io::Result<String> {
  let mut contents = String::new();

  try!(fs::File::open(path)
       .map(io::BufReader::new)
       .and_then(|mut f| f.read_to_string(&mut contents)));

  Ok(contents)
}
