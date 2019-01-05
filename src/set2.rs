pub fn pkcs7_pad(data: &mut Vec<u8>, block_len: usize) {
  let len = data.len();
  let num_bytes = pkcs7_size(len, block_len) - len;
  for _ in 0..num_bytes {
    data.push(0x4);
  }
}

fn pkcs7_size(len: usize, block_len: usize) -> usize {
  if len % block_len == 0 {
    len
  } else {
    block_len * (1 + len / block_len)
  }
  // Or:
  // ((len + block_len - 1) / block_len) * block_len
}
