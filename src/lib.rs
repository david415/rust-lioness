// Copyright 2016 Jeffrey Burdges and David Stainton

//! Lioness wide block cipher

#[macro_use]
extern crate arrayref;
extern crate crypto;
extern crate rustc_serialize as serialize;


use crypto::digest::Digest;
use crypto::blake2b::Blake2b;
use crypto::symmetriccipher::SynchronousStreamCipher;
use crypto::chacha20::ChaCha20;
//use serialize::hex::ToHex;

pub mod error;
pub use error::LionessError;
pub mod util;
pub use util::{xor, xor_assign};

pub const DIGEST_RESULT_SIZE: usize = 32;
pub const DIGEST_KEY_SIZE: usize = 32;
pub const STREAM_CIPHER_KEY_SIZE: usize = 32;
pub const RAW_KEY_SIZE: usize = 2*STREAM_CIPHER_KEY_SIZE + 2*DIGEST_KEY_SIZE;
const CHACHA20_NONCE_SIZE: usize = 12;
pub const IV_SIZE: usize = CHACHA20_NONCE_SIZE * 4;


pub fn encrypt(key: &[u8; RAW_KEY_SIZE], iv: &[u8; IV_SIZE], dst: &mut [u8], src: &[u8]) -> Result<(), LionessError> {
    let mut hr = [0u8; DIGEST_RESULT_SIZE];
    let mut k = [0u8; STREAM_CIPHER_KEY_SIZE];
    let keylen = std::mem::size_of_val(&k);

    let blocklen = src.len();
    if blocklen <= keylen {
        return Err(LionessError::BlockSizeError)
    }

    let (k1,k2,k3,k4) = array_refs![key,STREAM_CIPHER_KEY_SIZE,DIGEST_KEY_SIZE,STREAM_CIPHER_KEY_SIZE,DIGEST_KEY_SIZE];
    let (iv1,iv2,iv3,iv4) = array_refs![iv,CHACHA20_NONCE_SIZE,CHACHA20_NONCE_SIZE,CHACHA20_NONCE_SIZE,CHACHA20_NONCE_SIZE];
    let blocky = src.split_at(keylen);
    let mut left = vec![0; blocky.0.len()];
    left.clone_from_slice(blocky.0);
    let mut right = vec![0; blocky.1.len()];
    right.clone_from_slice(blocky.1);
    let mut tmp_right = Vec::with_capacity(blocklen-keylen);
    for _ in 0..blocklen-keylen { tmp_right.push(0u8); }

    let mut v = Vec::new();
    v.extend_from_slice(k2);
    v.extend_from_slice(iv2);
    let mut h = Blake2b::new_keyed(DIGEST_RESULT_SIZE, &v);

    // R = ChaCha20(L ^ k1, iv1, R)
    xor(&left, k1, &mut k);
    let mut sc = ChaCha20::new(&k, iv1);
    sc.process(&right, &mut tmp_right);

    // XXX println!("encrypt ROUND 1: {}", right.to_hex());

    // L = L ^ BLAKE2b(k2 | iv2, R)
    h.input(&tmp_right);
    h.result(&mut hr);
    xor_assign(left.as_mut_slice(), &hr);

    // R = ChaCha20(L ^ k3, iv3, R)
    xor(&left, k3, &mut k);
    let mut sc = ChaCha20::new(&k, iv3);
    sc.process(&tmp_right, right.as_mut_slice());

    // L ^ BLAKE2b(k4 | iv4, R)
    let mut v = Vec::new();
    v.extend_from_slice(k4);
    v.extend_from_slice(iv4);
    let mut h = Blake2b::new_keyed(DIGEST_RESULT_SIZE, &v);
    h.input(&right);
    h.result(&mut hr);
    xor_assign(left.as_mut_slice(), &hr);

    dst[0..left.len()].clone_from_slice(&left);
    dst[left.len()..].clone_from_slice(&right);

    Ok(())
}

pub fn decrypt(key: &[u8; RAW_KEY_SIZE], iv: &[u8; IV_SIZE], dst: &mut [u8], src: &[u8]) -> Result<(), LionessError> {
    let mut hr = [0u8; DIGEST_RESULT_SIZE];
    let mut k = [0u8; STREAM_CIPHER_KEY_SIZE];
    let keylen = std::mem::size_of_val(&k);

    let blocklen = src.len();
    if blocklen <= keylen {
        return Err(LionessError::BlockSizeError)
    }

    let (k1,k2,k3,k4) = array_refs![key,STREAM_CIPHER_KEY_SIZE,DIGEST_KEY_SIZE,STREAM_CIPHER_KEY_SIZE,DIGEST_KEY_SIZE];
    let (iv1,iv2,iv3,iv4) = array_refs![iv,CHACHA20_NONCE_SIZE,CHACHA20_NONCE_SIZE,CHACHA20_NONCE_SIZE,CHACHA20_NONCE_SIZE];
    let blocky = src.split_at(keylen);
    let mut left = vec![0; blocky.0.len()];
    left.clone_from_slice(blocky.0);
    let mut right = vec![0; blocky.1.len()];
    right.clone_from_slice(blocky.1);
    let mut tmp_right = Vec::with_capacity(blocklen-keylen);
    for _ in 0..blocklen-keylen { tmp_right.push(0u8); }

    let mut v = Vec::new();
    v.extend_from_slice(k4);
    v.extend_from_slice(iv4);
    let mut h = Blake2b::new_keyed(DIGEST_RESULT_SIZE, &v);

    // L = L ^ BLAKE2b(k4 | iv4, R)
    h.input(&right);
    h.result(&mut hr);
    xor_assign(left.as_mut_slice(), &hr);

    // R = ChaCha20(L ^ k3, iv3, R)
    xor(&left, k3, &mut k);
    let mut sc = ChaCha20::new(&k, iv3);
    sc.process(&right, &mut tmp_right);

    // L = L ^ BLAKE2b(k2 | iv2, R)
    let mut v = Vec::new();
    v.extend_from_slice(k2);
    v.extend_from_slice(iv2);
    let mut h = Blake2b::new_keyed(DIGEST_RESULT_SIZE, &v);
    h.input(&tmp_right);
    h.result(&mut hr);
    xor_assign(left.as_mut_slice(), &hr);

    // R = ChaCha20(L ^ k1, iv1, R)
    xor(&left, k1, &mut k);
    let mut sc = ChaCha20::new(&k, iv1);
    sc.process(&tmp_right, right.as_mut_slice());

    dst[..left.len()].clone_from_slice(&left);
    dst[left.len()..].clone_from_slice(&right);

    Ok(())
}

#[cfg(test)]
mod tests {
    extern crate rand;
    extern crate rustc_serialize;
    use super::*;
    //use crypto::blake2b::Blake2b;
    //use crypto::chacha20::ChaCha20;
    use self::rand::Rng;
    use self::rand::os::OsRng;
    //use self::rustc_serialize::hex::FromHex;
    //use serialize::hex::ToHex;

    #[test]
    fn simple_encrypt_decrypt_test() {
        const TEST_PLAINTEXT: &'static [u8] = b"Hello there world, I'm just a test string";
        let mut rnd = OsRng::new().unwrap();
        let raw_key = rnd.gen_iter::<u8>().take(RAW_KEY_SIZE).collect::<Vec<u8>>();
        let raw_iv = rnd.gen_iter::<u8>().take(IV_SIZE).collect::<Vec<u8>>();
        let src: Vec<u8> = TEST_PLAINTEXT.to_owned();
        let mut dst1: Vec<u8> = vec![0u8; src.len()];
        let mut dst2: Vec<u8> = vec![0u8; src.len()];
        let mut key = [0u8; RAW_KEY_SIZE];
        key.copy_from_slice(raw_key.as_slice());
        let mut iv = [0u8; IV_SIZE];
        iv.copy_from_slice(raw_iv.as_slice());
        encrypt(&key, &iv, &mut dst1, &src).unwrap();
        decrypt(&key, &iv, &mut dst2, &dst1).unwrap();
        assert!(dst2 == src)
    }
}
