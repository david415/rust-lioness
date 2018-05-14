// Copyright 2016 Jeffrey Burdges and David Stainton

//! Lioness wide block cipher

#[macro_use]
extern crate arrayref;
extern crate chacha;
extern crate blake2b;
extern crate keystream;

use self::keystream::KeyStream;
use self::chacha::ChaCha as ChaCha20;
use self::blake2b::blake2b_keyed;

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


/// encrypt a block
///
/// # Arguments
///
/// * `key` - a key
/// * `iv`  - an IV
/// * `dst` - a destination mutable byte slice
/// * `src` - a source reference to a byte slice of data to encrypt
///
/// # Errors
///
/// * `LionessError::BlockSizeError` - returned if block size is too small
///
pub fn encrypt(key: &[u8; RAW_KEY_SIZE], iv: &[u8; IV_SIZE], dst: &mut [u8], src: &[u8]) -> Result<(), LionessError> {
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

    // R = ChaCha20(L ^ k1, iv1, R)
    xor(&left, k1, &mut k);
    let mut sc = ChaCha20::new_ietf(&k, iv1);
    sc.xor_read(right.as_mut_slice()).unwrap();

    // L = L ^ BLAKE2b(k2 | iv2, R)
    let mut v = Vec::new();
    v.extend_from_slice(k2);
    v.extend_from_slice(iv2);
    let hash = blake2b_keyed(DIGEST_RESULT_SIZE, &v, &right);
    xor_assign(left.as_mut_slice(), &hash);

    // R = ChaCha20(L ^ k3, iv3, R)
    xor(&left, k3, &mut k);
    let mut sc = ChaCha20::new_ietf(&k, iv3);
    sc.xor_read(right.as_mut_slice()).unwrap();

    // L ^ BLAKE2b(k4 | iv4, R)
    let mut v = Vec::new();
    v.extend_from_slice(k4);
    v.extend_from_slice(iv4);
    let hash = blake2b_keyed(DIGEST_RESULT_SIZE, &v, &right);
    xor_assign(left.as_mut_slice(), &hash);

    dst[0..left.len()].clone_from_slice(&left);
    dst[left.len()..].clone_from_slice(&right);

    Ok(())
}

/// decrypt a block
///
/// # Arguments
///
/// * `key` - a key
/// * `iv`  - an IV
/// * `dst` - a destination mutable byte slice
/// * `src` - a source reference to a byte slice of data to decrypt
///
/// # Errors
///
/// * `LionessError::BlockSizeError` - returned if block size is too small
///
pub fn decrypt(key: &[u8; RAW_KEY_SIZE], iv: &[u8; IV_SIZE], dst: &mut [u8], src: &[u8]) -> Result<(), LionessError> {
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

    // L = L ^ BLAKE2b(k4 | iv4, R)
    let mut v = Vec::new();
    v.extend_from_slice(k4);
    v.extend_from_slice(iv4);
    let hash = blake2b_keyed(DIGEST_RESULT_SIZE, &v, &right);
    xor_assign(left.as_mut_slice(), &hash);

    // R = ChaCha20(L ^ k3, iv3, R)
    xor(&left, k3, &mut k);
    let mut sc = ChaCha20::new_ietf(&k, iv3);
    sc.xor_read(right.as_mut_slice()).unwrap();

    // L = L ^ BLAKE2b(k2 | iv2, R)
    let mut v = Vec::new();
    v.extend_from_slice(k2);
    v.extend_from_slice(iv2);
    let hash = blake2b_keyed(DIGEST_RESULT_SIZE, &v, &right);
    xor_assign(left.as_mut_slice(), &hash);

    // R = ChaCha20(L ^ k1, iv1, R)
    xor(&left, k1, &mut k);
    let mut sc = ChaCha20::new_ietf(&k, iv1);
    sc.xor_read(right.as_mut_slice()).unwrap();

    dst[..left.len()].clone_from_slice(&left);
    dst[left.len()..].clone_from_slice(&right);

    Ok(())
}

#[cfg(test)]
mod tests {
    extern crate rand;
    extern crate rustc_serialize;
    use super::*;
    use self::rand::Rng;
    use self::rand::os::OsRng;
    use self::rustc_serialize::hex::FromHex;

    struct Test {
        input: Vec<u8>,
        output: Vec<u8>,
        key: Vec<u8>,
        iv: Vec<u8>,
    }

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

    fn test_cipher(tests: &[Test]) {
        for t in tests {
            let mut dst = vec![0u8; t.input.len()];
            let mut key = [0u8; RAW_KEY_SIZE];
            key.copy_from_slice(t.key.as_slice());
            let mut iv = [0u8; IV_SIZE];
            iv.copy_from_slice(t.iv.as_slice());
            encrypt(&key, &iv, &mut dst, t.input.as_slice()).unwrap();
            let want: Vec<u8> = t.output.as_slice().to_owned();
            assert_eq!(want, dst)
        }
    }

    #[test]
    fn chach20_blake2b_lioness_vectors_test() {
        let test_vectors = vec![
            Test {
                key: "a5d7bd43320df4f560a3ff85b05f22dfc3d4e7405d53802305be474de7bf1c33d29da3ab7af680cc8ffb0a58111434004c807fea8af67ae01486f0a2be89463f365b910000c7cd87f80a0e8df7e61f083fbe9cd537f6fc33e7c97062351aa3599b767c6fa8a8fb60dac72573e169b34b2dc73a3edfb0cdad47657a83ea559140".from_hex().unwrap(),
                iv: "2ca1a11bff1713d7d6dbaadf1037d53d6a96092fbf74198371e77bf8c77b346b625cc938c449fdb3a11f1851703a1534".from_hex().unwrap(),
                input: "3e2e5cab574e9baeb9fb9a6c9c1d629b3876577d677cde37e957538ff76f6fae97f72aa40d4039ba32c9957fa1728cee12e0ad322f25021cd409c816d3a1861d804adb25966d6409f6b3a73ecf6b9f85dbe5411697e98b5d34eef2e9c957f54296988fa4374284dc17c85f27e50b73a333bd55f5220d89e9b513395ff8962d2871cdda248e5d8ff019be8c4ef794f9361fe7623385ff3f17088f8edab0b10b1e298d6da11b743b09dc6593821fa780cd0ac9b187dfc33fbf5f9f566efd23a1c7f602a0e2d16a9bb2973a184640cabbe2726ec13ea9eefdf563cff7cc3827ad6a0cf0040db7180909c5f940a85333880ad957b651d210c86568ce8dc12687ec87b60c4aec2e1a37cc12904f568e14d30e67de4aaf6b70678d3dd609434f2aae6d762c2f04e00a32fe06f1ec2860c7b7abc780137330157a381bc6655d4bf17ed1f4031e052105efe74bb6c1d5215b225dd7388841d9f72df9ce5ca64eba668ae4ac17d5b3c8a7d216cd58c242f4c8ffdb02961fa3880fb616fd7939af01c100457dffc010072c2bf00610257a31ffb9bbf569e1a6604691c5a727ff133fd4fbc0067a012a9bc34f6bd2b6544c126853ada937cdf4b426a603ec4a7c13e06b48752c4fce5d632ca0b4ece880a870976b009956bbfaf4f29b4b22e763c94200db5906d0ab67c221e219e06dd8bffe617112f5f5703a".from_hex().unwrap(),
                output: "484716632eda1a807a7cc84b4b7824ae968c687cdc2bbe982012a718d924db4b9b33e78374990e2a2cd7f8d46fbedad701960e6db1c7198ae261f3fc6ad23d845df73b2d0e8a8f5f6305a0ea0867d7d16b3a0fff662536090ff5580b3020351c7c004c3f5ca126a03fa46646c460fd50d52f7748c45882bd995a6bc066930df1ec23e247e5cc58a2cfe4224224a784f6e408ec47cffe4a09473526e679e6527ff6144fc7b0ea9559ad8ce474b71b73c3585fb53327dc698e87d9755b452bdb9f8c19791de68101edd492c9a8b10227aae8d39214bb222cae95cd352e06ab67e753d56b5f07c958aef105423e27a4eac8a7e956e90f731d255a5ac3fd41fcef167ffc2f080d42a9bb008a7f32a16b7a787b44bb683729ff8dc2244755d7b124f80c6b9dc9a98fb3ae238ad1a25960beb952aa27a73e85bc0c0ab421b2f4ae6e2829db6103e9f3a8399a1e27f0fcebdc30cd76560fce1b88447ac18a362a3ff3a3bf4b8361fcac8eede3eeeb30472c3cd4d29ebc8d194143d9554362da27387fde22248c7e2d91010a816a368bcc221f5adf17dc004eaedf997a08bbab85cca1cfa42e132dd411a6fe38efe132a0ef5b1ca9ce94d48b2a0b52b10a90101f8dd70e94a887cf2de58af36f759464fa7b771b7a8c803116d1091329824f03829d0a21c5b5a27f5a1d9cb48d3dace7eead9331fc89abaf".from_hex().unwrap(),
            },
            Test {
                key: "1338761c4cbeb912ba90c276b60a6be1f8d1faf88d982c2650c6e3e50a466d33f8adeaf0f7348e97994549695f4c5ebd60cd9bbfb6a1145afd95c0e521aff2572c534ed4d4956149cf349e9b19b9b4a2218aa85f0bc9ff5cef96152c664b9bead6439688565b4032db6132e8d01e3de3d75ac61415fd91fe65ad0b5aee79dd15".from_hex().unwrap(),
                iv: "86453b143014e6c2cae0ea111917570d56a030e9ddb3d66e540980b281a22e13ea3c3595bc9492fa5756b0a4ba8dda5f".from_hex().unwrap(),
                input: "5a66aec61d86899aa42e1785e3d71278cd62a8f0fa3d03023e56efcbeb6edc2b79".from_hex().unwrap(),
                output: "6e46fd5a8891e196b311ffedbca854cde93c15c9b7d0eda9a1660161faf0da78a0".from_hex().unwrap(),
            }
        ];

        test_cipher(&test_vectors[..]);
    }

} // tests
