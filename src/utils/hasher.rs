use openssl::symm::{Cipher, Crypter, Mode};
use openssl::pkcs5::pbkdf2_hmac;
use openssl::hash::MessageDigest;
use rand::Rng;
use std::error::Error;
use zeroize::Zeroize;

const SALT_LEN: usize = 16;
const KEY_LEN: usize = 32;
const IV_LEN: usize = 16;
const ITERATIONS: usize = 100_000;

pub fn encrypt(passphrase: &str, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let cipher = Cipher::aes_256_cbc();

    // Generate a random salt
    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill(&mut salt);

    // Derive the key and IV using PBKDF2
    let mut key = [0u8; KEY_LEN];
    let mut iv = [0u8; IV_LEN];
    pbkdf2_hmac(passphrase.as_bytes(), &salt, ITERATIONS, MessageDigest::sha256(), &mut key)?;
    pbkdf2_hmac(passphrase.as_bytes(), &salt, ITERATIONS, MessageDigest::sha256(), &mut iv)?;

    // Encrypt the data
    let mut crypter = Crypter::new(cipher, Mode::Encrypt, &key, Some(&iv))?;
    let mut encrypted = vec![0; data.len() + cipher.block_size()];
    let count = crypter.update(data, &mut encrypted)?;
    let rest = crypter.finalize(&mut encrypted[count..])?;
    encrypted.truncate(count + rest);

    // Combine the salt and encrypted data
    let mut result = Vec::with_capacity(SALT_LEN + encrypted.len());
    result.extend_from_slice(&salt);
    result.extend_from_slice(&encrypted);

    // Efface les données sensibles
    key.zeroize();
    iv.zeroize();

    Ok(result)
}

pub fn decrypt(passphrase: &str, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let cipher = Cipher::aes_256_cbc();

    // Extract the salt and encrypted data
    let (salt, encrypted_data) = data.split_at(SALT_LEN);

    // Derive the key and IV using PBKDF2
    let mut key = [0u8; KEY_LEN];
    let mut iv = [0u8; IV_LEN];
    pbkdf2_hmac(passphrase.as_bytes(), salt, ITERATIONS, MessageDigest::sha256(), &mut key)?;
    pbkdf2_hmac(passphrase.as_bytes(), salt, ITERATIONS, MessageDigest::sha256(), &mut iv)?;

    // Decrypt the data
    let mut crypter = Crypter::new(cipher, Mode::Decrypt, &key, Some(&iv))?;
    let mut decrypted = vec![0; encrypted_data.len() + cipher.block_size()];
    let count = crypter.update(encrypted_data, &mut decrypted)?;
    let rest = crypter.finalize(&mut decrypted[count..])?;
    decrypted.truncate(count + rest);

    // Efface les données sensibles
    key.zeroize();
    iv.zeroize();

    Ok(decrypted)
}
