use super::Error;
use super::Result;

use crate::utils::{ITERATIONS, KEY_LEN, NONCE_LEN, SALT_LEN};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::pbkdf2;
use ring::rand::{SecureRandom, SystemRandom};
use std::num::NonZeroU32;
use zeroize::Zeroize;

pub fn encrypt(passphrase: &str, data: &[u8]) -> Result<Vec<u8>> {
    let rng = SystemRandom::new();

    // Generate a random salt
    let mut salt = [0u8; SALT_LEN];
    rng.fill(&mut salt).map_err(|_| Error::CryptoError {
        error: "Failed to generate random salt".to_string(),
    })?;

    // Derive the encryption key using PBKDF2
    let mut key = [0u8; KEY_LEN];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(ITERATIONS as u32).unwrap(),
        &salt,
        passphrase.as_bytes(),
        &mut key,
    );

    // Generate a random nonce
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng.fill(&mut nonce_bytes).map_err(|_| Error::CryptoError {
        error: "Failed to generate random nonce".to_string(),
    })?;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    // Initialize AES-GCM for encryption
    let key_unbound = UnboundKey::new(&AES_256_GCM, &key).map_err(|_| Error::CryptoError {
        error: "Failed to create unbound key".to_string(),
    })?;
    let sealing_key = LessSafeKey::new(key_unbound);

    // Encrypt the data
    let mut encrypted = data.to_vec();
    sealing_key
        .seal_in_place_append_tag(nonce, Aad::empty(), &mut encrypted)
        .map_err(|_| Error::CryptoError {
            error: "Failed to encrypt data".to_string(),
        })?;

    // Combine salt, nonce, and encrypted data
    let mut result = Vec::with_capacity(SALT_LEN + NONCE_LEN + encrypted.len());
    result.extend_from_slice(&salt);
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&encrypted);

    // Efface la clé
    key.zeroize();

    Ok(result)
}

pub fn decrypt(passphrase: &str, data: &[u8]) -> Result<Vec<u8>> {
    // Extract the salt, nonce, and encrypted data
    if data.len() < SALT_LEN + NONCE_LEN {
        return Err(Error::CryptoError {
            error: "Invalid encrypted data".to_string(),
        });
    }

    let (salt, rest) = data.split_at(SALT_LEN);
    let (nonce_bytes, encrypted_data) = rest.split_at(NONCE_LEN);

    // Derive the decryption key using PBKDF2
    let mut key = [0u8; KEY_LEN];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(ITERATIONS as u32).unwrap(),
        salt,
        passphrase.as_bytes(),
        &mut key,
    );

    // Initialize AES-GCM for decryption
    let nonce = Nonce::assume_unique_for_key(nonce_bytes.try_into().unwrap());
    let key_unbound = UnboundKey::new(&AES_256_GCM, &key).map_err(|_| Error::CryptoError {
        error: "Failed to create unbound key".to_string(),
    })?;
    let opening_key = LessSafeKey::new(key_unbound);

    // Decrypt the data
    let mut decrypted = encrypted_data.to_vec();
    let decrypt_len = opening_key
        .open_in_place(nonce, Aad::empty(), &mut decrypted)
        .map_err(|_| Error::CryptoError {
            error: "Failed to decrypt data".to_string(),
        })?
        .len();

    // Truncate the buffer to the valid length
    decrypted.truncate(decrypt_len);

    // Efface la clé
    key.zeroize();

    Ok(decrypted)
}


/******************************************************************************************************************************
*
*                                           Tests
*
 ******************************************************************************************************************************/
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let passphrase = "strong_password";
        let data = b"Hello, World!";

        let encrypted = encrypt(passphrase, data).expect("Encryption failed");
        let decrypted = decrypt(passphrase, &encrypted).expect("Decryption failed");

        assert_eq!(data.to_vec(), decrypted);
    }

    #[test]
    fn test_invalid_data_length() {
        let passphrase = "strong_password";
        let invalid_data = vec![0u8; SALT_LEN + NONCE_LEN - 1];

        let result = decrypt(passphrase, &invalid_data);
        assert!(result.is_err(), "Expected decryption to fail");
    }
}
