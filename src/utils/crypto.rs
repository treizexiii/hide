use super::Result;

#[cfg(target_os = "linux")]
pub mod crypto {
    use super::Result;
    use crate::utils::{Error, ITERATIONS, IV_LEN, KEY_LEN, SALT_LEN};
    use openssl::hash::MessageDigest;
    use openssl::pkcs5::pbkdf2_hmac;
    use openssl::symm::{Cipher, Crypter, Mode};
    use rand::Rng;
    use zeroize::Zeroize;

    pub fn encrypt(passphrase: &str, data: &[u8]) -> Result<Vec<u8>> {
        let cipher = Cipher::aes_256_cbc();

        // Generate a random salt
        let mut salt = [0u8; SALT_LEN];
        rand::thread_rng().fill(&mut salt);

        // Derive the key and IV using PBKDF2
        let mut key = [0u8; KEY_LEN];
        let mut iv = [0u8; IV_LEN];
        pbkdf2_hmac(passphrase.as_bytes(), &salt, ITERATIONS, MessageDigest::sha256(), &mut key)
            .or(Err(Error::KeyFailHmac))?;

        pbkdf2_hmac(passphrase.as_bytes(), &salt, ITERATIONS, MessageDigest::sha256(), &mut iv)
            .or(Err(Error::KeyFailHmac))?;

        // Encrypt the data
        let mut crypt = Crypter::new(cipher, Mode::Encrypt, &key, Some(&iv))
            .or(Err(Error::EncryptFail))?;
        let mut encrypted = vec![0; data.len() + cipher.block_size()];
        let count = crypt.update(data, &mut encrypted)
            .or(Err(Error::EncryptFail))?;
        let rest = crypt.finalize(&mut encrypted[count..])
            .or(Err(Error::EncryptFail))?;
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

    pub fn decrypt(passphrase: &str, data: &[u8]) -> Result<Vec<u8>> {
        let cipher = Cipher::aes_256_cbc();

        // Extract the salt and encrypted data
        let (salt, encrypted_data) = data.split_at(SALT_LEN);

        // Derive the key and IV using PBKDF2
        let mut key = [0u8; KEY_LEN];
        let mut iv = [0u8; IV_LEN];
        pbkdf2_hmac(passphrase.as_bytes(), salt, ITERATIONS, MessageDigest::sha256(), &mut key)
            .or(Err(Error::KeyFailHmac))?;
        pbkdf2_hmac(passphrase.as_bytes(), salt, ITERATIONS, MessageDigest::sha256(), &mut iv)
            .or(Err(Error::KeyFailHmac))?;

        // Decrypt the data
        let mut crypt = Crypter::new(cipher, Mode::Decrypt, &key, Some(&iv))
            .or(Err(Error::DecryptFail))?;
        let mut decrypted = vec![0; encrypted_data.len() + cipher.block_size()];
        let count = crypt.update(encrypted_data, &mut decrypted)
            .or(Err(Error::DecryptFail))?;
        let rest = crypt.finalize(&mut decrypted[count..])
            .or(Err(Error::DecryptFail))?;
        decrypted.truncate(count + rest);

        // Efface les données sensibles
        key.zeroize();
        iv.zeroize();

        Ok(decrypted)
    }
}


#[cfg(target_os = "windows")]
pub mod crypto {
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
        rng.fill(&mut salt)?;

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
        rng.fill(&mut nonce_bytes)?;
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        // Initialize AES-GCM for encryption
        let key_unbound = UnboundKey::new(&AES_256_GCM, &key)?;
        let sealing_key = LessSafeKey::new(key_unbound);

        // Encrypt the data
        let mut encrypted = data.to_vec();
        sealing_key.seal_in_place_append_tag(nonce, Aad::empty(), &mut encrypted)?;

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
        let key_unbound = UnboundKey::new(&AES_256_GCM, &key)?;
        let opening_key = LessSafeKey::new(key_unbound);

        // Decrypt the data
        let mut decrypted = encrypted_data.to_vec();
        opening_key.open_in_place(nonce, Aad::empty(), &mut decrypted)?;

        // Efface la clé
        key.zeroize();

        Ok(decrypted)
    }
}
