use rsa::{RsaPrivateKey, RsaPublicKey, Pkcs1v15Encrypt};
use rsa::pkcs8::{EncodePublicKey, DecodePublicKey, EncodePrivateKey, DecodePrivateKey};
use rand_core::OsRng;

pub fn generate_rsa_keys() -> (RsaPrivateKey, RsaPublicKey) {
    let mut rng = OsRng;
    let bits = 2048;
    let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let pub_key = RsaPublicKey::from(&priv_key);
    (priv_key, pub_key)
}

pub fn pub_key_to_pem(pub_key: &RsaPublicKey) -> String {
    pub_key.to_public_key_pem(rsa::pkcs8::LineEnding::LF).unwrap()
}

pub fn pem_to_pub_key(pem: &str) -> RsaPublicKey {
    RsaPublicKey::from_public_key_pem(pem).expect("Invalid PEM")
}

pub fn encrypt_rsa(pub_key: &RsaPublicKey, data: &[u8]) -> Vec<u8> {
    let mut rng = OsRng;
    pub_key.encrypt(&mut rng, Pkcs1v15Encrypt, data).expect("Failed to encrypt using RSA")
}

pub fn decrypt_rsa(priv_key: &RsaPrivateKey, data: &[u8]) -> Vec<u8> {
    priv_key.decrypt(Pkcs1v15Encrypt, data).expect("Failed to decrypt using RSA")
}
