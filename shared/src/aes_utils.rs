use aes::Aes256;
use cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::cipher::generic_array::GenericArray;
use rand_core::{RngCore, OsRng};

pub fn generate_aes_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

pub fn encrypt_aes(key: &[u8; 32], mut data: Vec<u8>) -> Vec<u8> {
    let cipher = Aes256::new(GenericArray::from_slice(key));
    // Pad data to 16 bytes
    let pad_len = 16 - (data.len() % 16);
    data.resize(data.len() + pad_len, pad_len as u8);
    
    for chunk in data.chunks_mut(16) {
        let block = GenericArray::from_mut_slice(chunk);
        cipher.encrypt_block(block);
    }
    data
}

pub fn decrypt_aes(key: &[u8; 32], mut data: Vec<u8>) -> Vec<u8> {
    let cipher = Aes256::new(GenericArray::from_slice(key));
    
    for chunk in data.chunks_mut(16) {
        let block = GenericArray::from_mut_slice(chunk);
        cipher.decrypt_block(block);
    }
    
    // Remove padding
    if let Some(&pad_len) = data.last() {
        let new_len = data.len().saturating_sub(pad_len as usize);
        data.truncate(new_len);
    }
    data
}
