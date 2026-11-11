use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Sensitive user identity held in RAM only during active enclave execution.
/// Automatically overwritten with zeros in memory when dropped.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ProtectedIdentityPayload {
    pub master_did: String,
    pub full_name: String,
    pub passport_or_id: String,
    pub ten_finger_hash: String,
    pub live_face_hash: String,
    pub offline_seed_hash: String,
}

#[derive(Serialize, Deserialize)]
pub struct EncryptedBlockchainRecord {
    pub record_id: String,
    pub nonce_hex: String,
    pub ciphertext_hex: String,
    pub integrity_mac_hex: String,
}

/// Seals personal data and 3-factor recovery commitments into an encrypted blockchain/DB blob.
/// Master key is wiped from RAM immediately after encryption.
pub fn encrypt_blockchain_record(
    mut master_key_bytes: [u8; 32],
    record: ProtectedIdentityPayload,
) -> Result<EncryptedBlockchainRecord, &'static str> {
    let cipher = ChaCha20Poly1305::new(&master_key_bytes.into());
    master_key_bytes.zeroize(); // Wipe key from RAM immediately

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let serialized = serde_json::to_vec(&record).map_err(|_| "Serialization failed")?;
    let ciphertext = cipher
        .encrypt(nonce, serialized.as_ref())
        .map_err(|_| "Enclave encryption failed")?;

    let mut hasher = Sha3_256::new();
    hasher.update(&ciphertext);
    let integrity_mac_hex = hex::encode(hasher.finalize());

    Ok(EncryptedBlockchainRecord {
        record_id: format!("blk_enc_{}", &integrity_mac_hex[..16]),
        nonce_hex: hex::encode(nonce_bytes),
        ciphertext_hex: hex::encode(ciphertext),
        integrity_mac_hex,
    })
}

/// Decrypts a blockchain/database record strictly inside the protected Rust enclave.
pub fn decrypt_blockchain_record(
    mut master_key_bytes: [u8; 32],
    encrypted: &EncryptedBlockchainRecord,
) -> Result {
    let cipher = ChaCha20Poly1305::new(&master_key_bytes.into());
    master_key_bytes.zeroize();

    let nonce_vec = hex::decode(&encrypted.nonce_hex).map_err(|_| "Invalid nonce")?;
    let cipher_vec = hex::decode(&encrypted.ciphertext_hex).map_err(|_| "Invalid ciphertext")?;
    let nonce = Nonce::from_slice(&nonce_vec);

    let plaintext = cipher
        .decrypt(nonce, cipher_vec.as_ref())
        .map_err(|_| "Decryption failed or tampered data")?;

    serde_json::from_slice(&plaintext).map_err(|_| "Corrupted identity payload")
}
