use masterkey_rust_enclave::{
    decrypt_blockchain_record, encrypt_blockchain_record, ProtectedIdentityPayload,
};
use sha3::{Digest, Sha3_256};

fn hash_factor(input: &str) -> String {
    let mut h = Sha3_256::new();
    h.update(input.trim().to_lowercase().as_bytes());
    hex::encode(h.finalize())
}

fn main() {
    let enclave_master_key = [0x42u8; 32]; // In production, loaded from hardware HSM / KMS

    let payload = ProtectedIdentityPayload {
        master_did: "did:web5:masterkey:user-994821".into(),
        full_name: "Aarav Perera".into(),
        passport_or_id: "N8492014".into(),
        ten_finger_hash: hash_factor("10-FINGERS-VERIFIED"),
        live_face_hash: hash_factor("3D-LIVE-FACE-VERIFIED"),
        offline_seed_hash: hash_factor("ocean timber crystal shield quantum horizon liberty anchor pulse vertex orbit falcon"),
    };

    let sealed = encrypt_blockchain_record(enclave_master_key, payload).expect("Encryption failed");
    println!("Encrypted Blockchain/DB Record (Safe for Ledger Storage):\n{}", serde_json::to_string_pretty(&sealed).unwrap());

    let unsealed = decrypt_blockchain_record([0x42u8; 32], &sealed).expect("Decryption failed");
    println!("\nDecrypted Inside Protected Rust Enclave Only -> Owner: {}", unsealed.full_name);
}
