import { ml_kem768 } from '@noble/post-quantum/ml-kem';
import { sha3_256 } from '@noble/hashes/sha3';
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export interface SovereignIdentityRecord {
  masterDid: string;
  fullName: string;
  dateOfBirth: string;
  passportNumber: string;
  nationality: string;
  biometricLivenessHash: string;
  kycTier: 'TIER_1' | 'TIER_2' | 'TIER_3_AML_FULL';
  sanctionsClearance: 'PASSED' | 'FAILED';
}

export interface EncryptedDwnEnvelope {
  version: 'PQ-DWN-MLKEM768-v1';
  masterDid: string;
  kemCipherTextHex: string;
  ivHex: string;
  authTagHex: string;
  encryptedPayloadHex: string;
  updatedAt: string;
}

/**
 * Generates a Post-Quantum ML-KEM-768 keypair bound to the user's device enclave.
 */
export function generateVaultKeypair() {
  return ml_kem768.keygen(randomBytes(64));
}

/**
 * Encrypts sensitive personal identity records using NIST ML-KEM-768 + AES-256-GCM.
 * Neither the platform servers nor third-party apps can read this envelope.
 */
export function sealIdentityInVault(
  vaultPublicKey: Uint8Array,
  record: SovereignIdentityRecord
): EncryptedDwnEnvelope {
  // 1. Post-Quantum Key Encapsulation (produces shared secret + quantum-safe ciphertext)
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(vaultPublicKey);

  // 2. Derive 256-bit symmetric key from ML-KEM shared secret
  const aesKey = sha3_256(sharedSecret);
  const iv = randomBytes(12);

  // 3. Encrypt identity record with AES-256-GCM
  const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
  const plaintext = Buffer.from(JSON.stringify(record), 'utf8');
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return {
    version: 'PQ-DWN-MLKEM768-v1',
    masterDid: record.masterDid,
    kemCipherTextHex: bytesToHex(cipherText),
    ivHex: bytesToHex(iv),
    authTagHex: bytesToHex(authTag),
    encryptedPayloadHex: encrypted.toString('hex'),
    updatedAt: new Date().toISOString()
  };
}

/**
 * Unlocks the local Web5 DWN Vault using the user's private ML-KEM-768 secret key.
 */
export function unsealIdentityFromVault(
  vaultSecretKey: Uint8Array,
  envelope: EncryptedDwnEnvelope
): SovereignIdentityRecord {
  // 1. Decapsulate the Post-Quantum shared secret
  const cipherText = hexToBytes(envelope.kemCipherTextHex);
  const sharedSecret = ml_kem768.decapsulate(cipherText, vaultSecretKey);

  // 2. Re-derive AES-256 key and decrypt
  const aesKey = sha3_256(sharedSecret);
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    aesKey,
    hexToBytes(envelope.ivHex)
  );
  decipher.setAuthTag(hexToBytes(envelope.authTagHex));

  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(envelope.encryptedPayloadHex, 'hex')),
    decipher.final()
  ]);

  return JSON.parse(decrypted.toString('utf8')) as SovereignIdentityRecord;
}

/**
 * Persists the encrypted DWN envelope to local decentralized node storage.
 */
export function saveDwnNode(storageDir: string, envelope: EncryptedDwnEnvelope): string {
  fs.mkdirSync(storageDir, { recursive: true });
  const filePath = path.join(storageDir, `${envelope.masterDid.replace(/[:/]/g, '_')}.dwn.json`);
  fs.writeFileSync(filePath, JSON.stringify(envelope, null, 2));
  return filePath;
}

export interface ThreeFactorRecoveryCommitment {
  tenFingerCommitmentHash: string;
  liveFaceCommitmentHash: string;
  offlineSeedCommitmentHash: string;
  enrolledFingersCount: number;
}

/**
 * Binds all 3 recovery factors (10-finger scan + 3D live face + offline seed phrase)
 * into quantum-safe SHA3-256 commitments so raw biometrics never leave the user's device.
 */
export function createRecoveryCommitment(
  tenFingerScanVector: string,
  liveFaceLivenessVector: string,
  offlineSeedPhrase: string
): ThreeFactorRecoveryCommitment {
  return {
    tenFingerCommitmentHash: bytesToHex(sha3_256(Buffer.from(tenFingerScanVector.trim().toLowerCase(), 'utf8'))),
    liveFaceCommitmentHash: bytesToHex(sha3_256(Buffer.from(liveFaceLivenessVector.trim().toLowerCase(), 'utf8'))),
    offlineSeedCommitmentHash: bytesToHex(sha3_256(Buffer.from(offlineSeedPhrase.trim().toLowerCase(), 'utf8'))),
    enrolledFingersCount: 10
  };
}

/**
 * Verifies all 3 factors simultaneously before granting global cross-device vault recovery.
 */
export function verifyThreeFactorRecovery(
  stored: ThreeFactorRecoveryCommitment,
  tenFingerInput: string,
  liveFaceInput: string,
  offlineSeedInput: string
): { recovered: boolean; failedFactors: string[] } {
  const failedFactors: string[] = [];

  const fingerHash = bytesToHex(sha3_256(Buffer.from(tenFingerInput.trim().toLowerCase(), 'utf8')));
  const faceHash = bytesToHex(sha3_256(Buffer.from(liveFaceInput.trim().toLowerCase(), 'utf8')));
  const seedHash = bytesToHex(sha3_256(Buffer.from(offlineSeedInput.trim().toLowerCase(), 'utf8')));

  if (fingerHash !== stored.tenFingerCommitmentHash) failedFactors.push('10-Finger Biometric Scan');
  if (faceHash !== stored.liveFaceCommitmentHash) failedFactors.push('3D Live Face Scan');
  if (seedHash !== stored.offlineSeedCommitmentHash) failedFactors.push('Offline Seed Phrase');

  return {
    recovered: failedFactors.length === 0,
    failedFactors
  };
}
