import {
  generateVaultKeypair,
  sealIdentityInVault,
  unsealIdentityFromVault,
  SovereignIdentityRecord
} from './index.js';

const keys = generateVaultKeypair();

const realIdentity: SovereignIdentityRecord = {
  masterDid: 'did:web5:masterkey:user-994821',
  fullName: 'Aarav Perera',
  dateOfBirth: '1995-04-18',
  passportNumber: 'N8492014',
  nationality: 'LKA',
  biometricLivenessHash: '0x9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e',
  kycTier: 'TIER_3_AML_FULL',
  sanctionsClearance: 'PASSED'
};

const encryptedEnvelope = sealIdentityInVault(keys.publicKey, realIdentity);
console.log('Encrypted Post-Quantum ML-KEM-768 DWN Envelope:\n', JSON.stringify(encryptedEnvelope, null, 2));

const unlocked = unsealIdentityFromVault(keys.secretKey, encryptedEnvelope);
console.log('\nUnsealed Locally by User Hardware Key:\n', unlocked);
