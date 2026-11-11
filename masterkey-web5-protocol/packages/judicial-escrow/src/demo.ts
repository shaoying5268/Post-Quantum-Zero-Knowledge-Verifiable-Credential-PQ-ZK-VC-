import { ml_dsa65 } from '@noble/post-quantum/ml-dsa';
import { bytesToHex, randomBytes, utf8ToBytes } from '@noble/hashes/utils';
import { generateVaultKeypair, sealIdentityInVault } from '@masterkey/web5-dwn-vault';
import { JudicialTransparencyLedger } from './index.js';

const courtKeys = ml_dsa65.keygen(randomBytes(32));
const userSigningKeys = ml_dsa65.keygen(randomBytes(32));
const userVaultKeys = generateVaultKeypair();

const pairwiseDid = 'did:ppid:0x2df896bb52d33b8f5cd77e4152458961117cc7405fd1f7e3d22c66a2b3a759b6';

// 1. Seal user's real identity inside their Post-Quantum Web5 Vault
const envelope = sealIdentityInVault(userVaultKeys.publicKey, {
  masterDid: 'did:web5:masterkey:user-994821',
  fullName: 'Aarav Perera',
  dateOfBirth: '1995-04-18',
  passportNumber: 'N8492014',
  nationality: 'LKA',
  biometricLivenessHash: '0x9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e',
  kycTier: 'TIER_3_AML_FULL',
  sanctionsClearance: 'PASSED'
});

const ledger = new JudicialTransparencyLedger();
ledger.registerPairwiseTokenLink(pairwiseDid, envelope, userVaultKeys.secretKey);

// 2. Court submits a signed warrant targeting the anonymous token
const draft = {
  warrantId: 'WRT-2026-8841',
  courtAuthorityName: 'High Court Financial Crimes Division',
  courtDid: 'did:gov:judiciary:financial-court-01',
  targetPairwiseDid: pairwiseDid,
  legalBasis: 'AML Act Section 14(2) — Court Order #FC-902',
  scope: 'Verify legal identity bound to anonymous bank token',
  issuedAt: new Date().toISOString()
};

const courtSig = bytesToHex(ml_dsa65.sign(courtKeys.secretKey, utf8ToBytes(JSON.stringify(draft))));
const submitted = ledger.submitJudicialWarrant(courtKeys.publicKey, {
  ...draft,
  courtSignatureHex: courtSig
});

console.log('1. Court Warrant Submitted (User Push Alert Triggered):\n', submitted);

// 3. User reviews notification and grants cryptographic consent
const resolution = ledger.processUserWarrantResponse(
  submitted.warrantId,
  true,
  userSigningKeys.secretKey
);
console.log('\n2. User Consent Resolution:\n', resolution);
