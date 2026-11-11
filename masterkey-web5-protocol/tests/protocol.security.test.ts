import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa';
import { bytesToHex, randomBytes, utf8ToBytes } from '@noble/hashes/utils';
import {
  derivePairwiseDid,
  issueW3cBlindKycCredential,
  verifyW3cBlindKycCredential
} from '../packages/pq-zkkyc-sdk/src/index.js';
import {
  generateVaultKeypair,
  sealIdentityInVault,
  unsealIdentityFromVault
} from '../packages/web5-dwn-vault/src/index.js';
import { JudicialTransparencyLedger } from '../packages/judicial-escrow/src/index.js';

describe('MasterKey Web5 Post-Quantum Protocol Security Suite', () => {
  it('1. Enforces Pairwise Unlinkability across external apps', () => {
    const masterSecret = randomBytes(32);
    const bankDid = derivePairwiseDid(masterSecret, 'did:web:bank-a.example');
    const socialDid = derivePairwiseDid(masterSecret, 'did:web:social-b.example');
    assert.notEqual(bankDid, socialDid);
    assert.match(bankDid, /^did:ppid:0x[a-f0-9]{64}$/);
  });

  it('2. Mints and verifies W3C VC 2.0 ML-DSA-65 Blind Credentials and blocks tampering', () => {
    const anchorKeys = ml_dsa65.keygen(randomBytes(32));
    const userSecret = randomBytes(32);
    const cred = issueW3cBlindKycCredential(
      anchorKeys.secretKey,
      'did:web5:masterkey:trust-anchor-global',
      'did:web5:masterkey:trust-anchor-global#key-1',
      userSecret,
      'did:web:global-bank.example',
      { isHumanVerified: true, kycComplianceLevel: 'TIER_3_AML_FULL', isOver18: true, sanctionsClearance: 'PASSED' },
      'STARK_BLOB'
    );

    const validRes = verifyW3cBlindKycCredential(anchorKeys.publicKey, cred);
    assert.equal(validRes.valid, true);

    // Tamper with compliance tier and ensure signature check fails
    const tampered = structuredClone(cred);
    tampered.credentialSubject.claims.kycComplianceLevel = 'TIER_1';
    const invalidRes = verifyW3cBlindKycCredential(anchorKeys.publicKey, tampered);
    assert.equal(invalidRes.valid, false);
  });

  it('3. Seals and unseals personal identity inside NIST ML-KEM-768 DWN Vault', () => {
    const vaultKeys = generateVaultKeypair();
    const record = {
      masterDid: 'did:web5:masterkey:user-001',
      fullName: 'Aarav Perera',
      dateOfBirth: '1995-04-18',
      passportNumber: 'N8492014',
      nationality: 'LKA',
      biometricLivenessHash: '0x1234',
      kycTier: 'TIER_3_AML_FULL' as const,
      sanctionsClearance: 'PASSED' as const
    };
    const sealed = sealIdentityInVault(vaultKeys.publicKey, record);
    const unsealed = unsealIdentityFromVault(vaultKeys.secretKey, sealed);
    assert.deepEqual(unsealed, record);
  });

  it('4. Requires explicit user consent before unsealing identity under judicial warrant', () => {
    const courtKeys = ml_dsa65.keygen(randomBytes(32));
    const userSignKeys = ml_dsa65.keygen(randomBytes(32));
    const vaultKeys = generateVaultKeypair();
    const ppid = 'did:ppid:0x' + 'a'.repeat(64);

    const envelope = sealIdentityInVault(vaultKeys.publicKey, {
      masterDid: 'did:web5:masterkey:user-001',
      fullName: 'Aarav Perera',
      dateOfBirth: '1995-04-18',
      passportNumber: 'N8492014',
      nationality: 'LKA',
      biometricLivenessHash: '0x1234',
      kycTier: 'TIER_3_AML_FULL',
      sanctionsClearance: 'PASSED'
    });

    const ledger = new JudicialTransparencyLedger();
    ledger.registerPairwiseTokenLink(ppid, envelope, vaultKeys.secretKey);

    const draft = {
      warrantId: 'WRT-999',
      courtAuthorityName: 'Supreme Financial Court',
      courtDid: 'did:gov:court',
      targetPairwiseDid: ppid,
      legalBasis: 'Order #999',
      scope: 'Identity check',
      issuedAt: new Date().toISOString()
    };
    const courtSig = bytesToHex(ml_dsa65.sign(courtKeys.secretKey, utf8ToBytes(JSON.stringify(draft))));
    ledger.submitJudicialWarrant(courtKeys.publicKey, { ...draft, courtSignatureHex: courtSig });

    // Contesting blocks disclosure
    const contested = ledger.processUserWarrantResponse('WRT-999', false, userSignKeys.secretKey);
    assert.equal(contested.disclosedIdentity, undefined);
    assert.equal(contested.warrant.status, 'CONTESTED_JUDICIAL_REVIEW');
  });
});
