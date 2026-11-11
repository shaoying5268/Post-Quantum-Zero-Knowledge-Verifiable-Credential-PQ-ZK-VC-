import express from 'express';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa';
import { bytesToHex, randomBytes, utf8ToBytes } from '@noble/hashes/utils';
import {
  issueW3cBlindKycCredential,
  verifyW3cBlindKycCredential,
  W3CPostQuantumZkKycCredential
} from '@masterkey/pq-zkkyc-sdk';
import { generateVaultKeypair, sealIdentityInVault } from '@masterkey/web5-dwn-vault';
import { JudicialTransparencyLedger } from '@masterkey/judicial-escrow';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const schemasDir = path.resolve(__dirname, '../../pq-zkkyc-sdk/schemas');
const contextDoc = JSON.parse(fs.readFileSync(path.join(schemasDir, 'pq-zkkyc-v1.jsonld'), 'utf8'));
const schemaDoc = JSON.parse(fs.readFileSync(path.join(schemasDir, 'pq-zkkyc-v1.schema.json'), 'utf8'));

const app = express();
app.use(express.json());

const trustAnchorKeys = ml_dsa65.keygen(randomBytes(32));
const courtAuthorityKeys = ml_dsa65.keygen(randomBytes(32));
const userSigningKeys = ml_dsa65.keygen(randomBytes(32));
const userVaultKeys = generateVaultKeypair();
const demoUserMasterSecret = randomBytes(32);

const ISSUER_DID = 'did:web5:masterkey:trust-anchor-global';
const VERIFICATION_METHOD = `${ISSUER_DID}#pq-mldsa65-key-1`;

const encryptedUserVault = sealIdentityInVault(userVaultKeys.publicKey, {
  masterDid: 'did:web5:masterkey:user-994821',
  fullName: 'Aarav Perera',
  dateOfBirth: '1995-04-18',
  passportNumber: 'N8492014',
  nationality: 'LKA',
  biometricLivenessHash: '0x9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e',
  kycTier: 'TIER_3_AML_FULL',
  sanctionsClearance: 'PASSED'
});

const judicialLedger = new JudicialTransparencyLedger();
let lastMintedPairwiseDid = '';

const verifiedPosts = [
  {
    id: 'post-1',
    authorBadge: 'Verified Human #9948',
    content: 'Zero bots, zero deepfakes. Every post carries a Post-Quantum ML-DSA-65 proof of humanity.',
    signaturePreview: bytesToHex(ml_dsa65.sign(userSigningKeys.secretKey, utf8ToBytes('genesis'))).slice(0, 28) + '...'
  }
];

const quantumChats = [
  {
    id: 'msg-1',
    sender: 'You (Hardware Enclave)',
    recipient: 'Nimal (ML-KEM-768)',
    cipherPreview: 'mlkem768::0x8f92a4c1d0e7b3... [Quantum Safe]',
    plaintext: 'Sent you the signed smart contract via our Web5 DWN node.'
  }
];

const careerCredentials = [
  {
    role: 'Principal Post-Quantum Protocol Architect',
    organization: 'MasterKey Web5 Foundation',
    status: 'Cryptographically Attested (W3C VC 2.0)'
  }
];

app.get('/.well-known/did.json', (_req, res) => {
  res.json({
    '@context': ['https://w3.org'],
    id: ISSUER_DID,
    verificationMethod: [{
      id: VERIFICATION_METHOD,
      type: 'ML-DSA-65-VerificationKey2026',
      controller: ISSUER_DID,
      publicKeyHex: bytesToHex(trustAnchorKeys.publicKey)
    }],
    assertionMethod: [VERIFICATION_METHOD]
  });
});

app.get('/contexts/pq-zkkyc-v1.jsonld', (_req, res) => res.json(contextDoc));
app.get('/schemas/pq-zkkyc-v1.schema.json', (_req, res) => res.json(schemaDoc));
app.get('/api/superapp/vault-status', (_req, res) => res.json({ encryptedEnvelope: encryptedUserVault }));

app.post('/api/superapp/mint-blind-credential', (req, res) => {
  const { thirdPartyAppDid = 'did:web:global-bank.example', kycComplianceLevel = 'TIER_3_AML_FULL' } = req.body;
  const credential = issueW3cBlindKycCredential(
    trustAnchorKeys.secretKey,
    ISSUER_DID,
    VERIFICATION_METHOD,
    demoUserMasterSecret,
    thirdPartyAppDid,
    { isHumanVerified: true, kycComplianceLevel, isOver18: true, sanctionsClearance: 'PASSED' },
    'STARK_PROOF_VERIFIED_ON_DEVICE'
  );
  lastMintedPairwiseDid = credential.credentialSubject.id;
  judicialLedger.registerPairwiseTokenLink(lastMintedPairwiseDid, encryptedUserVault, userVaultKeys.secretKey);
  res.json({ credential });
});

app.post('/api/third-party-bank/onboard', (req, res) => {
  const credential = req.body.credential as W3CPostQuantumZkKycCredential;
  const verification = verifyW3cBlindKycCredential(trustAnchorKeys.publicKey, credential);
  if (!verification.valid) return res.status(401).json({ status: 'REJECTED', reason: verification.reason });
  res.json({
    status: 'ACCOUNT_CREATED',
    anonymousAccountId: verification.pairwiseUserId,
    piiStoredByBank: 'NONE (Zero-Knowledge Blind Vault)'
  });
});

app.get('/api/superapp/state', (_req, res) => {
  res.json({ posts: verifiedPosts, chats: quantumChats, credentials: careerCredentials, warrants: judicialLedger.listWarrants() });
});

app.post('/api/superapp/post', (req, res) => {
  const { content } = req.body;
  if (!content) return res.status(400).json({ error: 'Content required' });
  const sig = bytesToHex(ml_dsa65.sign(userSigningKeys.secretKey, utf8ToBytes(content)));
  const post = { id: `post-${Date.now()}`, authorBadge: 'Verified Human #9948', content, signaturePreview: sig.slice(0, 28) + '...' };
  verifiedPosts.unshift(post);
  res.json({ post });
});

app.post('/api/superapp/chat', (req, res) => {
  const { message } = req.body;
  if (!message) return res.status(400).json({ error: 'Message required' });
  const chat = { id: `msg-${Date.now()}`, sender: 'You', recipient: 'Nimal (ML-KEM-768)', cipherPreview: `mlkem768::0x${bytesToHex(randomBytes(8))}...`, plaintext: message };
  quantumChats.push(chat);
  res.json({ chat });
});

app.post('/api/judicial/submit-warrant', (_req, res) => {
  if (!lastMintedPairwiseDid) return res.status(400).json({ error: 'Click Login to Global Bank first to mint a target token.' });
  const draft = {
    warrantId: `WRT-${Math.floor(1000 + Math.random() * 9000)}`,
    courtAuthorityName: 'High Court Financial Crimes Division',
    courtDid: 'did:gov:judiciary:financial-court-01',
    targetPairwiseDid: lastMintedPairwiseDid,
    legalBasis: 'AML Act Section 14(2)',
    scope: 'Verify legal identity bound to anonymous financial token',
    issuedAt: new Date().toISOString()
  };
  const courtSignatureHex = bytesToHex(ml_dsa65.sign(courtAuthorityKeys.secretKey, utf8ToBytes(JSON.stringify(draft))));
  const warrant = judicialLedger.submitJudicialWarrant(courtAuthorityKeys.publicKey, { ...draft, courtSignatureHex });
  res.json({ warrant });
});

app.post('/api/judicial/respond', (req, res) => {
  const { warrantId, grantConsent } = req.body;
  try {
    res.json(judicialLedger.processUserWarrantResponse(warrantId, Boolean(grantConsent), userSigningKeys.secretKey));
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

app.use(express.static(path.resolve(__dirname, '../public')));
app.listen(4000, () => console.log('MasterKey Web5 Super-App running on http://localhost:4000'));
