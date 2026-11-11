import express from 'express';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa';
import { bytesToHex, randomBytes } from '@noble/hashes/utils';
import {
  issueW3cBlindKycCredential,
  verifyW3cBlindKycCredential,
  W3CPostQuantumZkKycCredential
} from '@masterkey/pq-zkkyc-sdk';
import contextDoc from '../../pq-zkkyc-sdk/schemas/pq-zkkyc-v1.jsonld' with { type: 'json' };
import schemaDoc from '../../pq-zkkyc-sdk/schemas/pq-zkkyc-v1.schema.json' with { type: 'json' };

const app = express();
app.use(express.json());

// Simulated Trust Anchor Post-Quantum Keypair & User Vault Secret
const trustAnchorKeys = ml_dsa65.keygen(randomBytes(32));
const demoUserMasterSecret = randomBytes(32);

const ISSUER_DID = 'did:web5:masterkey:trust-anchor-global';
const VERIFICATION_METHOD = `${ISSUER_DID}#pq-mldsa65-key-1`;

// 1. W3C DID Document Endpoint (Banks resolve this to fetch the ML-DSA-65 Public Key)
app.get('/.well-known/did.json', (_req, res) => {
  res.json({
    '@context': ['https://w3.org'],
    id: ISSUER_DID,
    verificationMethod: [
      {
        id: VERIFICATION_METHOD,
        type: 'ML-DSA-65-VerificationKey2026',
        controller: ISSUER_DID,
        publicKeyHex: bytesToHex(trustAnchorKeys.publicKey)
      }
    ],
    assertionMethod: [VERIFICATION_METHOD]
  });
});

// 2. Hosted W3C JSON-LD Context & Schema Registry
app.get('/contexts/pq-zkkyc-v1.jsonld', (_req, res) => res.json(contextDoc));
app.get('/schemas/pq-zkkyc-v1.schema.json', (_req, res) => res.json(schemaDoc));

// 3. Super-App Endpoint: User approves a third-party app's KYC request
app.post('/api/superapp/mint-blind-credential', (req, res) => {
  const { thirdPartyAppDid, kycComplianceLevel = 'TIER_3_AML_FULL' } = req.body;
  if (!thirdPartyAppDid) {
    return res.status(400).json({ error: 'thirdPartyAppDid is required' });
  }

  const credential = issueW3cBlindKycCredential(
    trustAnchorKeys.secretKey,
    ISSUER_DID,
    VERIFICATION_METHOD,
    demoUserMasterSecret,
    thirdPartyAppDid,
    {
      isHumanVerified: true,
      kycComplianceLevel,
      isOver18: true,
      sanctionsClearance: 'PASSED'
    },
    'STARK_PROOF_VERIFIED_ON_DEVICE'
  );

  res.json({ credential });
});

// 4. Third-Party Bank/App Endpoint: Instant Account Provisioning via OID4VP
app.post('/api/third-party-bank/onboard', (req, res) => {
  const credential = req.body.credential as W3CPostQuantumZkKycCredential;
  const verification = verifyW3cBlindKycCredential(trustAnchorKeys.publicKey, credential);

  if (!verification.valid) {
    return res.status(401).json({
      status: 'REJECTED',
      reason: verification.reason
    });
  }

  res.json({
    status: 'ACCOUNT_CREATED',
    complianceTier: credential.credentialSubject.claims.kycComplianceLevel,
    anonymousAccountId: verification.pairwiseUserId,
    piiStoredByBank: 'NONE (Zero-Knowledge Blind Vault)'
  });
});

const PORT = 4000;
app.listen(PORT, () => {
  console.log(`MasterKey W3C Trust Registry & OID4VP Gateway running on http://localhost:${PORT}`);
  console.log(`- W3C DID Document:   http://localhost:${PORT}/.well-known/did.json`);
  console.log(`- JSON-LD Context:    http://localhost:${PORT}/contexts/pq-zkkyc-v1.jsonld`);
  console.log(`- JSON Schema:        http://localhost:${PORT}/schemas/pq-zkkyc-v1.schema.json`);
});
