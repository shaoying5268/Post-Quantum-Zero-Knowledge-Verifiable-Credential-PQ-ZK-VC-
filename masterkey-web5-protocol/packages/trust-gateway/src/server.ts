import express from 'express';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa';
import { bytesToHex, randomBytes } from '@noble/hashes/utils';
import {
  issueW3cBlindKycCredential,
  verifyW3cBlindKycCredential,
  W3CPostQuantumZkKycCredential
} from '@masterkey/pq-zkkyc-sdk';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const schemasDir = path.resolve(__dirname, '../../pq-zkkyc-sdk/schemas');

const contextDoc = JSON.parse(fs.readFileSync(path.join(schemasDir, 'pq-zkkyc-v1.jsonld'), 'utf8'));
const schemaDoc = JSON.parse(fs.readFileSync(path.join(schemasDir, 'pq-zkkyc-v1.schema.json'), 'utf8'));

const app = express();
app.use(express.json());

// Simulated Trust Anchor Post-Quantum Keypair & User Vault Secret
const trustAnchorKeys = ml_dsa65.keygen(randomBytes(32));
const demoUserMasterSecret = randomBytes(32);

const ISSUER_DID = 'did:web5:masterkey:trust-anchor-global';
const VERIFICATION_METHOD = `${ISSUER_DID}#pq-mldsa65-key-1`;

app.get("/", (_req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html style="font-family:system-ui;background:#0b0f19;color:#f8fafc;padding:2rem;">
    <head><title>MasterKey Web5 Post-Quantum Gateway</title></head>
    <body style="max-width:760px;margin:auto;">
      <h1>MasterKey Web5 — Post-Quantum Trust Gateway</h1>
      <p><strong>Status:</strong> Active (NIST ML-DSA-65 + W3C VC 2.0)</p>
      <h3>1. Public W3C Registry Endpoints</h3>
      <ul>
        <li><a style="color:#38bdf8" href="/.well-known/did.json">/.well-known/did.json</a> (W3C DID Document)</li>
        <li><a style="color:#38bdf8" href="/contexts/pq-zkkyc-v1.jsonld">/contexts/pq-zkkyc-v1.jsonld</a> (JSON-LD Context)</li>
        <li><a style="color:#38bdf8" href="/schemas/pq-zkkyc-v1.schema.json">/schemas/pq-zkkyc-v1.schema.json</a> (JSON Schema)</li>
      </ul>
      <h3>2. Interactive Zero-Knowledge Bank Onboarding Test</h3>
      <button id="btn" style="background:#2563eb;color:white;border:none;padding:12px 20px;border-radius:8px;font-size:16px;cursor:pointer;">
        Continue with Master Key (Global Bank KYC)
      </button>
      <pre id="out" style="background:#1e293b;padding:1rem;border-radius:8px;overflow:auto;margin-top:1rem;">Click the button to mint a blind token and onboard with zero PII...</pre>
      <script>
        document.getElementById("btn").onclick = async () => {
          const out = document.getElementById("out");
          out.textContent = "Minting Post-Quantum ML-DSA-65 W3C Credential...";
          const mintRes = await fetch("/api/superapp/mint-blind-credential", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ thirdPartyAppDid: "did:web:global-bank.example" })
          });
          const { credential } = await mintRes.json();
          const bankRes = await fetch("/api/third-party-bank/onboard", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ credential })
          });
          const bankResult = await bankRes.json();
          out.textContent = JSON.stringify({ bankResult, blindCredentialSent: credential }, null, 2);
        };
      </script>
    </body>
    </html>
  `);
});

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
