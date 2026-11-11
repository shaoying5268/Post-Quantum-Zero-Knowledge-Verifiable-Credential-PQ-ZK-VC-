import { ml_dsa65 } from '@noble/post-quantum/ml-dsa';
import { randomBytes } from '@noble/hashes/utils';
import { issueW3cBlindKycCredential, verifyW3cBlindKycCredential } from './index.js';

const trustAnchorKeys = ml_dsa65.keygen(randomBytes(32));
const userVaultMasterSecret = randomBytes(32);

const issuerDid = 'did:web5:masterkey:trust-anchor-global';
const verificationMethod = `${issuerDid}#pq-mldsa65-key-1`;

// Issue W3C VC 2.0 Credential for an international bank
const credential = issueW3cBlindKycCredential(
  trustAnchorKeys.secretKey,
  issuerDid,
  verificationMethod,
  userVaultMasterSecret,
  'did:web:hsbc-global-onboarding.example',
  {
    isHumanVerified: true,
    kycComplianceLevel: 'TIER_3_AML_FULL',
    isOver18: true,
    sanctionsClearance: 'PASSED'
  },
  'STARK_PROOF_BLOB_VERIFIED_LOCALLY'
);

console.log('W3C VC 2.0 Post-Quantum Credential:\n', JSON.stringify(credential, null, 2));

// Bank verifies W3C Schema + Canonicalized ML-DSA-65 Signature
const result = verifyW3cBlindKycCredential(trustAnchorKeys.publicKey, credential);
console.log('\nBank Verification Result:', result);
