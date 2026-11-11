import { ml_dsa65 } from '@noble/post-quantum/ml-dsa';
import { sha3_256 } from '@noble/hashes/sha3';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils';
import canonicalizeModule from 'canonicalize';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import vcSchema from '../schemas/pq-zkkyc-v1.schema.json' with { type: 'json' };

const canonicalize = canonicalizeModule as unknown as (input: unknown) => string | undefined;

// Initialize strict W3C VC 2.0 Schema Validator
const AjvClass = (Ajv2020 as any).default ?? Ajv2020;
const ajv = new AjvClass({ allErrors: true });
const applyFormats = (addFormats as any).default ?? addFormats;
applyFormats(ajv);
const validateSchema = ajv.compile(vcSchema);

export interface ZkKycClaims {
  isHumanVerified: true;
  kycComplianceLevel: 'TIER_1' | 'TIER_2' | 'TIER_3_AML_FULL';
  isOver18: boolean;
  sanctionsClearance: 'PASSED' | 'FAILED';
}

export interface W3CPostQuantumZkKycCredential {
  '@context': [
    'https://w3.org',
    'https://masterkey.network'
  ];
  id: string;
  type: ['VerifiableCredential', 'PostQuantumZKKYCCredential'];
  issuer: string;
  validFrom: string;
  validUntil: string;
  credentialSubject: {
    id: string; // Pairwise Pseudonymous DID (did:ppid:0x...)
    claims: ZkKycClaims;
  };
  zkStarkProof: {
    circuitId: string;
    publicInputsHash: string;
    proofBlob: string;
  };
  proof: {
    type: 'ML-DSA-65-Signature2026';
    created: string;
    verificationMethod: string;
    proofPurpose: 'assertionMethod';
    proofValue: string; // Hex-encoded ML-DSA-65 signature over canonicalized VC
  };
}

/**
 * Generates an unlinkable Pairwise Pseudonymous DID (did:ppid) scoped strictly to one app.
 */
export function derivePairwiseDid(userMasterSecret: Uint8Array, thirdPartyAppDid: string): string {
  const combined = new Uint8Array([...userMasterSecret, ...utf8ToBytes(thirdPartyAppDid)]);
  const hash = sha3_256(combined);
  return `did:ppid:0x${bytesToHex(hash)}`;
}

/**
 * Super-App Vault: Issues a W3C VC 2.0 compliant, canonicalized, Post-Quantum signed credential.
 */
export function issueW3cBlindKycCredential(
  trustAnchorSecretKey: Uint8Array,
  issuerDid: string,
  verificationMethodId: string,
  userMasterSecret: Uint8Array,
  thirdPartyAppDid: string,
  claims: ZkKycClaims,
  zkStarkProofBlob: string
): W3CPostQuantumZkKycCredential {
  const now = new Date();
  const expires = new Date(now.getTime() + 24 * 60 * 60 * 1000);

  const unsignedCredential = {
    '@context': [
      'https://w3.org' as const,
      'https://masterkey.network' as const
    ],
    id: `urn:uuid:${crypto.randomUUID()}`,
    type: ['VerifiableCredential' as const, 'PostQuantumZKKYCCredential' as const],
    issuer: issuerDid,
    validFrom: now.toISOString(),
    validUntil: expires.toISOString(),
    credentialSubject: {
      id: derivePairwiseDid(userMasterSecret, thirdPartyAppDid),
      claims
    },
    zkStarkProof: {
      circuitId: 'stark-kyc-v1.4',
      publicInputsHash: `0x${bytesToHex(sha3_256(utf8ToBytes(zkStarkProofBlob)))}`,
      proofBlob: zkStarkProofBlob
    }
  };

  // Deterministic RFC 8785 Canonicalization before Post-Quantum ML-DSA signing
  const canonicalPayload = canonicalize(unsignedCredential);
  if (!canonicalPayload) {
    throw new Error('Failed to canonicalize W3C Verifiable Credential payload');
  }

  const signature = ml_dsa65.sign(trustAnchorSecretKey, utf8ToBytes(canonicalPayload));

  const signedCredential: W3CPostQuantumZkKycCredential = {
    ...unsignedCredential,
    "@context": unsignedCredential["@context"] as ["https://w3.org", "https://masterkey.network"],
    proof: {
      type: 'ML-DSA-65-Signature2026',
      created: now.toISOString(),
      verificationMethod: verificationMethodId,
      proofPurpose: 'assertionMethod',
      proofValue: bytesToHex(signature)
    }
  };

  if (!validateSchema(signedCredential)) {
    throw new Error(`Issued credential failed W3C schema validation: ${JSON.stringify(validateSchema.errors)}`);
  }

  return signedCredential;
}

/**
 * Third-Party Bank/App Verifier:
 * 1. Validates W3C VC 2.0 JSON Schema structure
 * 2. Checks expiration & compliance claims
 * 3. Canonicalizes payload and verifies Post-Quantum ML-DSA-65 signature
 */
export function verifyW3cBlindKycCredential(
  trustAnchorPublicKey: Uint8Array,
  credential: W3CPostQuantumZkKycCredential
): { valid: boolean; pairwiseUserId?: string; reason?: string } {
  // 1. Strict W3C Schema Validation
  if (!validateSchema(credential)) {
    return {
      valid: false,
      reason: `W3C Schema validation failed: ${ajv.errorsText(validateSchema.errors)}`
    };
  }

  // 2. Expiration & Sanctions Check
  if (new Date(credential.validUntil) < new Date()) {
    return { valid: false, reason: 'Credential expired' };
  }
  if (credential.credentialSubject.claims.sanctionsClearance !== 'PASSED') {
    return { valid: false, reason: 'Sanctions clearance not passed' };
  }

  // 3. Reconstruct Canonical Payload & Verify ML-DSA-65 Signature
  const { proof, ...unsignedCredential } = credential;
  const canonicalPayload = canonicalize(unsignedCredential);
  if (!canonicalPayload) {
    return { valid: false, reason: 'Canonicalization error' };
  }

  const sigBytes = Uint8Array.from(Buffer.from(proof.proofValue, 'hex'));
  const isValidSig = ml_dsa65.verify(trustAnchorPublicKey, utf8ToBytes(canonicalPayload), sigBytes);

  if (!isValidSig) {
    return { valid: false, reason: 'Invalid Post-Quantum ML-DSA-65 signature' };
  }

  return {
    valid: true,
    pairwiseUserId: credential.credentialSubject.id
  };
}
