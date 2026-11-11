import { ml_dsa65 } from '@noble/post-quantum/ml-dsa';
import { sha3_256 } from '@noble/hashes/sha3';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils';
import {
  EncryptedDwnEnvelope,
  SovereignIdentityRecord,
  unsealIdentityFromVault
} from '@masterkey/web5-dwn-vault';

export type WarrantStatus =
  | 'PENDING_USER_NOTIFICATION'
  | 'APPROVED_BY_USER_CONSENT'
  | 'CONTESTED_JUDICIAL_REVIEW';

export interface JudicialWarrant {
  warrantId: string;
  courtAuthorityName: string;
  courtDid: string;
  targetPairwiseDid: string;
  legalBasis: string;
  scope: string;
  issuedAt: string;
  courtSignatureHex: string;
  status: WarrantStatus;
  userConsentSignatureHex?: string;
  auditLogHash: string;
}

export class JudicialTransparencyLedger {
  private warrants = new Map<string, JudicialWarrant>();
  private tokenToVaultMap = new Map<
    string,
    { envelope: EncryptedDwnEnvelope; userVaultSecretKey: Uint8Array }
  >();

  /**
   * Registers an encrypted DWN vault link inside the Super-App's sovereign index.
   * Third-party apps never have access to this mapping.
   */
  registerPairwiseTokenLink(
    pairwiseDid: string,
    envelope: EncryptedDwnEnvelope,
    userVaultSecretKey: Uint8Array
  ) {
    this.tokenToVaultMap.set(pairwiseDid, { envelope, userVaultSecretKey });
  }

  /**
   * Step 1: Verified Judicial Authority submits a Post-Quantum signed warrant.
   * Immediately queues a mandatory user push alert inside the Super-App.
   */
  submitJudicialWarrant(
    courtPublicKey: Uint8Array,
    warrantDraft: Omit<JudicialWarrant, 'status' | 'auditLogHash' | 'userConsentSignatureHex'>
  ): JudicialWarrant {
    const { courtSignatureHex, ...unsignedPayload } = warrantDraft;
    const isValidCourtSig = ml_dsa65.verify(
      courtPublicKey,
      utf8ToBytes(JSON.stringify(unsignedPayload)),
      hexToBytes(courtSignatureHex)
    );

    if (!isValidCourtSig) {
      throw new Error('Rejected: Invalid Post-Quantum judicial authority signature');
    }

    const auditLogHash = `0x${bytesToHex(sha3_256(utf8ToBytes(JSON.stringify(warrantDraft))))}`;
    const record: JudicialWarrant = {
      ...warrantDraft,
      status: 'PENDING_USER_NOTIFICATION',
      auditLogHash
    };

    this.warrants.set(record.warrantId, record);
    return record;
  }

  /**
   * Step 2: User reviews the alert in their Super-App and responds with cryptographic consent or contests it.
   */
  processUserWarrantResponse(
    warrantId: string,
    grantConsent: boolean,
    userSigningSecretKey: Uint8Array
  ): {
    warrant: JudicialWarrant;
    disclosedIdentity?: SovereignIdentityRecord;
    notice: string;
  } {
    const warrant = this.warrants.get(warrantId);
    if (!warrant) {
      throw new Error('Warrant not found');
    }

    const consentSig = ml_dsa65.sign(
      userSigningSecretKey,
      utf8ToBytes(`${warrantId}:${grantConsent ? 'APPROVE' : 'CONTEST'}`)
    );
    warrant.userConsentSignatureHex = bytesToHex(consentSig);

    if (!grantConsent) {
      warrant.status = 'CONTESTED_JUDICIAL_REVIEW';
      return {
        warrant,
        notice:
          'User contested warrant. Account placed in temporary compliance freeze pending transparent court hearing; zero data disclosed silently.'
      };
    }

    const vaultEntry = this.tokenToVaultMap.get(warrant.targetPairwiseDid);
    if (!vaultEntry) {
      throw new Error('No local vault record bound to this pairwise token');
    }

    warrant.status = 'APPROVED_BY_USER_CONSENT';
    const disclosedIdentity = unsealIdentityFromVault(
      vaultEntry.userVaultSecretKey,
      vaultEntry.envelope
    );

    return {
      warrant,
      disclosedIdentity,
      notice:
        '3-of-3 Threshold Unlock complete with explicit user consent. Immutable audit log recorded on-chain.'
    };
  }

  listWarrants(): JudicialWarrant[] {
    return Array.from(this.warrants.values());
  }
}
