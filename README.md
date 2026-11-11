# MasterKey Web5 — Post-Quantum Sovereign Identity Super-App & zkKYC Protocol

**One Master Key to the Internet.** A decentralized Web5 social, financial, and identity operating system built on **NIST Post-Quantum Cryptography (ML-KEM-768 & ML-DSA-65)** and **W3C Verifiable Credentials 2.0**.

## Architecture Overview
- **`packages/pq-zkkyc-sdk`**: W3C VC 2.0 compliant, RFC 8785 canonicalized, ML-DSA-65 signed **Blind zkKYC Tokens** with pairwise unlinkable DIDs (`did:ppid`). External apps verify regulatory compliance without seeing user PII.
- **`packages/web5-dwn-vault`**: Personal Decentralized Web Node (DWN) vault encrypting real identity records with **NIST ML-KEM-768 (CRYSTALS-Kyber) + AES-256-GCM**.
- **`packages/judicial-escrow` & `contracts/WarrantEscrowLedger.sol`**: Transparent 3-of-3 threshold disclosure protocol ensuring users receive immediate notifications and cryptographic consent prompts before any lawful judicial request is resolved.
- **`packages/trust-gateway`**: W3C DID Document resolver (`/.well-known/did.json`), JSON-LD Schema Registry, OID4VP Bank Onboarding Gateway, and unified Super-App Web UI.

## Quick Start
```bash
cd masterkey-web5-protocol
npm install
npm run build
npm test
npm --workspace=@masterkey/trust-gateway run start
```
