/**
 * MasterKey Connect — 1-Click Institution Onboarding SDK
 * Allows any bank, fintech, or website to verify users with zero PII storage.
 */
window.MasterKeyConnect = {
  async login({ institutionDid, institutionName, requiredTier = 'TIER_3_AML_FULL', onSuccess, onError }) {
    try {
      // 1. Request a blind, pairwise W3C credential from the user's MasterKey Vault
      const mintRes = await fetch('/api/superapp/mint-blind-credential', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          thirdPartyAppDid: institutionDid,
          kycComplianceLevel: requiredTier
        })
      });
      const { credential } = await mintRes.json();

      // 2. Institution server verifies the Post-Quantum ML-DSA-65 signature & provisions account
      const verifyRes = await fetch('/api/third-party-bank/onboard', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ credential })
      });
      const result = await verifyRes.json();

      if (result.status !== 'ACCOUNT_CREATED') {
        throw new Error(result.reason || 'Verification declined');
      }

      if (typeof onSuccess === 'function') {
        onSuccess({
          institutionName,
          anonymousCustomerId: result.anonymousAccountId,
          complianceTier: result.complianceTier,
          piiStored: 'ZERO (Protected by MasterKey Blind Vault)'
        });
      }
    } catch (err) {
      if (typeof onError === 'function') onError(err.message);
    }
  },

  renderButton(containerId, options) {
    const el = document.getElementById(containerId);
    if (!el) return;
    el.innerHTML = `
      <button id="mk-btn-${containerId}" style="background:#1d4ed8;color:#fff;border:none;padding:12px 20px;border-radius:10px;font-size:15px;font-weight:600;cursor:pointer;display:inline-flex;align-items:center;gap:8px;box-shadow:0 4px 12px rgba(29,78,216,0.25);">
        🔑 Continue with MasterKey (Instant Verified Login)
      </button>
    `;
    document.getElementById(`mk-btn-${containerId}`).onclick = () => this.login(options);
  }
};
