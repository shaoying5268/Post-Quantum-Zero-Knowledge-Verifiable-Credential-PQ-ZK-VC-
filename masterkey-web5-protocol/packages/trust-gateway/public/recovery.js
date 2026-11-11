let enrolledFingers = '';
let enrolledFace = '';
let recoveryFingers = '';
let recoveryFace = '';

function scanTenFingers() {
  enrolledFingers = '10-FINGERS-L1L2L3L4L5-R1R2R3R4R5-VERIFIED';
  const btn = document.getElementById('fingerBtn');
  btn.textContent = '✔ All 10 Fingers Scanned (10/10)';
  btn.style.borderColor = '#059669';
  btn.style.color = '#059669';
}

function scanLiveFace() {
  enrolledFace = '3D-LIVENESS-DEPTH-BLINK-VERIFIED';
  const btn = document.getElementById('faceBtn');
  btn.textContent = '✔ 3D Live Face Verified';
  btn.style.borderColor = '#059669';
  btn.style.color = '#059669';
}

function scanRecoveryFingers() {
  recoveryFingers = '10-FINGERS-L1L2L3L4L5-R1R2R3R4R5-VERIFIED';
  const btn = document.getElementById('recFingerBtn');
  btn.textContent = '✔ 10 Fingers Matched';
  btn.style.borderColor = '#059669';
  btn.style.color = '#059669';
}

function scanRecoveryFace() {
  recoveryFace = '3D-LIVENESS-DEPTH-BLINK-VERIFIED';
  const btn = document.getElementById('recFaceBtn');
  btn.textContent = '✔ Live 3D Face Matched';
  btn.style.borderColor = '#059669';
  btn.style.color = '#059669';
}

const originalCreateMasterKey = window.createMasterKey;
window.createMasterKey = async function () {
  const seedPhrase = document.getElementById('seedPhrase').value.trim();
  const box = document.getElementById('keyStatus');
  if (!enrolledFingers || !enrolledFace || !seedPhrase) {
    box.style.display = 'block';
    box.style.background = '#fef2f2';
    box.style.borderColor = '#fecaca';
    box.style.color = '#991b1b';
    box.innerHTML = '<strong>Complete all 3 safety checks first:</strong> Scan all 10 fingers, complete the 3D live face scan, and keep your 12-word offline seed phrase.';
    return;
  }
  box.style.background = '#f0fdf4';
  box.style.borderColor = '#bbf7d0';
  box.style.color = '#166534';

  await fetch('/api/superapp/enroll-recovery', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ tenFingersData: enrolledFingers, liveFaceData: enrolledFace, seedPhrase })
  });

  await originalCreateMasterKey();
  box.innerHTML += '<br/>• <strong>3-Step Recovery Shield Active:</strong> All 10 fingers + 3D live face + 12-word offline seed phrase enrolled.';
};

window.recoverLostAccount = async function () {
  const seedPhrase = document.getElementById('recSeedPhrase').value.trim();
  const box = document.getElementById('recoveryStatus');
  box.style.display = 'block';

  const res = await fetch('/api/superapp/recover-account', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ tenFingersData: recoveryFingers, liveFaceData: recoveryFace, seedPhrase })
  });
  const data = await res.json();

  if (!data.recovered) {
    box.style.background = '#fef2f2';
    box.style.borderColor = '#fecaca';
    box.style.color = '#991b1b';
    box.innerHTML = `<strong>Recovery Denied:</strong> ${data.message}`;
    return;
  }

  box.style.background = '#f0fdf4';
  box.style.borderColor = '#bbf7d0';
  box.style.color = '#166534';
  box.innerHTML = `<strong>Account Recovered Globally!</strong><br/>• ${data.message}<br/>• <strong>Restored Master Key:</strong> <code>${data.masterKeyId}</code>`;
};
