async function onboardApp(appDid) {
  const out = document.getElementById('kycOut');
  out.textContent = 'Minting pairwise W3C credential...';
  const mintRes = await fetch('/api/superapp/mint-blind-credential', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ thirdPartyAppDid: appDid })
  });
  const { credential } = await mintRes.json();
  const bankRes = await fetch('/api/third-party-bank/onboard', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ credential })
  });
  out.textContent = JSON.stringify({ appDid, result: await bankRes.json() }, null, 2);
}

async function simulateCourtWarrant() {
  const res = await fetch('/api/judicial/submit-warrant', { method: 'POST' });
  const data = await res.json();
  document.getElementById('warrantOut').textContent = data.error || 'ALERT: Court warrant received! User consent required.';
  refreshState();
}

async function respondWarrant(warrantId, grantConsent) {
  const res = await fetch('/api/judicial/respond', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ warrantId, grantConsent })
  });
  document.getElementById('warrantOut').textContent = JSON.stringify(await res.json(), null, 2);
  refreshState();
}

async function publishPost() {
  const input = document.getElementById('postInput');
  if (!input.value) return;
  await fetch('/api/superapp/post', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ content: input.value })
  });
  input.value = '';
  refreshState();
}

async function sendChat() {
  const input = document.getElementById('chatInput');
  if (!input.value) return;
  await fetch('/api/superapp/chat', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message: input.value })
  });
  input.value = '';
  refreshState();
}

async function refreshState() {
  const state = await (await fetch('/api/superapp/state')).json();
  document.getElementById('feedList').innerHTML = state.posts.map(p =>
    `<div class="item"><strong>${p.authorBadge}</strong><br/>${p.content}<br/><small style="color:#64748b">Sig: ${p.signaturePreview}</small></div>`
  ).join('');
  document.getElementById('chatList').innerHTML = state.chats.map(c =>
    `<div class="item"><strong>${c.sender} → ${c.recipient}</strong><br/>${c.plaintext}<br/><small style="color:#64748b">${c.cipherPreview}</small></div>`
  ).join('');
  document.getElementById('careerList').innerHTML = state.credentials.map(cr =>
    `<div class="item"><strong>${cr.role}</strong> • ${cr.organization} (${cr.status})</div>`
  ).join('');
  document.getElementById('warrantList').innerHTML = state.warrants.map(w =>
    `<div class="item"><strong>${w.warrantId} (${w.status})</strong><br/>${w.courtAuthorityName}: ${w.scope}` +
    (w.status === 'PENDING_USER_NOTIFICATION'
      ? `<br/><button class="success" onclick="respondWarrant('${w.warrantId}', true)">Approve</button><button class="danger" onclick="respondWarrant('${w.warrantId}', false)">Contest</button>`
      : '') + `</div>`
  ).join('');
}
refreshState();
