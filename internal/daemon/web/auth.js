'use strict';

const enrolling = location.pathname === '/enroll';
const approving = location.pathname === '/approve';
const approval = approving ? location.hash.slice(1) : '';
if (approving) history.replaceState(null, '', '/approve');
const invitation = enrolling ? location.hash.slice(1) : '';
if (enrolling) history.replaceState(null, '', '/enroll');
const form = document.getElementById('form');
const button = document.getElementById('submit');
const status = document.getElementById('status');
const name = document.getElementById('name');
const logout = document.getElementById('logout');
const sessionStatus = document.getElementById('session-status');
let approvalExpires = 0;
let approvalTimer;
let approvalComplete = false;

function showSession(signedIn) {
  sessionStatus.hidden = false;
  sessionStatus.dataset.state = signedIn ? 'signed-in' : 'signed-out';
  sessionStatus.textContent = signedIn ? 'This browser is signed in.' : 'This browser is not signed in.';
  form.hidden = signedIn;
  logout.hidden = !signedIn;
  document.getElementById('title').textContent = signedIn ? 'Ready to connect' : 'Sign in to sshpd';
  document.getElementById('description').textContent = signedIn
    ? 'Return to your Terminal connection. Signing out here closes connections from this browser login.'
    : 'Use your passkey to connect through the SSH relay.';
}

async function checkSession() {
  sessionStatus.hidden = false;
  sessionStatus.textContent = 'Checking browser sign-in…';
  try {
    const response = await fetch('/cookie?version=2&method=direct', {credentials: 'same-origin', cache: 'no-store', signal: AbortSignal.timeout(10000)});
    if (!response.ok) throw new Error('Session check failed');
    if (response.redirected && new URL(response.url).pathname === '/login') {
      showSession(false);
    } else if (!response.redirected && response.headers.get('Content-Type')?.startsWith('application/json')) {
      showSession(true);
    } else {
      throw new Error('Unexpected session response');
    }
  } catch {
    sessionStatus.textContent = 'Browser sign-in could not be checked. Reload this page or sign in again.';
    form.hidden = false;
  }
}

function expireApproval() {
  if (approvalComplete || Date.now() < approvalExpires) return;
  clearInterval(approvalTimer);
  button.disabled = true;
  status.textContent = 'Approval expired. Start a new login from your command line.';
}
if (enrolling) {
  form.hidden = false;
  document.title = 'Register a passkey | sshpd';
  document.getElementById('title').textContent = 'Register a passkey';
  document.getElementById('description').textContent = 'Use the enrollment link from your operator to add a passkey.';
  document.getElementById('name-field').hidden = true;
  name.required = false;
  button.textContent = 'Register a passkey';
}
if (approving) {
  form.hidden = false;
  document.title = 'Approve a native SSH client | sshpd';
  document.getElementById('title').textContent = 'Approve a native SSH client';
  document.getElementById('logout').hidden = true;
  button.textContent = 'Approve with a passkey';
  button.disabled = true;
  document.getElementById('description').textContent = 'Approve only a login you started. Check the code and client before using your passkey.';
  status.textContent = 'Loading approval details…';
  post('/auth/native/info', {code: approval}).then(info => {
    approvalExpires = Date.parse(info.expires);
    if (!Number.isFinite(approvalExpires)) throw new Error('Invalid approval expiry');
    document.getElementById('approval-code').textContent = info.code;
    document.getElementById('approval-client').textContent = info.client_id;
    const expiry = document.getElementById('approval-expiry');
    expiry.dateTime = info.expires;
    expiry.textContent = new Date(approvalExpires).toLocaleString(undefined, {dateStyle: 'medium', timeStyle: 'long'});
    document.getElementById('approval-details').hidden = false;
    status.textContent = '';
    button.disabled = Date.now() >= approvalExpires;
    approvalTimer = setInterval(expireApproval, 1000);
    expireApproval();
  }).catch(() => { status.textContent = 'Approval expired or unavailable. Start a new login from your command line.'; });
}

if (!enrolling && !approving) checkSession();

function decode(text) {
  const base64 = text.replace(/-/g, '+').replace(/_/g, '/');
  return Uint8Array.from(atob(base64), c => c.charCodeAt(0));
}

function encode(buffer) {
  let text = '';
  for (const value of new Uint8Array(buffer)) text += String.fromCharCode(value);
  return btoa(text).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function post(path, body, ceremony = '') {
  const response = await fetch(path, {
    method: 'POST', credentials: 'same-origin',
    headers: {'Content-Type': 'application/json', 'X-Ceremony-ID': ceremony},
    body: JSON.stringify(body),
  });
  if (!response.ok) throw new Error('Authentication failed. Retry or contact your operator.');
  return response.status === 204 ? {} : response.json();
}

form.addEventListener('submit', async event => {
  event.preventDefault();
  button.disabled = true;
  status.textContent = '';
  try {
    if (approving && (!approvalExpires || Date.now() >= approvalExpires)) throw new Error('Approval expired or unavailable. Start a new login from your command line.');
    if (enrolling && !invitation) throw new Error('Open a valid enrollment link from your operator.');
    if (!navigator.credentials || typeof navigator.credentials[enrolling ? 'create' : 'get'] !== 'function') {
      throw new Error('This browser does not support passkeys. Use a browser with passkey support.');
    }
    const kind = enrolling ? 'register' : approving ? 'native' : 'login';
    const begin = await post(`/auth/${kind}/begin`, enrolling ? {invitation} : approving ? {name: name.value, approval} : {name: name.value});
    const publicKey = begin.publicKey;
    publicKey.challenge = decode(publicKey.challenge);
    if (publicKey.user) publicKey.user.id = decode(publicKey.user.id);
    for (const field of ['allowCredentials', 'excludeCredentials']) {
      for (const credential of publicKey[field] || []) credential.id = decode(credential.id);
    }
    const credential = await (enrolling ? navigator.credentials.create({publicKey}) : navigator.credentials.get({publicKey}));
    if (!credential) throw new Error('No passkey was selected.');
    const response = {clientDataJSON: encode(credential.response.clientDataJSON)};
    if (enrolling) {
      response.attestationObject = encode(credential.response.attestationObject);
      if (credential.response.getTransports) response.transports = credential.response.getTransports();
    } else {
      response.authenticatorData = encode(credential.response.authenticatorData);
      response.signature = encode(credential.response.signature);
      if (credential.response.userHandle) response.userHandle = encode(credential.response.userHandle);
    }
    await post(`/auth/${kind}/finish`, {
      id: credential.id, rawId: encode(credential.rawId), type: credential.type,
      authenticatorAttachment: credential.authenticatorAttachment,
      clientExtensionResults: credential.getClientExtensionResults(), response,
    }, begin.ceremony);
    if (enrolling) {
      status.textContent = 'Passkey registered. Open the sign-in page to connect.';
      form.hidden = true;
      const link = document.createElement('a');
      link.href = '/login'; link.textContent = 'Sign in';
      status.append(' ', link);
      link.focus();
    } else if (approving) {
      approvalComplete = true;
      clearInterval(approvalTimer);
      status.textContent = 'Native login approved. Return to your command line. This does not sign in your browser.';
      form.hidden = true;
      status.focus();
    } else {
      showSession(true);
      status.textContent = 'Signed in. Return to your Terminal connection.';
      status.focus();
      if (new URLSearchParams(location.search).get('close') === '1') window.close();
    }
  } catch (error) {
    status.textContent = error.name === 'NotAllowedError' ? 'Passkey request canceled or expired. Retry when ready.' : error.message;
  } finally {
    button.disabled = approving && (approvalComplete || !approvalExpires || Date.now() >= approvalExpires);
  }
});

logout.addEventListener('click', async () => {
  logout.disabled = true;
  try {
    await post('/auth/logout', {});
    showSession(false);
    status.textContent = 'Signed out. Connections from this browser login are closed.';
    name.focus();
  } catch (error) { status.textContent = error.message; }
  finally { logout.disabled = false; }
});
