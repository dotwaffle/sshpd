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
if (enrolling) {
  document.title = 'Register a passkey | sshpd';
  document.getElementById('title').textContent = 'Register a passkey';
  document.getElementById('description').textContent = 'Use the enrollment link from your operator to add a passkey.';
  document.getElementById('name-field').hidden = true;
  name.required = false;
  button.textContent = 'Register a passkey';
}
if (approving) {
  document.title = 'Approve a native SSH client | sshpd';
  document.getElementById('title').textContent = 'Approve a native SSH client';
  document.getElementById('logout').hidden = true;
  button.textContent = 'Approve with a passkey';
  button.disabled = true;
  post('/auth/native/info', {code: approval}).then(info => {
    document.getElementById('description').textContent = `Approve only a login you started. Compare code ${info.code} and client ${info.client_id} with your command line. Approval expires ${new Date(info.expires).toLocaleTimeString()}.`;
    button.disabled = false;
  }).catch(() => { status.textContent = 'Approval expired or unavailable.'; });
}

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
      status.textContent = 'Native login approved. Return to your command line.';
      form.hidden = true;
      status.focus();
    } else {
      status.textContent = 'Signed in. Return to your Terminal connection.';
      if (new URLSearchParams(location.search).get('close') === '1') window.close();
    }
  } catch (error) {
    status.textContent = error.name === 'NotAllowedError' ? 'Passkey request canceled or expired. Retry when ready.' : error.message;
  } finally {
    button.disabled = false;
  }
});

document.getElementById('logout').addEventListener('click', async () => {
  try {
    await post('/auth/logout', {});
    status.textContent = 'Signed out. Connections from this login are closed.';
  } catch (error) { status.textContent = error.message; }
});
