const statusEl = document.getElementById("status");
const usernameEl = document.getElementById("username");
const registerBtn = document.getElementById("registerBtn");
const loginBtn = document.getElementById("loginBtn");

function getWebAuthnIssue() {
  if (!window.isSecureContext) {
    return "WebAuthn requires a secure context. Use https://... or http://localhost.";
  }
  if (!window.PublicKeyCredential) {
    return "This browser does not support WebAuthn/Passkeys.";
  }
  return null;
}

function setStatus(text, data = null) {
  if (data) {
    statusEl.textContent = `${text}\n${JSON.stringify(data, null, 2)}`;
  } else {
    statusEl.textContent = text;
  }
}

function getUsername() {
  const username = usernameEl.value.trim();
  if (!username) {
    throw new Error("Username is required");
  }
  return username;
}

function bufferToBase64url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (const b of bytes) {
    binary += String.fromCharCode(b);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64urlToBuffer(base64url) {
  const base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
  const padding = "=".repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(base64 + padding);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

function publicKeyCredentialToJSON(credential) {
  if (!credential) {
    return null;
  }

  const response = credential.response || {};
  const serializedResponse = {};

  if (response.clientDataJSON) {
    serializedResponse.clientDataJSON = bufferToBase64url(response.clientDataJSON);
  }
  if (response.attestationObject) {
    serializedResponse.attestationObject = bufferToBase64url(response.attestationObject);
  }
  if (response.authenticatorData) {
    serializedResponse.authenticatorData = bufferToBase64url(response.authenticatorData);
  }
  if (response.signature) {
    serializedResponse.signature = bufferToBase64url(response.signature);
  }
  if (response.userHandle) {
    serializedResponse.userHandle = bufferToBase64url(response.userHandle);
  }
  if (typeof response.getTransports === "function") {
    serializedResponse.transports = response.getTransports();
  }

  const serializedCredential = {
    id: credential.id,
    rawId: bufferToBase64url(credential.rawId),
    type: credential.type,
    response: serializedResponse,
  };

  if (credential.authenticatorAttachment) {
    serializedCredential.authenticatorAttachment = credential.authenticatorAttachment;
  }
  if (typeof credential.getClientExtensionResults === "function") {
    serializedCredential.clientExtensionResults = credential.getClientExtensionResults();
  }

  return serializedCredential;
}

function normalizeCreationOptions(publicKey) {
  return {
    ...publicKey,
    challenge: base64urlToBuffer(publicKey.challenge),
    user: {
      ...publicKey.user,
      id: base64urlToBuffer(publicKey.user.id),
    },
    excludeCredentials: (publicKey.excludeCredentials || []).map((cred) => ({
      ...cred,
      id: base64urlToBuffer(cred.id),
    })),
  };
}

function normalizeRequestOptions(publicKey) {
  return {
    ...publicKey,
    challenge: base64urlToBuffer(publicKey.challenge),
    allowCredentials: (publicKey.allowCredentials || []).map((cred) => ({
      ...cred,
      id: base64urlToBuffer(cred.id),
    })),
  };
}

async function postJSON(path, payload) {
  const resp = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const body = await resp.json().catch(() => ({}));
  if (!resp.ok) {
    throw new Error(body.detail || `Request failed (${resp.status})`);
  }
  return body;
}

registerBtn.addEventListener("click", async () => {
  try {
    const issue = getWebAuthnIssue();
    if (issue) {
      throw new Error(issue);
    }

    const username = getUsername();
    setStatus("Starting registration...");
    const begin = await postJSON("/register/begin", { username });

    let credential;
    try {
      credential = await navigator.credentials.create({
        publicKey: normalizeCreationOptions(begin.publicKey),
      });
    } catch (err) {
      await postJSON("/register/cancel", { username });
      throw new Error(`Registration cancelled: ${err.message}`);
    }

    const finish = await postJSON("/register/finish", {
      username,
      credential: publicKeyCredentialToJSON(credential),
    });

    setStatus(finish.message);
  } catch (err) {
    setStatus(`Registration failed: ${err.message}`);
  }
});

loginBtn.addEventListener("click", async () => {
  try {
    const issue = getWebAuthnIssue();
    if (issue) {
      throw new Error(issue);
    }

    const username = getUsername();
    setStatus("Starting login...");
    const begin = await postJSON("/login/begin", { username });

    let assertion;
    try {
      assertion = await navigator.credentials.get({
        publicKey: normalizeRequestOptions(begin.publicKey),
      });
    } catch (err) {
      await postJSON("/login/cancel", { username });
      throw new Error(`Login cancelled: ${err.message}`);
    }

    const finish = await postJSON("/login/finish", {
      username,
      credential: publicKeyCredentialToJSON(assertion),
    });

    setStatus(finish.message);
  } catch (err) {
    setStatus(`Login failed: ${err.message}`);
  }
});

const startupIssue = getWebAuthnIssue();
if (startupIssue) {
  setStatus(`Environment check failed: ${startupIssue}`);
}
