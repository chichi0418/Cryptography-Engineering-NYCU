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
  if (credential instanceof ArrayBuffer) {
    return bufferToBase64url(credential);
  }
  if (credential instanceof Uint8Array) {
    return bufferToBase64url(credential.buffer);
  }
  if (Array.isArray(credential)) {
    return credential.map((item) => publicKeyCredentialToJSON(item));
  }
  
  // Explicitly handle PublicKeyCredential to capture inherited properties like 'id' and 'rawId'
  if (credential && typeof credential === "object") {
    const obj = {};
    
    // List of keys to explicitly check if Object.keys(credential) is empty
    const keys = Object.keys(credential).length > 0 
      ? Object.keys(credential) 
      : ["id", "rawId", "type", "response", "authenticatorAttachment"];

    for (const key of keys) {
      if (credential[key] !== undefined && credential[key] !== null) {
        obj[key] = publicKeyCredentialToJSON(credential[key]);
      }
    }
    return obj;
  }
  return credential;
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
