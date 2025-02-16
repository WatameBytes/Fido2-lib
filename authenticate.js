import fetch from "node-fetch";
import base64url from "base64url";
import crypto from "crypto";
import fs from "fs/promises";

const CONFIG = {
  origin: "http://localhost:3000",
  serverUrl: "http://localhost:8080"
};

async function makeAssertion(credentialJson, savedCred) {
  const { challenge } = credentialJson.publicKey;

  // Create authenticator data
  const authData = createAuthenticatorData();
  
  // Create client data
  const clientDataJSON = createClientDataJSON(challenge);
  
  // Create the signature base by concatenating authData and hash of clientDataJSON
  const clientDataHash = crypto.createHash('sha256').update(clientDataJSON).digest();
  const signatureBase = Buffer.concat([authData, clientDataHash]);

  // Create signature using the private key
  const sign = crypto.createSign('SHA256');
  sign.update(signatureBase);
  const signature = sign.sign({
    key: savedCred.privateKey,
    dsaEncoding: 'der'  // Important: Use DER encoding for the signature
  });

  return {
    id: savedCred.credentialId,
    rawId: savedCred.credentialId,
    type: "public-key",
    response: {
      authenticatorData: bufToBase64Url(authData),
      clientDataJSON: bufToBase64Url(clientDataJSON),
      signature: bufToBase64Url(signature)
    },
    clientExtensionResults: {}
  };
}

function createAuthenticatorData() {
  const rpIdHash = crypto.createHash("sha256").update("localhost").digest();
  const flags = Buffer.from([0x01]); // User Present flag
  const signCount = Buffer.alloc(4);
  return Buffer.concat([rpIdHash, flags, signCount]);
}

function createClientDataJSON(challenge) {
  const clientDataObj = {
    type: "webauthn.get",
    challenge: challenge,
    origin: CONFIG.origin,
    crossOrigin: false
  };
  return Buffer.from(JSON.stringify(clientDataObj));
}

async function authenticate() {
  try {
    const savedCred = await loadSavedCredential();
    console.log("Loaded saved credential:", savedCred);

    const startResp = await fetch(`${CONFIG.serverUrl}/authenticate/start`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        credentialId: savedCred.credentialId,
        username: savedCred.username
      }),
    });

    if (!startResp.ok) {
      const errorText = await startResp.text();
      throw new Error(`Failed /authentication/start: ${startResp.status} - ${errorText}`);
    }

    const startJson = await startResp.json();
    console.log("Authentication start response:", startJson);

    const credentialJson = JSON.parse(startJson.credentialJson);
    console.log("Parsed credential options:", credentialJson);

    const assertion = await makeAssertion(credentialJson, savedCred);

    const formattedOutput = {
      assertionId: startJson.assertionId,
      publicKeyCredentialJson: JSON.stringify(assertion)
    };

    await fs.writeFile('auth-response.json', JSON.stringify(formattedOutput, null, 2));
    
    console.log("\nAuthentication response saved to auth-response.json");
    console.log("\nFormatted output:");
    console.log(JSON.stringify(formattedOutput, null, 2));

    return formattedOutput;
  } catch (error) {
    console.error("Authentication failed:", error);
    throw error;
  }
}

async function loadSavedCredential() {
  try {
    const savedData = await fs.readFile('saved-credential.json', 'utf8');
    return JSON.parse(savedData);
  } catch (error) {
    console.error("Error loading saved credential:", error);
    throw new Error("No saved credential found. Please register first.");
  }
}

function bufToBase64Url(buf) {
  return base64url(buf);
}

// Run the authentication
console.log("Starting authentication process...");
authenticate().catch(err => {
  console.error("Fatal error:", err);
  process.exit(1);
});