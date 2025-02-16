/**
 * simulate-registration.js
 * 
 * Generates a WebAuthn "none" attestation credential and saves it to disk
 * for further usage (e.g. in an authentication test).
 */

import fetch from "node-fetch";
import cbor from "cbor";
import base64url from "base64url";
import crypto from "crypto";
import fs from "fs/promises";

// ─────────────────────────────────────────────────────────────────────────────
//  Configuration
// ─────────────────────────────────────────────────────────────────────────────
const CONFIG = {
  // The origin your front-end uses in clientDataJSON
  origin: "http://localhost:3000",

  // Your backend API base URL
  serverUrl: "http://localhost:8080",

  // Where we’ll save the final credential object
  credentialOutputFile: "credential-formatted.json",

  // The GUID you want to pass to /registration/start
  publicGuid: "guid1guid1guid",
};

// ─────────────────────────────────────────────────────────────────────────────
//  Main Entry Point
// ─────────────────────────────────────────────────────────────────────────────
async function signCredential() {
  try {
    console.log(`Using front-end origin: ${CONFIG.origin}`);
    console.log(`Using back-end URL:    ${CONFIG.serverUrl}`);

    // 1) Request creation options
    const startResp = await fetch(`${CONFIG.serverUrl}/registration/start`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ publicGuid: CONFIG.publicGuid }),
    });

    if (!startResp.ok) {
      throw new Error(`Failed /registration/start: ${startResp.status}`);
    }

    const startJson = await startResp.json();
    const { registrationId, publicKeyCredentialCreationOptions } = startJson;
    if (!registrationId || !publicKeyCredentialCreationOptions) {
      throw new Error("Missing expected fields from /registration/start");
    }

    // 2) Parse creationOptions
    const creationOptions = JSON.parse(publicKeyCredentialCreationOptions);

    // 3) Generate "none" attestation credential
    const signedCredential = await makeNoneAttestationResponse(creationOptions);

    // 4) Format the result object & save to file
    const formattedOutput = {
      registrationId: registrationId,
      publicKeyCredentialString: JSON.stringify(signedCredential),
    };

    await fs.writeFile(CONFIG.credentialOutputFile, JSON.stringify(formattedOutput, null, 2));
    console.log(`\nCredential saved to "${CONFIG.credentialOutputFile}"`);
    console.log("\nFormatted output:");
    console.log(JSON.stringify(formattedOutput, null, 2));

    return formattedOutput;
  } catch (error) {
    console.error("Error in signCredential:", error);
    throw error;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
//  makeNoneAttestationResponse
//    Builds a minimal "none" attestation credential object
// ─────────────────────────────────────────────────────────────────────────────
async function makeNoneAttestationResponse(pubKeyCredParams) {
  const {
    challenge,
    rp,
    user,
    pubKeyCredParams: algs,
  } = pubKeyCredParams.publicKey;

  // 1) Generate an EC key pair on P-256
  const keyPair = crypto.generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
    publicKeyEncoding: { type: "spki", format: "der" },
    privateKeyEncoding: { type: "pkcs8", format: "der" },
  });

  // 2) Build clientDataJSON (including the "origin" from CONFIG)
  const clientDataObj = {
    type: "webauthn.create",
    challenge: challenge,    // server usually expects base64url, but we'll pass the exact string
    origin: CONFIG.origin,
    crossOrigin: false,
  };
  const clientDataJSON = Buffer.from(JSON.stringify(clientDataObj));
  console.log("ClientDataJSON:", clientDataObj); // Debug log

  // 3) Build authenticatorData
  const rpIdHash = crypto.createHash("sha256").update(rp.id).digest();
  const flagsBuf = Buffer.from([0x45]);  // 0x45 => AT flag, UV flag, etc. (adjust if needed)
  const signCountBuf = Buffer.alloc(4);  // 0
  const aaguid = Buffer.alloc(16);       // 0
  const credId = crypto.randomBytes(16);
  const credIdLenBuf = Buffer.alloc(2);
  credIdLenBuf.writeUInt16BE(credId.length, 0);

  // 4) Convert SPKI to uncompressed XY coords for COSE
  const pubKeyUncompressed = extractECPublicKeyCoords(keyPair.publicKey);

  // 5) Build COSE public key
  const cosePublicKey = new Map([
    [1, 2],   // kty: EC2
    [3, -7],  // alg: ES256
    [-1, 1],  // crv: P-256
    [-2, pubKeyUncompressed.x],
    [-3, pubKeyUncompressed.y],
  ]);
  const credentialPublicKey = cbor.encodeCanonical(cosePublicKey);

  const authenticatorData = Buffer.concat([
    rpIdHash,
    flagsBuf,
    signCountBuf,
    aaguid,
    credIdLenBuf,
    credId,
    credentialPublicKey,
  ]);

  // 6) Build attestationObject with fmt="none"
  const attestationObj = {
    fmt: "none",
    attStmt: {},
    authData: authenticatorData,
  };
  const attestationObject = cbor.encodeCanonical(attestationObj);

  // 7) Return final credential shape
  return {
    id: bufToBase64Url(credId),
    rawId: bufToBase64Url(credId),
    response: {
      clientDataJSON: bufToBase64Url(clientDataJSON),
      attestationObject: bufToBase64Url(attestationObject),
    },
    type: "public-key",
    clientExtensionResults: {},
    authenticatorAttachment: "platform",
  };
}

// ─────────────────────────────────────────────────────────────────────────────
//  extractECPublicKeyCoords
//    Scans the DER-encoded SPKI, searching for the final 0x04 + 64-byte XY
// ─────────────────────────────────────────────────────────────────────────────
function extractECPublicKeyCoords(spkiDer) {
  let offset = spkiDer.length - 65;

  while (offset >= 0) {
    if (spkiDer[offset] === 0x04 && offset + 65 <= spkiDer.length) {
      const potentialPoint = spkiDer.slice(offset, offset + 65);
      if (potentialPoint.length === 65) {
        const coords = potentialPoint.slice(1); // remove 0x04
        return {
          x: coords.slice(0, 32),
          y: coords.slice(32),
        };
      }
    }
    offset--;
  }
  throw new Error("Failed to find valid EC point in SPKI format");
}

// ─────────────────────────────────────────────────────────────────────────────
//  Utility: Buffer -> base64url
// ─────────────────────────────────────────────────────────────────────────────
function bufToBase64Url(buf) {
  return base64url(buf);
}

// ─────────────────────────────────────────────────────────────────────────────
//  Run the signing process
// ─────────────────────────────────────────────────────────────────────────────
console.log("Starting credential signing process...");
signCredential().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
