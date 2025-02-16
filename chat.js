// simulate-registration.js

import fetch from "node-fetch";   // or remove if on Node 18+ and using native fetch
import cbor from "cbor";
import base64url from "base64url";
import crypto from "crypto";

/**
 * Utility: base64url-encode a buffer
 */
function bufToBase64Url(buf) {
  return base64url(buf);
}

/**
 * Main function: 
 *  1) Calls GET /registration/start with a JSON body (!) 
 *  2) Generates a "none" attestation 
 *  3) Calls POST /registration/finish
 */
async function simulateRegistration() {
  // 1) Request the creation options from your server
  //    *** UNCONVENTIONAL: we do a GET request with a body. *** 
  //    Many servers ignore this. If your server is custom-coded to accept it, fine.
  const startResp = await fetch("http://localhost:8080/registration/start", {
    method: "GET",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      publicGuid: "guid1guid1guid",
    }),
  });

  if (!startResp.ok) {
    throw new Error(`Failed /registration/start: ${startResp.status}`);
  }

  const startJson = await startResp.json();
  // Expect something like:
  // {
  //   "registrationId": "...",
  //   "publicKeyCredentialCreationOptions": "{\"publicKey\":{...}}"
  // }

  const { registrationId, publicKeyCredentialCreationOptions } = startJson;
  if (!registrationId || !publicKeyCredentialCreationOptions) {
    console.error("DEBUG - startJson:", startJson);
    throw new Error("Missing expected fields in /registration/start response");
  }

  // 2) Parse the server's JSON string into a real JS object
  const creationOptions = JSON.parse(publicKeyCredentialCreationOptions);

  // 3) Generate a "none" attestation
  const credential = await makeNoneAttestationResponse(creationOptions);

  // 4) Submit credential to /registration/finish
  const finishPayload = {
    registrationId: registrationId,
    publicKeyCredentialJson: credential,
  };

  console.log("Submitting to /registration/finish:", finishPayload);

  const finishResp = await fetch("http://localhost:8080/registration/finish", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(finishPayload),
  });

  if (!finishResp.ok) {
    throw new Error(`Finish failed: HTTP ${finishResp.status}`);
  }

  const finishJson = await finishResp.json();
  console.log("Registration finish response:", finishJson);
  console.log("SUCCESS! 🎉");
}

/**
 * Generate a minimal "none" attestation with a new P-256 key. 
 * Returns an object like:
 * {
 *   id,
 *   rawId,
 *   type: "public-key",
 *   response: {
 *     clientDataJSON,
 *     attestationObject
 *   }
 * }
 */
async function makeNoneAttestationResponse(creationOptions) {
  const {
    challenge,
    rp,
    user,
    pubKeyCredParams,
    authenticatorSelection,
    attestation,
  } = creationOptions.publicKey;

  // 1) Generate a new EC keypair (P-256)
  const { privateKey } = crypto.generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
  });

  // 2) Use ECDH to get an uncompressed public key (0x04 + x(32) + y(32))
  const ecdh = crypto.createECDH("prime256v1");
  const pkcs8Der = privateKey.export({ type: "pkcs8", format: "der" });
  ecdh.setPrivateKey(pkcs8Der);

  const pubKeyUncompressed = ecdh.getPublicKey();
  // pubKeyUncompressed[0] = 0x04, next 32 bytes = X, next 32 bytes = Y
  if (pubKeyUncompressed.length !== 65 || pubKeyUncompressed[0] !== 0x04) {
    throw new Error(`Expected uncompressed public key 0x04 + 64 bytes, got length=${pubKeyUncompressed.length}`);
  }
  const x = pubKeyUncompressed.slice(1, 33);
  const y = pubKeyUncompressed.slice(33, 65);

  // 3) clientDataJSON
  const clientDataObj = {
    type: "webauthn.create",
    challenge: base64url.toBase64(challenge),
    origin: "http://localhost",
  };
  const clientDataJSONBuf = Buffer.from(JSON.stringify(clientDataObj));

  // 4) authenticatorData
  const rpIdHash = crypto.createHash("sha256").update(rp.id).digest();
  const flagsBuf = Buffer.from([0x41]); // 0x41 => AT flag + userPresent
  const signCountBuf = Buffer.alloc(4); // zero
  const aaguid = Buffer.alloc(16);      // zero
  const credId = crypto.randomBytes(16);
  const credIdLenBuf = Buffer.alloc(2);
  credIdLenBuf.writeUInt16BE(credId.length, 0);

  // Build COSE key for ES256
  const coseKey = new Map();
  coseKey.set(1, 2);   // kty=EC2
  coseKey.set(3, -7);  // alg=ES256
  coseKey.set(-1, 1);  // crv=P-256
  coseKey.set(-2, x);
  coseKey.set(-3, y);
  const credentialPublicKey = cbor.encodeCanonical(coseKey);

  const authenticatorData = Buffer.concat([
    rpIdHash,
    flagsBuf,
    signCountBuf,
    aaguid,
    credIdLenBuf,
    credId,
    credentialPublicKey,
  ]);

  // 5) Attestation object => "none"
  const attObj = new Map();
  attObj.set("fmt", "none");
  attObj.set("attStmt", new Map());
  attObj.set("authData", authenticatorData);

  const attestationObjectBuf = cbor.encodeCanonical(attObj);

  // 6) Return the final credential shape
  return {
    id: bufToBase64Url(credId),
    rawId: bufToBase64Url(credId),
    type: "public-key",
    response: {
      clientDataJSON: bufToBase64Url(clientDataJSONBuf),
      attestationObject: bufToBase64Url(attestationObjectBuf),
    },
  };
}

// Run it!
simulateRegistration().catch((err) => {
  console.error("ERROR in simulateRegistration:", err);
  process.exit(1);
});
