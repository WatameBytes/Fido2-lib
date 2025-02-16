import fetch from "node-fetch";
import { Fido2Lib } from "fido2-lib";
import cbor from "cbor";
import base64url from "base64url";
import crypto from "crypto";
import fs from "fs/promises";

// Configuration
const CONFIG = {
  origin: "http://localhost:3000",
  serverUrl: "http://localhost:8080"
};

async function makeNoneAttestationResponse(pubKeyCredParams) {
  const {
    challenge,
    rp,
    user,
    pubKeyCredParams: algs,
  } = pubKeyCredParams.publicKey;

  // Generate key pair
  const keyPair = crypto.generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
    publicKeyEncoding: {
      type: 'spki',
      format: 'der'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem'  // Save as PEM for easy reuse
    }
  });

  // Build clientDataJSON
  const clientDataObj = {
    type: "webauthn.create",
    challenge: challenge,
    origin: CONFIG.origin,
    crossOrigin: false
  };
  
  const clientDataJSON = Buffer.from(JSON.stringify(clientDataObj));
  console.log('ClientDataJSON:', clientDataObj);

  const rpIdHash = crypto.createHash("sha256").update(rp.id).digest();
  const flagsBuf = Buffer.from([0x45]);
  const signCountBuf = Buffer.alloc(4);
  const aaguid = Buffer.alloc(16);
  const credId = crypto.randomBytes(16);
  const credIdLenBuf = Buffer.alloc(2);
  credIdLenBuf.writeUInt16BE(credId.length, 0);

  const pubKeyUncompressed = extractECPublicKeyCoords(keyPair.publicKey);

  const cosePublicKey = new Map([
    [1, 2],      // kty: EC2
    [3, -7],     // alg: ES256
    [-1, 1],     // crv: P-256
    [-2, pubKeyUncompressed.x],
    [-3, pubKeyUncompressed.y]
  ]);

  const credentialPublicKey = cbor.encodeCanonical(cosePublicKey);

  const authenticatorData = Buffer.concat([
    rpIdHash,
    flagsBuf,
    signCountBuf,
    aaguid,
    credIdLenBuf,
    credId,
    credentialPublicKey
  ]);

  const attestationObj = {
    fmt: "none",
    attStmt: {},
    authData: authenticatorData
  };
  
  const attestationObject = cbor.encodeCanonical(attestationObj);

  const credential = {
    id: bufToBase64Url(credId),
    rawId: bufToBase64Url(credId),
    response: {
      clientDataJSON: bufToBase64Url(clientDataJSON),
      attestationObject: bufToBase64Url(attestationObject)
    },
    type: "public-key",
    clientExtensionResults: {},
    authenticatorAttachment: "platform"
  };

  // Return both the credential and keyPair
  return { credential, keyPair };
}

async function signCredential() {
  try {
    console.log(`Using frontend origin: ${CONFIG.origin}`);
    console.log(`Using backend URL: ${CONFIG.serverUrl}`);

    const startResp = await fetch(`${CONFIG.serverUrl}/registration/start`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        publicGuid: "guid1guid1guid",
      }),
    });

    if (!startResp.ok) {
      throw new Error(`Failed /registration/start: ${startResp.status}`);
    }

    const startJson = await startResp.json();
    const { registrationId, publicKeyCredentialCreationOptions } = startJson;
    const creationOptions = JSON.parse(publicKeyCredentialCreationOptions);

    const { user } = creationOptions.publicKey;

    // Destructure the return value to get both credential and keyPair
    const { credential: signedCredential, keyPair } = await makeNoneAttestationResponse(creationOptions);

    const savedCredential = {
      credentialId: signedCredential.id,
      rpId: "localhost",
      username: user.name,
      userHandle: user.id,
      privateKey: keyPair.privateKey,
      registeredAt: new Date().toISOString()
    };
    
    const formattedOutput = {
      registrationId: registrationId,
      publicKeyCredentialString: JSON.stringify(signedCredential)
    };

    await fs.writeFile('credential-formatted.json', JSON.stringify(formattedOutput, null, 2));
    await fs.writeFile('saved-credential.json', JSON.stringify(savedCredential, null, 2));

    console.log("\nSaved files:");
    console.log("1. credential-formatted.json - For registration completion");
    console.log("2. saved-credential.json - For future authentication");
    console.log("\nCredential details:", {
      ...savedCredential,
      privateKey: '(private key not shown)'
    });
    
    return formattedOutput;
  } catch (error) {
    console.error("Error in signCredential:", error);
    throw error;
  }
}

function extractECPublicKeyCoords(spkiDer) {
  let offset = spkiDer.length - 65;
  
  while (offset >= 0) {
    if (spkiDer[offset] === 0x04 && 
        offset + 65 <= spkiDer.length) {
      const potentialPoint = spkiDer.slice(offset, offset + 65);
      if (potentialPoint.length === 65) {
        const coords = potentialPoint.slice(1);
        return {
          x: coords.slice(0, 32),
          y: coords.slice(32)
        };
      }
    }
    offset--;
  }
  throw new Error('Failed to find valid EC point in SPKI format');
}

function bufToBase64Url(buf) {
  return base64url(buf);
}

// Run the signing process
console.log("Starting credential signing process...");
signCredential().catch(err => {
  console.error("Fatal error:", err);
  process.exit(1);
});