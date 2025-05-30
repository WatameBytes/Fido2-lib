import crypto from 'crypto';
import cbor from 'cbor';
import base64url from 'base64url';

async function getStdinJSON() {
  const chunks = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString());
}

function extractPublicKeyCoords(spkiDer) {
  let offset = spkiDer.length - 65;

  while (offset >= 0) {
    if (spkiDer[offset] === 0x04 && offset + 65 <= spkiDer.length) {
      const coords = spkiDer.slice(offset + 1, offset + 65);
      return {
        x: coords.slice(0, 32),
        y: coords.slice(32),
      };
    }
    offset--;
  }
  throw new Error('Failed to extract public key coordinates');
}

(async () => {
  const input = await getStdinJSON();
  const registrationId = input.registrationId;
  const publicKeyCredentialCreationOptions = JSON.parse(input.publicKeyCredentialCreationOptions);
  const { challenge, rp, user } = publicKeyCredentialCreationOptions.publicKey;

  const challengeBuffer = base64url.toBuffer(challenge);

  const keyPair = crypto.generateKeyPairSync('ec', {
    namedCurve: 'prime256v1',
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  const clientDataJSON = Buffer.from(JSON.stringify({
    type: 'webauthn.create',
    challenge: challenge,
    origin: `https://${rp.id}`,
    crossOrigin: false,
  }));

  const rpIdHash = crypto.createHash('sha256').update(rp.id).digest();
  const flagsBuf = Buffer.from([0x41]);
  const signCountBuf = Buffer.alloc(4);
  const aaguid = Buffer.alloc(16);
  const credId = crypto.randomBytes(16);
  const credIdLenBuf = Buffer.alloc(2);
  credIdLenBuf.writeUInt16BE(credId.length, 0);

  const publicKeyCoords = extractPublicKeyCoords(keyPair.publicKey);
  const cosePublicKey = new Map([
    [1, 2],
    [3, -7],
    [-1, 1],
    [-2, publicKeyCoords.x],
    [-3, publicKeyCoords.y],
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

  const attestationObject = cbor.encodeCanonical({
    fmt: 'none',
    attStmt: {},
    authData: authenticatorData,
  });

  const credential = {
    id: base64url(credId),
    rawId: base64url(credId),
    response: {
      clientDataJSON: base64url(clientDataJSON),
      attestationObject: base64url(attestationObject),
    },
    type: 'public-key',
    clientExtensionResults: {},
    authenticatorAttachment: 'platform',
  };

  const finalOutput = {
    registrationId,
    publicKeyCredentialString: JSON.stringify(credential),
  };

  // 👇 Output only the signed payload to stdout
  console.log(JSON.stringify(finalOutput));
})();
