import crypto from 'crypto';
import base64url from 'base64url';
import fs from 'fs/promises';

async function authenticateFromFile(assertionInputFile, credentialSecretsFile) {
  // Load the assertion input and credential secrets
  const assertionInput = JSON.parse(await fs.readFile(assertionInputFile, 'utf8'));
  const credentialSecrets = JSON.parse(await fs.readFile(credentialSecretsFile, 'utf8'));

  const { credentialId, privateKey } = credentialSecrets;
  const decodedPrivateKey = Buffer.from(privateKey, 'base64').toString('utf8');

  const credentialJson = JSON.parse(assertionInput.credentialJson);
  const { challenge, rpId } = credentialJson.publicKey;

  // Prepare clientDataJSON
  const clientDataJSON = Buffer.from(JSON.stringify({
    type: 'webauthn.get',
    challenge: challenge,
    origin: `https://${rpId}`,
    crossOrigin: false,
  }));

  // Prepare authenticatorData
  const rpIdHash = crypto.createHash('sha256').update(rpId).digest();
  const flagsBuf = Buffer.from([0x01]); // user present
  const signCountBuf = Buffer.alloc(4); // zero
  const authenticatorData = Buffer.concat([rpIdHash, flagsBuf, signCountBuf]);

  // Signature Base: authenticatorData + hash(clientDataJSON)
  const signatureBase = Buffer.concat([
    authenticatorData,
    crypto.createHash('sha256').update(clientDataJSON).digest(),
  ]);

  // Sign using stored private key
  const sign = crypto.createSign('SHA256');
  sign.update(signatureBase);
  sign.end();

  const signature = sign.sign(decodedPrivateKey);

  // Final assertion response
  const assertionResponse = {
    credentialId: credentialId,
    clientDataJSON: base64url(clientDataJSON),
    authenticatorData: base64url(authenticatorData),
    signature: base64url(signature),
    userHandle: null,
  };

  const finalOutput = {
    assertionId: assertionInput.assertionId,
    assertionResponse: JSON.stringify(assertionResponse),
  };

  await fs.writeFile('generated-assertion.json', JSON.stringify(finalOutput, null, 2));
  console.log('Assertion signed and saved to "generated-assertion.json"');
}

const assertionInputFile = 'assertion-input.txt'; // your input assertion challenge
const credentialSecretsFile = 'credential-secrets.json';

authenticateFromFile(assertionInputFile, credentialSecretsFile);
