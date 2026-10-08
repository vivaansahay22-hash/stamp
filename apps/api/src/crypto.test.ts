import crypto from 'node:crypto';
import { describe, expect, it } from 'vitest';

describe('cryptography', () => {
  it('creates and verifies an ECDSA signature', () => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
      namedCurve: 'prime256v1',
    });

    const payload = Buffer.from(JSON.stringify({ credentialId: 'vty_123', nonce: 'abc123', action: 'login' }));
    const signature = crypto.sign(null, payload, privateKey);

    expect(crypto.verify(null, payload, publicKey, signature)).toBe(true);
  });

  it('rejects an invalid signature', () => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
      namedCurve: 'prime256v1',
    });

    const payload = Buffer.from('signed payload');
    const signature = crypto.sign(null, payload, privateKey);
    const altered = Buffer.concat([signature.subarray(0, 10), Buffer.from([0x00]), signature.subarray(11)]);

    expect(crypto.verify(null, payload, publicKey, altered)).toBe(false);
  });
});
