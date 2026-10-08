function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let index = 0; index < bytes.byteLength; index += 1) {
        binary += String.fromCharCode(bytes[index]);
    }
    return btoa(binary);
}
export class Verity {
    siteId;
    apiBase;
    constructor({ siteId, apiBase = '/api' }) {
        this.siteId = siteId;
        this.apiBase = apiBase;
    }
    getCredential() {
        const raw = globalThis.localStorage?.getItem('verity_credential');
        if (!raw)
            return null;
        try {
            return JSON.parse(raw);
        }
        catch {
            return null;
        }
    }
    getPrivateKey() {
        const raw = globalThis.localStorage?.getItem('verity_private_key');
        if (!raw)
            return null;
        try {
            return JSON.parse(raw);
        }
        catch {
            return null;
        }
    }
    static async generateCredential() {
        const keyPair = await crypto.subtle.generateKey({
            name: 'ECDSA',
            namedCurve: 'P-256',
        }, true, ['sign', 'verify']);
        const privateKey = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
        const publicKey = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
        const credentialId = `vty_${crypto.getRandomValues(new Uint8Array(4)).reduce((acc, value) => acc + value.toString(16).padStart(2, '0'), '').slice(0, 8).toUpperCase()}`;
        localStorage.setItem('verity_private_key', JSON.stringify(privateKey));
        localStorage.setItem('verity_credential', JSON.stringify({ id: credentialId, publicKey }));
        return {
            id: credentialId,
            publicKey,
            privateKey,
        };
    }
    async verify({ action, siteId = this.siteId, credentialId }) {
        const credential = this.getCredential();
        if (!credential) {
            return { ok: false, decision: 'BLOCK', riskScore: 100, riskLevel: 'EXTREME', reason: 'No credential found for this browser.' };
        }
        const resolvedCredentialId = credentialId ?? credential.id;
        const nonceResponse = await fetch(`${this.apiBase}/verify/nonce`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ credentialId: resolvedCredentialId, siteId, action }),
        });
        const nonceData = await nonceResponse.json();
        if (!nonceResponse.ok) {
            return { ok: false, decision: 'BLOCK', riskScore: 100, riskLevel: 'EXTREME', reason: nonceData.error ?? 'Could not obtain nonce.' };
        }
        const privateKey = this.getPrivateKey();
        if (!privateKey) {
            return { ok: false, decision: 'BLOCK', riskScore: 100, riskLevel: 'EXTREME', reason: 'Private key not available in secure storage.' };
        }
        const payload = JSON.stringify({
            credentialId: resolvedCredentialId,
            nonce: nonceData.nonce,
            timestamp: nonceData.timestamp,
            siteId,
            action,
        });
        const importedCryptoKey = await crypto.subtle.importKey('jwk', privateKey, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
        const signatureBuffer = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, importedCryptoKey, new TextEncoder().encode(payload));
        const response = await fetch(`${this.apiBase}/verify`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                credentialId: resolvedCredentialId,
                siteId,
                action,
                nonce: nonceData.nonce,
                timestamp: nonceData.timestamp,
                signature: arrayBufferToBase64(signatureBuffer),
                publicKey: credential.publicKey,
            }),
        });
        return (await response.json());
    }
}
