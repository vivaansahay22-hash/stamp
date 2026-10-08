export type JsonWebKeyLike = Record<string, string>;
export type VerityVerifyOptions = {
    action: string;
    siteId?: string;
    credentialId?: string;
};
export type VerityVerifyResponse = {
    ok: boolean;
    decision: 'ALLOW' | 'SILENT_MONITOR' | 'STEP_UP' | 'RATE_LIMIT' | 'BLOCK' | string;
    riskScore: number;
    riskLevel: string;
    credentialId?: string;
    siteId?: string;
    action?: string;
    timestamp?: number;
    reason?: string;
};
export declare class Verity {
    siteId: string;
    apiBase: string;
    constructor({ siteId, apiBase }: {
        siteId: string;
        apiBase?: string;
    });
    getCredential(): {
        id: string;
        publicKey: JsonWebKeyLike;
    } | null;
    private getPrivateKey;
    static generateCredential(): Promise<{
        id: string;
        publicKey: JsonWebKey;
        privateKey: JsonWebKey;
    }>;
    verify({ action, siteId, credentialId }: VerityVerifyOptions): Promise<VerityVerifyResponse>;
}
