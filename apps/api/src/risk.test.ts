import { describe, expect, it } from 'vitest';
import { calculateRisk, decisionFromRisk, riskLevel } from './risk.js';

describe('risk engine', () => {
  it('keeps low traffic low risk', () => {
    const score = calculateRisk({
      requestRate: 1,
      burst: 0,
      failureCount: 0,
      replayAttempts: 0,
      credentialValidity: true,
      suspiciousPatterns: 0,
    });

    expect(score).toBeLessThanOrEqual(29);
    expect(riskLevel(score)).toBe('LOW');
  });

  it('escalates on burst traffic', () => {
    const score = calculateRisk({
      requestRate: 10,
      burst: 4,
      failureCount: 0,
      replayAttempts: 0,
      credentialValidity: true,
      suspiciousPatterns: 4,
    });

    expect(score).toBeGreaterThan(59);
    expect(decisionFromRisk(score)).toBe('STEP_UP');
  });

  it('blocks replay attempts', () => {
    const score = calculateRisk({
      requestRate: 4,
      burst: 1,
      failureCount: 2,
      replayAttempts: 2,
      credentialValidity: true,
      suspiciousPatterns: 3,
    });

    expect(score).toBeGreaterThan(79);
    expect(decisionFromRisk(score)).toBe('BLOCK');
  });
});
