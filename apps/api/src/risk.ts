export function clamp(value: number, min: number, max: number) {
  return Math.min(max, Math.max(min, value));
}

export function riskLevel(score: number) {
  if (score <= 29) return 'LOW';
  if (score <= 59) return 'MEDIUM';
  if (score <= 79) return 'HIGH';
  return 'EXTREME';
}

export function decisionFromRisk(score: number) {
  if (score < 30) return 'ALLOW';
  if (score < 60) return 'SILENT_MONITOR';
  if (score < 80) return 'STEP_UP';
  if (score < 90) return 'RATE_LIMIT';
  return 'BLOCK';
}

export function calculateRisk(signals: {
  requestRate: number;
  burst: number;
  failureCount: number;
  replayAttempts: number;
  credentialValidity: boolean;
  suspiciousPatterns: number;
}) {
  const risk =
    (signals.credentialValidity ? 0 : 15) +
    clamp(signals.requestRate * 8, 0, 25) +
    clamp(signals.burst * 12, 0, 25) +
    clamp(signals.failureCount * 10, 0, 20) +
    clamp(signals.replayAttempts * 20, 0, 30) +
    clamp(signals.suspiciousPatterns * 10, 0, 25);

  return clamp(Math.round(risk), 0, 100);
}
