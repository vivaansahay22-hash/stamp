import dotenv from 'dotenv';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import cors from 'cors';
import express, { type Express, type Request, type Response } from 'express';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import { z } from 'zod';
import { calculateRisk, decisionFromRisk, riskLevel } from './risk.js';

dotenv.config({ path: fileURLToPath(new URL('../../../.env', import.meta.url)) });

const PORT = Number(process.env.PORT ?? 3001);
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD ?? 'password';
const SESSION_SECRET = process.env.SESSION_SECRET ?? 'stamp-prototype-session-secret';
const ENROLLMENT_MIN_DURATION_SECONDS = Number(process.env.ENROLLMENT_MIN_DURATION_SECONDS ?? 600);
const ENROLLMENT_PASS_SCORE = Number(process.env.ENROLLMENT_PASS_SCORE ?? 0.8);
const RECAPTCHA_TEST_SITE_KEY = '6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI';
const RECAPTCHA_TEST_SECRET_KEY = '6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe';
const ENV_RECAPTCHA_SITE_KEY = process.env.RECAPTCHA_SITE_KEY ?? '';
const ENV_RECAPTCHA_SECRET_KEY = process.env.RECAPTCHA_SECRET_KEY ?? '';
const USE_RECAPTCHA_TEST_KEYS = process.env.NODE_ENV !== 'production' && !ENV_RECAPTCHA_SITE_KEY && !ENV_RECAPTCHA_SECRET_KEY;
const RECAPTCHA_SITE_KEY = ENV_RECAPTCHA_SITE_KEY || (USE_RECAPTCHA_TEST_KEYS ? RECAPTCHA_TEST_SITE_KEY : '');
const RECAPTCHA_SECRET_KEY = ENV_RECAPTCHA_SECRET_KEY || (USE_RECAPTCHA_TEST_KEYS ? RECAPTCHA_TEST_SECRET_KEY : '');
const RECAPTCHA_HOSTNAME = process.env.RECAPTCHA_HOSTNAME ?? '';
const RECAPTCHA_TEST_MODE = RECAPTCHA_SITE_KEY === RECAPTCHA_TEST_SITE_KEY && RECAPTCHA_SECRET_KEY === RECAPTCHA_TEST_SECRET_KEY;
const RECAPTCHA_ENABLED = Boolean(RECAPTCHA_SITE_KEY && RECAPTCHA_SECRET_KEY) && !(process.env.NODE_ENV === 'production' && RECAPTCHA_TEST_MODE);
const RECAPTCHA_REQUIRED = process.env.RECAPTCHA_REQUIRED === 'true' || process.env.NODE_ENV === 'production';

const app: Express = express();

app.use(cors({ origin: true, credentials: true }));
app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginResourcePolicy: { policy: 'cross-origin' },
  }),
);
app.use(express.json({ limit: '1mb' }));
app.use(
  rateLimit({
    windowMs: 60 * 1000,
    max: 120,
    standardHeaders: true,
    legacyHeaders: false,
    message: { ok: false, error: 'Too many requests. Please slow down.' },
  }),
);

const demoSiteId = 'stamp';

const state = {
  credentials: [] as Array<any>,
  enrollments: [] as Array<any>,
  verificationNonces: [] as Array<any>,
  verificationEvents: [] as Array<any>,
  riskEvents: [] as Array<any>,
  enrollmentSessions: new Map<string, { startedAt: number; challenges: ReturnType<typeof seededChallenges> }>(),
  sites: [
    {
      id: 'site_stamp',
      name: 'Stamp',
      siteId: demoSiteId,
    },
  ] as Array<any>,
  policies: [
    {
      id: 'policy_demo_store',
      siteId: demoSiteId,
      allowLowRisk: true,
      stepUpThreshold: 60,
      rateLimitThreshold: 80,
      riskTolerance: 70,
      updatedAt: new Date().toISOString(),
    },
  ] as Array<any>,
};

function nowIso() {
  return new Date().toISOString();
}

function clamp(value: number, min: number, max: number) {
  return Math.min(max, Math.max(min, value));
}

function credentialId() {
  return `vty_${crypto.randomBytes(6).toString('hex').slice(0, 8).toUpperCase()}`;
}

function nonceValue() {
  return crypto.randomBytes(16).toString('hex');
}

function getSitePolicy(siteId: string) {
  return (
    state.policies.find((policy) => policy.siteId === siteId) ?? {
      siteId,
      allowLowRisk: true,
      stepUpThreshold: 60,
      rateLimitThreshold: 80,
      riskTolerance: 70,
      updatedAt: new Date().toISOString(),
    }
  );
}

function getCredentialById(credentialIdValue: string) {
  return state.credentials.find((credential) => credential.id === credentialIdValue);
}

function createAdminToken() {
  const payload = Buffer.from(JSON.stringify({ expiresAt: Date.now() + 8 * 60 * 60 * 1000 })).toString('base64url');
  const signature = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');
  return `${payload}.${signature}`;
}

function isAdminTokenValid(token: string | undefined) {
  if (!token) return false;
  const [payload, providedSignature] = token.split('.');
  if (!payload || !providedSignature) return false;

  const expectedSignature = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest();
  let supplied: Buffer;
  try {
    supplied = Buffer.from(providedSignature, 'base64url');
  } catch {
    return false;
  }
  if (supplied.length !== expectedSignature.length || !crypto.timingSafeEqual(supplied, expectedSignature)) return false;

  try {
    const claims = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as { expiresAt?: number };
    return typeof claims.expiresAt === 'number' && claims.expiresAt > Date.now();
  } catch {
    return false;
  }
}

function ensureAdmin(req: Request, res: Response, next: () => void) {
  const authorization = req.headers.authorization;
  const token = authorization?.startsWith('Bearer ') ? authorization.slice(7) : undefined;
  if (!isAdminTokenValid(token)) {
    return res.status(401).json({ ok: false, error: 'Admin authorization required.' });
  }

  return next();
}

function seededChallenges() {
  return [
    {
      id: 'c1',
      category: 'sequence',
      prompt: 'What number comes next: 4, 8, 12, 16?',
      options: ['18', '20', '22', '24'],
      answer: '20',
    },
    {
      id: 'c2',
      category: 'everyday reasoning',
      prompt: 'You need to leave at 2:30 and the trip takes 25 minutes. When should you leave?',
      options: ['2:05', '2:15', '2:30', '2:55'],
      answer: '2:05',
    },
    {
      id: 'c3',
      category: 'classification',
      prompt: 'Which one is usually used to tell time?',
      options: ['Clock', 'Kettle', 'Pillow', 'Spoon'],
      answer: 'Clock',
    },
    {
      id: 'c4',
      category: 'reading',
      prompt: 'Mina put a blue book beside the lamp. What color was the book?',
      options: ['Blue', 'Green', 'Red', 'The passage does not say'],
      answer: 'Blue',
    },
    {
      id: 'c5',
      category: 'sequence',
      prompt: 'Which day follows Tuesday?',
      options: ['Monday', 'Wednesday', 'Thursday', 'Sunday'],
      answer: 'Wednesday',
    },
    {
      id: 'c6',
      category: 'practical reasoning',
      prompt: 'A recipe for 2 people uses 1 cup of rice. How much rice for 4 people?',
      options: ['1/2 cup', '1 cup', '2 cups', '4 cups'],
      answer: '2 cups',
    },
    {
      id: 'c7',
      category: 'classification',
      prompt: 'Which item is most likely to be found in a garden?',
      options: ['Shovel', 'Remote control', 'Toothbrush', 'Keyboard'],
      answer: 'Shovel',
    },
    {
      id: 'c8',
      category: 'attention to detail',
      prompt: 'The note says “take the north exit.” Which direction should you go?',
      options: ['North', 'South', 'East', 'West'],
      answer: 'North',
    },
    {
      id: 'c9',
      category: 'sequence',
      prompt: 'What comes next: January, February, March, ...?',
      options: ['April', 'June', 'August', 'December'],
      answer: 'April',
    },
    {
      id: 'c10',
      category: 'everyday reasoning',
      prompt: 'A glass is full of water. You drink half. What remains?',
      options: ['Half a glass', 'An empty glass', 'Two full glasses', 'The glass disappears'],
      answer: 'Half a glass',
    },
    {
      id: 'c11',
      category: 'comparison',
      prompt: 'Which is heavier: one kilogram of apples or one kilogram of rice?',
      options: ['Apples', 'Rice', 'They weigh the same', 'Cannot be compared'],
      answer: 'They weigh the same',
    },
    {
      id: 'c12',
      category: 'reading',
      prompt: 'A sign says “Library closes at six.” What time does it close?',
      options: ['4 o’clock', '5 o’clock', '6 o’clock', '7 o’clock'],
      answer: '6 o’clock',
    },
    {
      id: 'c13',
      category: 'practical reasoning',
      prompt: 'You have 3 apples and receive 2 more. How many apples do you have?',
      options: ['4', '5', '6', '8'],
      answer: '5',
    },
    {
      id: 'c14',
      category: 'classification',
      prompt: 'Which one is not a mode of transport?',
      options: ['Bicycle', 'Train', 'Bus', 'Sandwich'],
      answer: 'Sandwich',
    },
    {
      id: 'c15',
      category: 'sequence',
      prompt: 'What number comes next: 5, 10, 15, 20?',
      options: ['22', '24', '25', '30'],
      answer: '25',
    },
    {
      id: 'c16',
      category: 'attention to detail',
      prompt: 'A message reads “bring a warm coat and gloves.” Which item is mentioned?',
      options: ['Umbrella', 'Gloves', 'Sunglasses', 'Sandals'],
      answer: 'Gloves',
    },
    {
      id: 'c17',
      category: 'everyday reasoning',
      prompt: 'If it is raining and you want to stay dry outside, what is most useful?',
      options: ['An umbrella', 'A fan', 'A pillow', 'A plate'],
      answer: 'An umbrella',
    },
    {
      id: 'c18',
      category: 'comparison',
      prompt: 'Which container usually holds more: a mug or a swimming pool?',
      options: ['A mug', 'A swimming pool', 'They hold the same', 'Neither holds anything'],
      answer: 'A swimming pool',
    },
    {
      id: 'c19',
      category: 'reading',
      prompt: '“Leo called Sam after lunch.” Who made the call?',
      options: ['Leo', 'Sam', 'Both', 'The passage does not say'],
      answer: 'Leo',
    },
    {
      id: 'c20',
      category: 'practical reasoning',
      prompt: 'A bus arrives every 10 minutes. One just left. About how long until the next one?',
      options: ['About 2 minutes', 'About 10 minutes', 'About 1 hour', 'Tomorrow'],
      answer: 'About 10 minutes',
    },
    {
      id: 'c21',
      category: 'sequence',
      prompt: 'What number comes next: 3, 6, 9, 12?',
      options: ['13', '14', '15', '18'],
      answer: '15',
    },
    {
      id: 'c22',
      category: 'reading',
      prompt: 'A note says “the keys are inside the blue bowl.” Where are the keys?',
      options: ['In the blue bowl', 'Under the table', 'In a drawer', 'The note does not say'],
      answer: 'In the blue bowl',
    },
    {
      id: 'c23',
      category: 'practical reasoning',
      prompt: 'A 12-page document is split equally into 3 sections. How many pages per section?',
      options: ['3', '4', '6', '9'],
      answer: '4',
    },
    {
      id: 'c24',
      category: 'classification',
      prompt: 'Which one is normally used to write on paper?',
      options: ['Pencil', 'Plate', 'Scarf', 'Cup'],
      answer: 'Pencil',
    },
    {
      id: 'c25',
      category: 'comparison',
      prompt: 'Which is longer: 90 centimeters or 1 meter?',
      options: ['90 centimeters', '1 meter', 'They are equal', 'There is not enough information'],
      answer: '1 meter',
    },
    {
      id: 'c26',
      category: 'everyday reasoning',
      prompt: 'You are looking for a book title in a library. Which area is the best place to check first?',
      options: ['The book shelves', 'The café kitchen', 'The parking lot', 'The coat room'],
      answer: 'The book shelves',
    },
    {
      id: 'c27',
      category: 'attention to detail',
      prompt: 'A list reads “milk, oats, pears.” Which item is listed between the others?',
      options: ['Milk', 'Oats', 'Pears', 'None'],
      answer: 'Oats',
    },
    {
      id: 'c28',
      category: 'sequence',
      prompt: 'What number comes next: 30, 25, 20, 15?',
      options: ['5', '10', '12', '20'],
      answer: '10',
    },
    {
      id: 'c29',
      category: 'reading',
      prompt: '“Nora opened the window because the room felt warm.” Why did Nora open it?',
      options: ['The room felt warm', 'It was raining', 'She lost her keys', 'The passage does not say'],
      answer: 'The room felt warm',
    },
    {
      id: 'c30',
      category: 'practical reasoning',
      prompt: 'A 4-dollar item is paid for with a 10-dollar note. How much change is due?',
      options: ['4 dollars', '5 dollars', '6 dollars', '14 dollars'],
      answer: '6 dollars',
    },
    {
      id: 'c31',
      category: 'classification',
      prompt: 'Which one is a fruit?',
      options: ['Peach', 'Ladle', 'Notebook', 'Boot'],
      answer: 'Peach',
    },
    {
      id: 'c32',
      category: 'comparison',
      prompt: 'Which temperature is warmer: 18°C or 12°C?',
      options: ['18°C', '12°C', 'They are equal', 'Neither is a temperature'],
      answer: '18°C',
    },
    {
      id: 'c33',
      category: 'everyday reasoning',
      prompt: 'A friend asks you to bring a cold drink. Which choice best fits?',
      options: ['Chilled water', 'Hot soup', 'A blanket', 'A loaf of bread'],
      answer: 'Chilled water',
    },
    {
      id: 'c34',
      category: 'attention to detail',
      prompt: 'The appointment card says “Room 204, second floor.” Which room should you find?',
      options: ['Room 204', 'Room 240', 'Room 24', 'Room 402'],
      answer: 'Room 204',
    },
    {
      id: 'c35',
      category: 'sequence',
      prompt: 'What number comes next: 1, 3, 5, 7?',
      options: ['8', '9', '10', '11'],
      answer: '9',
    },
    {
      id: 'c36',
      category: 'reading',
      prompt: '“The red train arrived before the green train.” Which train arrived first?',
      options: ['Red', 'Green', 'Both together', 'The passage does not say'],
      answer: 'Red',
    },
    {
      id: 'c37',
      category: 'practical reasoning',
      prompt: 'A meeting starts at 9:00 and lasts 30 minutes. When does it end?',
      options: ['9:15', '9:30', '10:00', '10:30'],
      answer: '9:30',
    },
    {
      id: 'c38',
      category: 'classification',
      prompt: 'Which item is normally worn on your feet?',
      options: ['Socks', 'Gloves', 'Hat', 'Necklace'],
      answer: 'Socks',
    },
    {
      id: 'c39',
      category: 'comparison',
      prompt: 'Which amount is greater: 3 groups of 2 or 2 groups of 3?',
      options: ['3 groups of 2', '2 groups of 3', 'They are equal', 'Neither has a value'],
      answer: 'They are equal',
    },
    {
      id: 'c40',
      category: 'everyday reasoning',
      prompt: 'You want to send a paper letter. What do you usually need to put on the envelope?',
      options: ['A delivery address', 'A spoon', 'A shoe size', 'A recipe'],
      answer: 'A delivery address',
    },
  ];
}

function shuffle<T>(items: T[]) {
  const shuffled = [...items];
  for (let index = shuffled.length - 1; index > 0; index -= 1) {
    const swapIndex = crypto.randomInt(index + 1);
    [shuffled[index], shuffled[swapIndex]] = [shuffled[swapIndex], shuffled[index]];
  }
  return shuffled;
}

function publicChallenges(challenges: ReturnType<typeof seededChallenges>) {
  return challenges.map(({ answer: _answer, ...challenge }) => challenge);
}

async function verifyRecaptchaToken(token: string) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 8000);

  try {
    const response = await fetch('https://www.google.com/recaptcha/api/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ secret: RECAPTCHA_SECRET_KEY, response: token }),
      signal: controller.signal,
    });
    if (!response.ok) return false;

    const result = await response.json() as { success?: boolean; action?: string; hostname?: string };
    return Boolean(
      result.success &&
      (!RECAPTCHA_HOSTNAME || result.hostname === RECAPTCHA_HOSTNAME),
    );
  } catch {
    return false;
  } finally {
    clearTimeout(timeout);
  }
}

app.get('/api/enrollment/config', (_req: Request, res: Response) => {
  const partialConfig = Boolean(RECAPTCHA_SITE_KEY) !== Boolean(RECAPTCHA_SECRET_KEY);
  res.json({
    recaptchaEnabled: RECAPTCHA_ENABLED,
    recaptchaRequired: RECAPTCHA_ENABLED || partialConfig || RECAPTCHA_REQUIRED,
    recaptchaTestMode: RECAPTCHA_TEST_MODE,
    siteKey: RECAPTCHA_ENABLED ? RECAPTCHA_SITE_KEY : null,
  });
});

app.get('/api/health', (_req: Request, res: Response) => {
  res.json({ ok: true, status: 'healthy', timestamp: new Date().toISOString() });
});

app.post('/api/admin/login', (req: Request, res: Response) => {
  const parsed = z.object({ password: z.string().min(1) }).safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ ok: false, error: 'Password is required.' });
  }

  const expected = Buffer.from(ADMIN_PASSWORD);
  const received = Buffer.from(parsed.data.password);
  if (expected.length !== received.length || !crypto.timingSafeEqual(expected, received)) {
    return res.status(401).json({ ok: false, error: 'Incorrect password.' });
  }

  return res.json({ ok: true, token: createAdminToken(), expiresInSeconds: 8 * 60 * 60 });
});

app.get('/api/sites', (_req: Request, res: Response) => {
  res.json({ ok: true, sites: state.sites });
});

app.post('/api/sites', (req: Request, res: Response) => {
  const schema = z.object({ name: z.string().min(2), siteId: z.string().min(2) });
  const parsed = schema.safeParse(req.body);

  if (!parsed.success) {
    return res.status(400).json({ ok: false, error: parsed.error.flatten() });
  }

  const site = { id: `site_${crypto.randomBytes(5).toString('hex')}`, ...parsed.data };
  state.sites.push(site);
  state.policies.push({
    id: `policy_${crypto.randomBytes(5).toString('hex')}`,
    siteId: site.siteId,
    allowLowRisk: true,
    stepUpThreshold: 60,
    rateLimitThreshold: 80,
    riskTolerance: 70,
    updatedAt: new Date().toISOString(),
  });

  return res.status(201).json({ ok: true, site });
});

app.get('/api/sites/:id/policy', (req: Request, res: Response) => {
  const siteId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
  return res.json({ ok: true, policy: getSitePolicy(siteId) });
});

app.put('/api/sites/:id/policy', ensureAdmin, (req: Request, res: Response) => {
  const siteId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
  const schema = z.object({
    allowLowRisk: z.boolean().optional(),
    stepUpThreshold: z.number().int().min(0).max(100).optional(),
    rateLimitThreshold: z.number().int().min(0).max(100).optional(),
    riskTolerance: z.number().int().min(0).max(100).optional(),
  });

  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ ok: false, error: parsed.error.flatten() });
  }

  const existing = getSitePolicy(siteId);
  const nextPolicy = {
    ...existing,
    ...parsed.data,
    updatedAt: new Date().toISOString(),
  };

  const idx = state.policies.findIndex((policy) => policy.siteId === siteId);
  if (idx >= 0) state.policies[idx] = nextPolicy;
  else state.policies.push(nextPolicy);

  return res.json({ ok: true, policy: nextPolicy });
});

app.post('/api/enrollment/start', async (req: Request, res: Response) => {
  const parsed = z.object({ captchaToken: z.string().min(1).max(8192).optional() }).safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ ok: false, error: 'Invalid CAPTCHA token.' });

  if (Boolean(RECAPTCHA_SITE_KEY) !== Boolean(RECAPTCHA_SECRET_KEY)) {
    return res.status(503).json({ ok: false, error: 'reCAPTCHA is partially configured. Set both public and secret keys.' });
  }
  if (RECAPTCHA_REQUIRED && !RECAPTCHA_ENABLED) {
    return res.status(503).json({ ok: false, error: 'reCAPTCHA is required but its keys are not configured.' });
  }
  if (RECAPTCHA_ENABLED) {
    if (!parsed.data.captchaToken || !(await verifyRecaptchaToken(parsed.data.captchaToken))) {
      return res.status(403).json({ ok: false, error: 'reCAPTCHA verification failed or expired. Please complete it again.' });
    }
  }

  const challenges = shuffle(seededChallenges()).slice(0, 20).map((challenge) => ({
    ...challenge,
    options: shuffle(challenge.options),
  }));
  const enrollmentId = crypto.randomBytes(24).toString('base64url');
  state.enrollmentSessions.set(enrollmentId, { startedAt: Date.now(), challenges });

  res.json({
    ok: true,
    enrollmentId,
    estimatedDurationSeconds: ENROLLMENT_MIN_DURATION_SECONDS,
    passScore: ENROLLMENT_PASS_SCORE,
    challenges: publicChallenges(challenges),
  });
});

app.post('/api/enrollment/challenge', (req: Request, res: Response) => {
  const schema = z.object({ index: z.number().int().nonnegative().optional() });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ ok: false, error: parsed.error.flatten() });
  }

  const challenge = seededChallenges()[parsed.data.index ?? 0];
  if (!challenge) return res.status(404).json({ ok: false, error: 'Challenge not found.' });
  return res.json({ ok: true, challenge: publicChallenges([challenge])[0] });
});

app.post('/api/enrollment/complete', (req: Request, res: Response) => {
  const schema = z.object({
    enrollmentId: z.string().min(1),
    responses: z.array(
      z.object({
        id: z.string(),
        answer: z.string(),
      }),
    ).length(20),
  });

  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ ok: false, error: parsed.error.flatten() });
  }

  const session = state.enrollmentSessions.get(parsed.data.enrollmentId);
  if (!session) {
    return res.status(410).json({ ok: false, error: 'Enrollment session expired or already completed.' });
  }
  const expectedIds = new Set(session.challenges.map((challenge) => challenge.id));
  const submittedIds = parsed.data.responses.map((response) => response.id);
  if (new Set(submittedIds).size !== session.challenges.length || submittedIds.some((id) => !expectedIds.has(id))) {
    return res.status(400).json({ ok: false, error: 'Answer each enrollment question exactly once.' });
  }
  state.enrollmentSessions.delete(parsed.data.enrollmentId);

  const durationMs = Date.now() - session.startedAt;
  const score = parsed.data.responses.reduce((total, response) => {
    const match = session.challenges.find((challenge) => challenge.id === response.id);
    if (!match) return total;
    return total + (match.answer === response.answer ? 1 : 0);
  }, 0);
  const normalizedScore = score / session.challenges.length;
  const passed = normalizedScore >= ENROLLMENT_PASS_SCORE && durationMs >= ENROLLMENT_MIN_DURATION_SECONDS * 1000;

  state.enrollments.push({
    id: `enrollment_${crypto.randomBytes(6).toString('hex')}`,
    score: normalizedScore,
    durationSeconds: Math.round(durationMs / 1000),
    passed,
    createdAt: nowIso(),
  });

  return res.json({
    ok: true,
    passed,
    score: normalizedScore,
    durationMs,
    minimumDurationSeconds: ENROLLMENT_MIN_DURATION_SECONDS,
    message: passed
      ? 'Enrollment succeeded. A pseudonymous credential can now be generated on-device.'
      : 'Enrollment failed or was too rapid. A fresh credential can be attempted later.',
  });
});

app.post('/api/credentials/register', (req: Request, res: Response) => {
  const schema = z.object({
    credentialId: z.string().optional(),
    publicKey: z.any(),
    status: z.string().optional(),
  });

  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ ok: false, error: parsed.error.flatten() });
  }

  const generatedId = parsed.data.credentialId ?? credentialId();
  const existing = getCredentialById(generatedId);
  if (existing) {
    return res.status(409).json({ ok: false, error: 'Credential already exists.' });
  }

  const credential = {
    id: generatedId,
    publicKey: typeof parsed.data.publicKey === 'string' ? parsed.data.publicKey : JSON.stringify(parsed.data.publicKey),
    status: parsed.data.status ?? 'active',
    issuedAt: nowIso(),
    expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(),
    createdAt: nowIso(),
    updatedAt: nowIso(),
    requestCount: 0,
    failureCount: 0,
  };

  state.credentials.push(credential);

  return res.status(201).json({
    ok: true,
    credential,
    message: 'Credential registered securely. Private key remains local to the browser.',
  });
});

app.post('/api/credentials/rotate', (req: Request, res: Response) => {
  const schema = z.object({ oldCredentialId: z.string(), newPublicKey: z.any() });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ ok: false, error: parsed.error.flatten() });
  }

  const oldCredential = getCredentialById(parsed.data.oldCredentialId);
  if (!oldCredential) {
    return res.status(404).json({ ok: false, error: 'Credential not found.' });
  }

  oldCredential.status = 'rotated';
  const rotated = {
    id: credentialId(),
    publicKey: typeof parsed.data.newPublicKey === 'string' ? parsed.data.newPublicKey : JSON.stringify(parsed.data.newPublicKey),
    status: 'active',
    issuedAt: nowIso(),
    expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(),
    createdAt: nowIso(),
    updatedAt: nowIso(),
    requestCount: 0,
    failureCount: 0,
  };

  state.credentials.push(rotated);

  return res.json({ ok: true, oldCredentialId: oldCredential.id, rotatedCredential: rotated });
});

app.get('/api/credentials/:id/status', (req: Request, res: Response) => {
  const credentialIdValue = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
  const credential = getCredentialById(credentialIdValue);
  if (!credential) {
    return res.status(404).json({ ok: false, error: 'Credential not found.' });
  }

  return res.json({ ok: true, credential: { id: credential.id, status: credential.status, expiresAt: credential.expiresAt } });
});

app.post('/api/verify/nonce', (req: Request, res: Response) => {
  const schema = z.object({ credentialId: z.string(), siteId: z.string(), action: z.string() });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ ok: false, error: parsed.error.flatten() });
  }

  const credential = getCredentialById(parsed.data.credentialId);
  if (!credential) {
    return res.status(404).json({ ok: false, error: 'Credential not found.' });
  }

  const nonce = {
    id: `nonce_${crypto.randomBytes(6).toString('hex')}`,
    credentialId: parsed.data.credentialId,
    siteId: parsed.data.siteId,
    action: parsed.data.action,
    nonce: nonceValue(),
    createdAt: Date.now(),
    expiresAt: Date.now() + 60 * 1000,
  };

  state.verificationNonces.push(nonce);

  return res.json({
    ok: true,
    nonce: nonce.nonce,
    timestamp: Date.now(),
    expiresAt: nonce.expiresAt,
  });
});

app.post('/api/verify', (req: Request, res: Response) => {
  const schema = z.object({
    credentialId: z.string(),
    siteId: z.string(),
    action: z.string(),
    nonce: z.string(),
    timestamp: z.number(),
    signature: z.string(),
    publicKey: z.any(),
  });

  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ ok: false, error: parsed.error.flatten() });
  }

  const credential = getCredentialById(parsed.data.credentialId);
  if (!credential) {
    return res.status(404).json({ ok: false, error: 'Credential not found.' });
  }

  if (credential.status !== 'active') {
    return res.status(403).json({ ok: false, error: 'Credential is inactive or expired.' });
  }

  const nonceRecord = state.verificationNonces.find(
    (item) => item.nonce === parsed.data.nonce && item.credentialId === parsed.data.credentialId,
  );

  if (!nonceRecord) {
    state.riskEvents.push({
      id: `risk_${crypto.randomBytes(5).toString('hex')}`,
      credentialId: parsed.data.credentialId,
      type: 'replay',
      severity: 'HIGH',
      timestamp: nowIso(),
      metadata: { nonce: parsed.data.nonce },
    });
    return res.status(409).json({ ok: false, decision: 'BLOCK', reason: 'Nonce rejected or replay detected.' });
  }

  if (Date.now() > nonceRecord.expiresAt) {
    return res.status(410).json({ ok: false, decision: 'BLOCK', reason: 'Nonce expired.' });
  }

  try {
    const payload = JSON.stringify({
      credentialId: parsed.data.credentialId,
      nonce: parsed.data.nonce,
      timestamp: parsed.data.timestamp,
      siteId: parsed.data.siteId,
      action: parsed.data.action,
    });

    const publicKey = parsed.data.publicKey;
    const key = crypto.createPublicKey({
      key: publicKey,
      format: 'jwk',
    });

    const valid = crypto.verify(null, Buffer.from(payload), key, Buffer.from(parsed.data.signature, 'base64'));
    if (!valid) {
      credential.failureCount = (credential.failureCount ?? 0) + 1;
      state.riskEvents.push({
        id: `risk_${crypto.randomBytes(5).toString('hex')}`,
        credentialId: parsed.data.credentialId,
        type: 'signature_failure',
        severity: 'MEDIUM',
        timestamp: nowIso(),
        metadata: { action: parsed.data.action },
      });
      return res.status(403).json({ ok: false, decision: 'BLOCK', reason: 'Signature verification failed.' });
    }

    nonceRecord.usedAt = Date.now();
    const recent = state.verificationEvents.filter(
      (event) => event.credentialId === parsed.data.credentialId && Date.now() - new Date(event.timestamp).getTime() < 60_000,
    );

    const riskScore = calculateRisk({
      requestRate: recent.length,
      burst: recent.filter((event) => event.action === 'checkout').length,
      failureCount: credential.failureCount ?? 0,
      replayAttempts: state.riskEvents.filter((event) => event.credentialId === parsed.data.credentialId && event.type === 'replay').length,
      credentialValidity: true,
      suspiciousPatterns: Math.max(0, recent.length - 3),
    });

    const policy = getSitePolicy(parsed.data.siteId);
    const decision = decisionFromRisk(riskScore);
    const result = {
      ok: true,
      decision,
      riskScore,
      riskLevel: riskLevel(riskScore),
      credentialId: parsed.data.credentialId,
      siteId: parsed.data.siteId,
      action: parsed.data.action,
      timestamp: Date.now(),
      nonce: parsed.data.nonce,
    };

    credential.requestCount = (credential.requestCount ?? 0) + 1;
    state.verificationEvents.push({
      id: `verify_${crypto.randomBytes(5).toString('hex')}`,
      credentialId: parsed.data.credentialId,
      siteId: parsed.data.siteId,
      action: parsed.data.action,
      timestamp: nowIso(),
      riskScore,
      decision,
    });

    if (decision !== 'ALLOW') {
      state.riskEvents.push({
        id: `risk_${crypto.randomBytes(5).toString('hex')}`,
        credentialId: parsed.data.credentialId,
        type: decision.toLowerCase(),
        severity: riskLevel(riskScore),
        timestamp: nowIso(),
        metadata: { siteId: parsed.data.siteId, action: parsed.data.action },
      });
    }

    return res.json(result);
  } catch (error) {
    console.error('Verification failed', error);
    return res.status(400).json({ ok: false, decision: 'BLOCK', reason: 'Invalid request or public key.' });
  }
});

app.get('/api/dashboard/overview', ensureAdmin, (_req: Request, res: Response) => {
  const totalRequests = state.verificationEvents.length;
  const verifiedRequests = state.verificationEvents.filter((event) => event.decision === 'ALLOW').length;
  const suspiciousRequests = state.verificationEvents.filter((event) => event.decision !== 'ALLOW').length;
  const blockedRequests = state.verificationEvents.filter((event) => event.decision === 'BLOCK').length;
  const activeCredentials = state.credentials.filter((credential) => credential.status === 'active').length;
  const enrollments = state.enrollments.length;

  res.json({
    ok: true,
    overview: {
      totalRequests,
      verifiedRequests,
      suspiciousRequests,
      blockedRequests,
      activeCredentials,
      enrollments,
    },
  });
});

app.get('/api/dashboard/events', ensureAdmin, (_req: Request, res: Response) => {
  const events = [...state.riskEvents, ...state.verificationEvents]
    .map((event) => ({
      id: event.id,
      type: event.type ?? 'Credential verified',
      severity: event.severity ?? riskLevel(event.riskScore ?? 0),
      timestamp: event.timestamp ?? nowIso(),
      siteId: event.siteId ?? 'n/a',
      credentialId: event.credentialId ?? 'n/a',
      decision: event.decision ?? 'ALLOW',
    }))
    .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
    .slice(0, 40);

  res.json({ ok: true, events });
});

app.get('/api/dashboard/risk', ensureAdmin, (_req: Request, res: Response) => {
  const summary = { LOW: 0, MEDIUM: 0, HIGH: 0, EXTREME: 0 };
  for (const event of state.verificationEvents) {
    const level = riskLevel(event.riskScore);
    summary[level] += 1;
  }

  const attack = state.riskEvents.some((event) => event.type?.toLowerCase().includes('bot')) ? 'Burst bot' : 'Normal traffic';

  res.json({
    ok: true,
    summary,
    attack,
  });
});

app.post('/api/demo/attack', ensureAdmin, (req: Request, res: Response) => {
  const schema = z.object({ profile: z.enum(['normal-user', 'naive-bot', 'credential-farmer', 'replay-attacker', 'distributed-attacker', 'low-and-slow-bot', 'burst-bot']) });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ ok: false, error: parsed.error.flatten() });
  }

  const profile = parsed.data.profile;
  const simulations: Record<string, any> = {
    'normal-user': { requests: 8, rate: 3, risk: 18 },
    'naive-bot': { requests: 40, rate: 17, risk: 68 },
    'credential-farmer': { requests: 80, rate: 22, risk: 74 },
    'replay-attacker': { requests: 16, rate: 8, risk: 82 },
    'distributed-attacker': { requests: 70, rate: 30, risk: 77 },
    'low-and-slow-bot': { requests: 25, rate: 5, risk: 41 },
    'burst-bot': { requests: 90, rate: 70, risk: 89 },
  };

  const selected = simulations[profile];
  const decisionCounts = { allowed: 0, challenged: 0, rateLimited: 0, blocked: 0 };

  for (let index = 0; index < selected.requests; index += 1) {
    const decision = index < selected.requests * 0.5 ? 'ALLOWED' : index < selected.requests * 0.7 ? 'CHALLENGED' : index < selected.requests * 0.9 ? 'RATE LIMITED' : 'BLOCKED';
    const risk = selected.risk + Math.min(20, index / 4);
    const mapped = decision.toUpperCase().replace(' ', '_');
    if (mapped === 'ALLOWED') decisionCounts.allowed += 1;
    if (mapped === 'CHALLENGED') decisionCounts.challenged += 1;
    if (mapped === 'RATE_LIMITED') decisionCounts.rateLimited += 1;
    if (mapped === 'BLOCKED') decisionCounts.blocked += 1;

    state.verificationEvents.push({
      id: `attack_${crypto.randomBytes(5).toString('hex')}`,
      credentialId: 'demo_attack',
      siteId: demoSiteId,
      action: 'campaign',
      timestamp: nowIso(),
      riskScore: Math.round(risk),
      decision: mapped,
    });
  }

  state.riskEvents.push({
    id: `attack_risk_${crypto.randomBytes(5).toString('hex')}`,
    credentialId: 'demo_attack',
    type: profile,
    severity: 'HIGH',
    timestamp: nowIso(),
    metadata: { requests: selected.requests, rate: selected.rate, risk: selected.risk },
  });

  return res.json({
    ok: true,
    profile,
    requests: selected.requests,
    requestsPerSecond: selected.rate,
    riskScore: selected.risk,
    verificationResults: decisionCounts,
  });
});

app.post('/api/demo/reset', ensureAdmin, (_req: Request, res: Response) => {
  state.verificationEvents.length = 0;
  state.riskEvents.length = 0;
  state.verificationNonces.length = 0;
  state.credentials.length = 0;
  state.enrollments.length = 0;
  state.credentials.push({
    id: 'demo_credential',
    publicKey: 'demo-public-key',
    status: 'active',
    issuedAt: nowIso(),
    expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(),
    createdAt: nowIso(),
    updatedAt: nowIso(),
    requestCount: 0,
    failureCount: 0,
  });

  return res.json({ ok: true, message: 'Demo data reset.' });
});

app.get('/api/demo/products', (_req: Request, res: Response) => {
  res.json({
    ok: true,
    products: [
      { id: 'p1', name: 'Halo Desk Lamp', price: 129, category: 'home' },
      { id: 'p2', name: 'Pulse Headphones', price: 249, category: 'audio' },
      { id: 'p3', name: 'Aster Coffee Kit', price: 79, category: 'kitchen' },
      { id: 'p4', name: 'North Travel Pack', price: 170, category: 'travel' },
    ],
  });
});

app.use((_req: Request, res: Response) => {
  res.status(404).json({ ok: false, error: 'Route not found.' });
});

app.listen(PORT, () => {
  console.log(`Stamp API listening on http://localhost:${PORT}`);
});
