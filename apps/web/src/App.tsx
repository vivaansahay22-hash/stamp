import { type FormEvent, useEffect, useRef, useState } from 'react';
import { Link, Route, Routes } from 'react-router-dom';
import { Verity } from '@verity/sdk';

const API_URL = import.meta.env.VITE_API_URL ?? '/api';

type RecaptchaApi = {
  ready: (callback: () => void) => void;
  render: (container: HTMLElement, options: {
    sitekey: string;
    theme: 'dark';
    callback: (token: string) => void;
    'error-callback': () => void;
    'expired-callback': () => void;
  }) => number;
  reset: (widgetId?: number) => void;
};

declare global {
  interface Window {
    grecaptcha?: RecaptchaApi;
  }
}

type AttackProfile =
  | 'normal-user'
  | 'naive-bot'
  | 'credential-farmer'
  | 'replay-attacker'
  | 'distributed-attacker'
  | 'low-and-slow-bot'
  | 'burst-bot';

const navItems = [
  { to: '/', label: 'Home' },
  { to: '/enroll', label: 'Enroll' },
  { to: '/admin', label: 'Admin' },
  { to: '/privacy', label: 'Privacy' },
];

async function generateKeyPairAndRegister() {
  const credential = await Verity.generateCredential();

  const response = await fetch(`${API_URL}/credentials/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      credentialId: credential.id,
      publicKey: credential.publicKey,
      status: 'active',
    }),
  });

  const result = await response.json();
  if (!response.ok) {
    throw new Error(result.error ?? 'Unable to register credential.');
  }

  return result.credential;
}

function App() {
  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <header className="sticky top-0 z-20 border-b border-slate-800 bg-slate-950/80 backdrop-blur">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-5 py-4">
          <Link to="/" className="flex items-center gap-3 text-lg font-semibold tracking-tight text-white">
            <span className="flex h-9 w-9 items-center justify-center rounded-xl bg-brand text-sm font-black text-slate-950">S</span>
            Stamp
          </Link>
          <nav className="hidden items-center gap-6 md:flex">
            {navItems.map((item) => (
              <Link key={item.to} to={item.to} className="text-sm text-slate-300 transition hover:text-white">
                {item.label}
              </Link>
            ))}
          </nav>
          <Link to="/enroll" className="btn-primary ml-4 text-sm">
            Create Credential
          </Link>
        </div>
      </header>

      <main>
        <Routes>
          <Route path="/" element={<LandingPage />} />
          <Route path="/enroll" element={<EnrollPage />} />
          <Route path="/admin" element={<AdminPanel />} />
          <Route path="/privacy" element={<PrivacyPage />} />
        </Routes>
      </main>
    </div>
  );
}

function LandingPage() {
  return (
    <div className="mx-auto max-w-7xl px-5 py-12 md:py-16">
      <section className="grid items-center gap-10 py-10 md:grid-cols-2 md:py-16">
        <div>
          <div className="mb-4 inline-flex items-center rounded-full border border-cyan-500/30 bg-cyan-500/10 px-3 py-1 text-xs font-semibold uppercase tracking-[0.22em] text-cyan-300">
            The CAPTCHA that never was
          </div>
          <h1 className="max-w-xl text-4xl font-black tracking-tight text-white md:text-6xl">
            Replace repeated human checks with one-time trust and adaptive anti-abuse.
          </h1>
          <p className="mt-6 max-w-xl text-lg text-slate-300">
            Stamp replaces repeated human tests with one-time enrollment and invisible, risk-adaptive verification.
          </p>
          <div className="mt-8 flex flex-wrap items-center gap-4">
            <Link to="/enroll" className="btn-primary">
              Create Credential
            </Link>
            <Link to="/admin" className="btn-secondary">
              See the Attack Demo
            </Link>
          </div>
        </div>

        <div className="card p-6">
          <div className="mb-6 flex items-center justify-between">
            <span className="text-sm font-medium text-slate-300">Verification model</span>
            <span className="rounded-full border border-emerald-500/40 bg-emerald-500/10 px-2 py-1 text-xs text-emerald-300">Active</span>
          </div>
          <div className="space-y-4">
            {[
              'ONE-TIME ENROLLMENT',
              'CRYPTOGRAPHIC CREDENTIAL',
              'SILENT VERIFICATION',
              'RISK ENGINE',
              'ADAPTIVE RESPONSE',
            ].map((step, index) => (
              <div key={step} className="flex items-center gap-4 rounded-xl border border-slate-800 bg-slate-900/60 p-3">
                <div className="flex h-8 w-8 items-center justify-center rounded-full bg-brand text-sm font-bold text-slate-950">
                  {index + 1}
                </div>
                <span className="text-sm uppercase tracking-[0.18em] text-slate-200">{step}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="grid gap-6 py-8 md:grid-cols-3">
        <div className="card p-6">
          <p className="label">The problem</p>
          <h3 className="text-2xl font-bold text-white">Bots scale cheaply.</h3>
          <p className="mt-3 text-slate-300">Humans repeatedly pay the friction cost while abusive automation multiplies at near-zero marginal cost.</p>
        </div>
        <div className="card p-6">
          <p className="label">The model</p>
          <h3 className="text-2xl font-bold text-white">One-time enrollment.</h3>
          <p className="mt-3 text-slate-300">A single manageable challenge creates a pseudonymous anti-abuse credential instead of repeated daily proof.</p>
        </div>
        <div className="card p-6">
          <p className="label">Why it is different</p>
          <h3 className="text-2xl font-bold text-white">Stamp changes the verification model entirely.</h3>
          <p className="mt-3 text-slate-300">The system asks whether behavior looks trustworthy, not whether a user can solve the same test again and again.</p>
        </div>
      </section>
    </div>
  );
}

function EnrollPage() {
  const [challenges, setChallenges] = useState<any[]>([]);
  const [enrollmentId, setEnrollmentId] = useState('');
  const [captchaConfig, setCaptchaConfig] = useState<{ enabled: boolean; required: boolean; testMode: boolean; siteKey: string | null }>({
    enabled: false,
    required: false,
    testMode: false,
    siteKey: null,
  });
  const [captchaToken, setCaptchaToken] = useState('');
  const captchaContainer = useRef<HTMLDivElement>(null);
  const captchaWidgetId = useRef<number | null>(null);
  const [step, setStep] = useState(0);
  const [responses, setResponses] = useState<Record<string, string>>({});
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState('');
  const [isWorking, setIsWorking] = useState(false);

  useEffect(() => {
    fetch(`${API_URL}/enrollment/config`)
      .then(async (response) => {
        const data = await response.json();
        if (!response.ok) throw new Error(data.error ?? 'Unable to load enrollment settings.');
        setCaptchaConfig({
          enabled: Boolean(data.recaptchaEnabled),
          required: Boolean(data.recaptchaRequired),
          testMode: Boolean(data.recaptchaTestMode),
          siteKey: data.siteKey ?? null,
        });
      })
      .catch(() => setError('Unable to load enrollment CAPTCHA settings.'));
  }, []);

  useEffect(() => {
    if (!captchaConfig.enabled || !captchaConfig.siteKey || !captchaContainer.current) return;

    let disposed = false;
    let renderQueued = false;
    const renderWidget = () => {
      const recaptcha = window.grecaptcha;
      if (disposed || renderQueued || !recaptcha || typeof recaptcha.ready !== 'function' || !captchaContainer.current) return;
      renderQueued = true;

      recaptcha.ready(() => {
        if (disposed || !captchaContainer.current) return;
        if (typeof recaptcha.render !== 'function') {
          renderQueued = false;
          setError('reCAPTCHA did not finish loading. Refresh the page and try again.');
          return;
        }

        try {
          captchaWidgetId.current = recaptcha.render(captchaContainer.current, {
            sitekey: captchaConfig.siteKey!,
            theme: 'dark',
            callback: (token) => {
              setCaptchaToken(token);
              setError('');
            },
            'error-callback': () => {
              setCaptchaToken('');
              setError('reCAPTCHA could not load. Confirm this site key is registered for the current hostname.');
            },
            'expired-callback': () => {
              setCaptchaToken('');
              setError('reCAPTCHA expired. Please complete it again.');
            },
          });
        } catch {
          renderQueued = false;
          setError('reCAPTCHA could not initialize. Confirm the key is for a v2 checkbox and allows this hostname.');
        }
      });
    };

    if (window.grecaptcha?.ready) {
      renderWidget();
    } else {
      let script = document.querySelector<HTMLScriptElement>('script[data-stamp-recaptcha]');
      if (!script) {
        script = document.createElement('script');
        script.src = 'https://www.google.com/recaptcha/api.js?render=explicit';
        script.async = true;
        script.defer = true;
        script.dataset.stampRecaptcha = 'true';
      }
      script.addEventListener('load', renderWidget, { once: true });
      script.addEventListener('error', () => setError('Unable to load reCAPTCHA. Check your connection and retry.'), { once: true });
      if (!script.isConnected) document.head.append(script);
    }

    return () => {
      disposed = true;
      if (captchaWidgetId.current !== null && window.grecaptcha) {
        window.grecaptcha.reset(captchaWidgetId.current);
        captchaWidgetId.current = null;
      }
    };
  }, [captchaConfig.enabled, captchaConfig.siteKey]);

  const startAssessment = async () => {
    if (captchaConfig.required && !captchaToken) {
      setError('Complete the CAPTCHA before starting enrollment.');
      return;
    }
    setIsWorking(true);
    try {
      const response = await fetch(`${API_URL}/enrollment/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ captchaToken: captchaToken || undefined }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error ?? 'Assessment could not start.');
      setChallenges(data.challenges ?? []);
      setEnrollmentId(data.enrollmentId ?? '');
      setCaptchaToken('');
      setStep(0);
      setResponses({});
      setResult(null);
      setError('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Assessment could not start.');
      setCaptchaToken('');
      if (captchaWidgetId.current !== null && window.grecaptcha) window.grecaptcha.reset(captchaWidgetId.current);
    } finally {
      setIsWorking(false);
    }
  };

  const resetAssessment = () => {
    setChallenges([]);
    setEnrollmentId('');
    setStep(0);
    setResponses({});
    setResult(null);
    setError('');
    setCaptchaToken('');
  };

  const current = challenges[step];

  const selectAnswer = (answer: string) => {
    if (!current) return;
    setResponses((prev) => ({ ...prev, [current.id]: answer }));
    setTimeout(() => {
      if (step < challenges.length - 1) setStep((prev) => prev + 1);
    }, 250);
  };

  const submitAssessment = async () => {
    if (!challenges.length || !enrollmentId) return;
    setIsWorking(true);

    try {
      const response = await fetch(`${API_URL}/enrollment/complete`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          enrollmentId,
          responses: Object.entries(responses).map(([id, answer]) => ({ id, answer })),
        }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error ?? 'Unable to complete assessment.');
      setResult(data);

      if (data.passed) {
        const credential = await generateKeyPairAndRegister();
        localStorage.setItem('verity_credential', JSON.stringify({ id: credential.id, publicKey: credential.publicKey }));
        setResult({ ...data, credentialId: credential.id });
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'There was a problem completing the assessment.');
    } finally {
      setIsWorking(false);
    }
  };

  const progress = challenges.length ? ((step + 1) / challenges.length) * 100 : 0;

  return (
    <div className="mx-auto max-w-4xl px-5 py-12">
      <div className="card p-8">
        <div className="mb-8 flex items-center justify-between">
          <div>
            <p className="label">Step {Math.min(step + 1, challenges.length || 1)} / {challenges.length || 20}</p>
            <h2 className="text-3xl font-bold text-white">Enrollment</h2>
          </div>
          <button onClick={challenges.length ? resetAssessment : startAssessment} className="btn-secondary" disabled={isWorking}>
            {challenges.length ? 'Reset' : 'Start'}
          </button>
        </div>

        <div className="mb-8 h-2 overflow-hidden rounded-full bg-slate-800">
          <div className="h-full rounded-full bg-gradient-to-r from-brand to-emerald-400" style={{ width: `${progress}%` }} />
        </div>

        {captchaConfig.enabled && (
          <div
            ref={captchaContainer}
            className={`min-h-[65px] ${challenges.length ? 'hidden' : ''}`}
            aria-label="reCAPTCHA verification"
          />
        )}

        {!challenges.length ? (
          <div className="space-y-6">
            <p className="text-slate-300">
              Complete this assessment once. After that, participating sites can verify your Stamp credential silently.
            </p>
            <ul className="space-y-2 text-sm text-slate-300">
              <li>• 20 short, varied questions; usually 15–20 minutes</li>
              <li>• Privacy-first: no personal identity collected</li>
              <li>• Private key remains on this device</li>
            </ul>
            {captchaConfig.required && !captchaConfig.enabled && (
              <p role="alert" className="rounded-xl border border-amber-500/30 bg-amber-500/10 p-3 text-sm text-amber-200">
                reCAPTCHA setup is incomplete. Add both Google reCAPTCHA keys to the API environment to enable enrollment.
              </p>
            )}
            {captchaConfig.enabled && captchaConfig.testMode && (
              <p className="text-xs text-amber-200">
                Google test keys are active. They verify the integration but never issue a real challenge; replace them with your own keys for live protection.
              </p>
            )}
            {!captchaConfig.required && (
              <p className="text-xs text-slate-500">reCAPTCHA is not configured. Add Google keys to enable the CAPTCHA gate.</p>
            )}
            <button
              onClick={startAssessment}
              className="btn-primary"
              disabled={isWorking || (captchaConfig.required && (!captchaConfig.enabled || !captchaToken))}
            >
              {isWorking ? 'Loading...' : 'Begin Assessment'}
            </button>
          </div>
        ) : current ? (
          <div>
            <p className="label">Question {step + 1} · {current.category}</p>
            <h3 className="text-2xl font-semibold text-white">{current.prompt}</h3>
            <div className="mt-6 grid gap-3 md:grid-cols-2">
              {current.options.map((option: string) => (
                <button
                  key={option}
                  onClick={() => selectAnswer(option)}
                  className="rounded-xl border border-slate-700 bg-slate-900 p-4 text-left text-slate-100 transition hover:border-brand hover:bg-slate-800"
                >
                  {option}
                </button>
              ))}
            </div>
          </div>
        ) : null}

        {error && <div className="mt-6 rounded-xl border border-red-500/40 bg-red-500/10 p-3 text-red-200">{error}</div>}

        {result && (
          <div className="mt-8 rounded-2xl border border-emerald-500/30 bg-emerald-500/10 p-5">
            <h4 className="text-xl font-bold text-white">Stamp Credential Created</h4>
            <div className="mt-4 grid gap-3 text-sm text-slate-200 md:grid-cols-2">
              <div>
                <p className="label">Credential ID</p>
                <p>{result.credentialId ?? 'vty_7F3A...'}</p>
              </div>
              <div>
                <p className="label">Private key</p>
                <p>Stored locally</p>
              </div>
              <div>
                <p className="label">Status</p>
                <p>{result.passed ? 'Active' : 'Review required'}</p>
              </div>
              <div>
                <p className="label">Score</p>
                <p>{Math.round((result.score ?? 0) * 100)}%</p>
              </div>
            </div>
          </div>
        )}

        {challenges.length > 0 && step === challenges.length - 1 && Object.keys(responses).length === challenges.length && !result && (
          <button onClick={submitAssessment} className="btn-primary mt-8" disabled={isWorking}>
            {isWorking ? 'Submitting...' : 'Complete Enrollment'}
          </button>
        )}
      </div>
    </div>
  );
}

function DemoPage() {
  const [products, setProducts] = useState<any[]>([]);
  const [verification, setVerification] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [credentialId, setCredentialId] = useState<string>('');

  useEffect(() => {
    fetch(`${API_URL}/demo/products`)
      .then((response) => response.json())
      .then((data) => setProducts(data.products ?? []));
    const stored = localStorage.getItem('verity_credential');
    if (stored) setCredentialId(JSON.parse(stored).id ?? '');
  }, []);

  const runVerification = async (action: string) => {
    setLoading(true);
    try {
      const verity = new Verity({ siteId: 'stamp', apiBase: API_URL });
      const result = await verity.verify({ action });
      setVerification({ action, ...result });
    } catch (error) {
      setVerification({ action, decision: 'BLOCK', reason: 'Verification failed.' });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="mx-auto max-w-6xl px-5 py-12">
      <div className="mb-8 flex items-center justify-between gap-4">
        <div>
          <p className="label">Stamp</p>
          <h2 className="text-3xl font-bold text-white">Trusted digital access</h2>
        </div>
        <div className="rounded-full border border-slate-700 bg-slate-900 px-3 py-1 text-sm text-slate-300">
          Credential: {credentialId || 'Not enrolled'}
        </div>
      </div>

      <div className="grid gap-8 lg:grid-cols-[1.3fr_0.7fr]">
        <div className="grid gap-4 md:grid-cols-2">
          {products.map((product) => (
            <div key={product.id} className="card p-5">
              <div className="mb-5 h-32 rounded-xl bg-gradient-to-br from-slate-700 to-slate-900" />
              <div className="flex items-center justify-between gap-3">
                <div>
                  <p className="text-lg font-semibold text-white">{product.name}</p>
                  <p className="text-sm text-slate-400">{product.category}</p>
                </div>
                <p className="text-lg font-bold text-brand">${product.price}</p>
              </div>
              <div className="mt-5 flex gap-3">
                <button className="btn-secondary flex-1" onClick={() => runVerification('browse')}>
                  Browse
                </button>
                <button className="btn-primary flex-1" onClick={() => runVerification('checkout')}>
                  Checkout
                </button>
              </div>
            </div>
          ))}
        </div>

        <aside className="card p-5">
          <p className="label">Live verification</p>
          <div className="space-y-4">
            <button className="btn-primary w-full" onClick={() => runVerification('login')} disabled={loading}>
              {loading ? 'Verifying...' : 'Verify Login'}
            </button>
            <button className="btn-secondary w-full" onClick={() => runVerification('signup')}>
              Verify Signup
            </button>
            <button className="btn-secondary w-full" onClick={() => runVerification('account-create')}>
              Verify Account Creation
            </button>
          </div>

          {verification && (
            <div className="mt-6 rounded-xl border border-slate-700 bg-slate-900 p-4">
              <p className="text-xs uppercase tracking-[0.2em] text-slate-400">Result</p>
              <div className="mt-3 space-y-2 text-sm text-slate-200">
                <p>Action: {verification.action}</p>
                <p>Decision: {verification.decision}</p>
                <p>Risk: {verification.riskLevel ?? 'LOW'}</p>
                <p>Reason: {verification.reason ?? 'Signed verification accepted.'}</p>
              </div>
            </div>
          )}
        </aside>
      </div>
    </div>
  );
}

function AdminPanel() {
  const [token, setToken] = useState(() => sessionStorage.getItem('stamp_admin_token') ?? '');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [activeTab, setActiveTab] = useState<'Dashboard' | 'Attack Simulator' | 'Live Verification'>('Dashboard');
  const [isSubmitting, setIsSubmitting] = useState(false);

  const unlock = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setIsSubmitting(true);
    setError('');
    try {
      const response = await fetch(`${API_URL}/admin/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error ?? 'Unable to unlock Admin.');
      sessionStorage.setItem('stamp_admin_token', data.token);
      setToken(data.token);
      setPassword('');
    } catch (unlockError) {
      setError(unlockError instanceof Error ? unlockError.message : 'Unable to unlock Admin.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const lock = () => {
    sessionStorage.removeItem('stamp_admin_token');
    setToken('');
    setActiveTab('Dashboard');
  };

  if (!token) {
    return (
      <div className="mx-auto max-w-md px-5 py-16">
        <form onSubmit={unlock} className="card p-8">
          <p className="label">Restricted access</p>
          <h2 className="text-3xl font-bold text-white">Admin panel</h2>
          <p className="mt-3 text-slate-300">Enter the admin password to open security tools.</p>
          <label className="mt-6 block">
            <span className="label">Password</span>
            <input
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              className="w-full rounded-xl border border-slate-700 bg-slate-900 px-4 py-3 text-white outline-none focus:border-brand"
              required
            />
          </label>
          {error && <p role="alert" className="mt-4 text-sm text-red-300">{error}</p>}
          <button className="btn-primary mt-6 w-full" type="submit" disabled={isSubmitting}>
            {isSubmitting ? 'Checking...' : 'Unlock Admin'}
          </button>
        </form>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-7xl px-5 py-8">
      <div className="mb-6 flex flex-wrap items-center justify-between gap-4">
        <div>
          <p className="label">Stamp / Restricted</p>
          <h2 className="text-3xl font-bold text-white">Admin panel</h2>
        </div>
        <button className="btn-secondary" onClick={lock}>Lock panel</button>
      </div>
      <div className="mb-6 flex flex-wrap gap-2 border-b border-slate-800">
        {(['Dashboard', 'Attack Simulator', 'Live Verification'] as const).map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`border-b-2 px-4 py-3 text-sm font-medium transition ${activeTab === tab ? 'border-brand text-white' : 'border-transparent text-slate-400 hover:text-white'}`}
          >
            {tab}
          </button>
        ))}
      </div>
      {activeTab === 'Dashboard' && <DashboardPage />}
      {activeTab === 'Attack Simulator' && <AttackSimulatorPage />}
      {activeTab === 'Live Verification' && <LivePage />}
    </div>
  );
}

function AttackSimulatorPage() {
  const [profile, setProfile] = useState<AttackProfile>('burst-bot');
  const [results, setResults] = useState<any>(null);

  const launchAttack = async () => {
    const response = await fetch(`${API_URL}/demo/attack`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${sessionStorage.getItem('stamp_admin_token') ?? ''}`,
      },
      body: JSON.stringify({ profile }),
    });
    const data = await response.json();
    setResults(data);
  };

  return (
    <div className="mx-auto max-w-6xl px-5 py-12">
      <div className="card p-8">
        <div className="mb-8 flex items-center justify-between">
          <div>
            <p className="label">Attack simulator</p>
            <h2 className="text-3xl font-bold text-white">Threat modeling demo</h2>
          </div>
          <button onClick={launchAttack} className="btn-primary">
            Launch Attack
          </button>
        </div>

        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          {[
            'Normal user',
            'Naive bot',
            'Credential farmer',
            'Replay attacker',
            'Distributed attacker',
            'Low-and-slow bot',
            'Burst bot',
          ].map((label) => {
            const value = label.toLowerCase().replace(/ /g, '-').replace(/-+/g, '-') as AttackProfile;
            const selected = value === profile;
            return (
              <button
                key={label}
                onClick={() => setProfile(value)}
                className={`rounded-xl border p-4 text-left text-sm font-medium ${selected ? 'border-brand bg-brand/10 text-white' : 'border-slate-700 bg-slate-900 text-slate-300'}`}
              >
                {label}
              </button>
            );
          })}
        </div>

        {results && (
          <div className="mt-8 grid gap-5 md:grid-cols-4">
            <div className="rounded-xl border border-slate-700 bg-slate-900 p-4">
              <p className="text-xs uppercase tracking-[0.2em] text-slate-400">Requests</p>
              <p className="mt-2 text-2xl font-bold text-white">{results.requests}</p>
            </div>
            <div className="rounded-xl border border-slate-700 bg-slate-900 p-4">
              <p className="text-xs uppercase tracking-[0.2em] text-slate-400">Requests/sec</p>
              <p className="mt-2 text-2xl font-bold text-white">{results.requestsPerSecond}</p>
            </div>
            <div className="rounded-xl border border-slate-700 bg-slate-900 p-4">
              <p className="text-xs uppercase tracking-[0.2em] text-slate-400">Risk score</p>
              <p className="mt-2 text-2xl font-bold text-white">{results.riskScore}</p>
            </div>
            <div className="rounded-xl border border-slate-700 bg-slate-900 p-4">
              <p className="text-xs uppercase tracking-[0.2em] text-slate-400">Profile</p>
              <p className="mt-2 text-2xl font-bold text-white">{results.profile}</p>
            </div>
            <div className="md:col-span-4 rounded-xl border border-slate-700 bg-slate-900 p-5">
              <p className="label">Verification results</p>
              <div className="grid gap-3 md:grid-cols-4">
                {Object.entries(results.verificationResults).map(([key, value]) => (
                  <div key={key} className="rounded-xl border border-slate-700 bg-slate-950/70 p-3">
                    <p className="text-sm uppercase tracking-[0.16em] text-slate-400">{key}</p>
                    <p className="mt-2 text-2xl font-bold text-white">{value as number}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function DashboardPage() {
  const [overview, setOverview] = useState<any>(null);
  const [events, setEvents] = useState<any[]>([]);
  const [riskSummary, setRiskSummary] = useState<any>(null);

  useEffect(() => {
    const load = async () => {
      const authorization = `Bearer ${sessionStorage.getItem('stamp_admin_token') ?? ''}`;
      const [overviewRes, eventsRes, riskRes] = await Promise.all([
        fetch(`${API_URL}/dashboard/overview`, { headers: { Authorization: authorization } }),
        fetch(`${API_URL}/dashboard/events`, { headers: { Authorization: authorization } }),
        fetch(`${API_URL}/dashboard/risk`, { headers: { Authorization: authorization } }),
      ]);

      if ([overviewRes, eventsRes, riskRes].some((result) => result.status === 401)) {
        sessionStorage.removeItem('stamp_admin_token');
        return;
      }
      setOverview((await overviewRes.json()).overview);
      setEvents((await eventsRes.json()).events);
      setRiskSummary((await riskRes.json()).summary);
    };

    load();
  }, []);

  const statCards = [
    { label: 'Total requests', value: overview?.totalRequests ?? 0 },
    { label: 'Verified requests', value: overview?.verifiedRequests ?? 0 },
    { label: 'Suspicious requests', value: overview?.suspiciousRequests ?? 0 },
    { label: 'Blocked requests', value: overview?.blockedRequests ?? 0 },
    { label: 'Active credentials', value: overview?.activeCredentials ?? 0 },
    { label: 'Enrollments', value: overview?.enrollments ?? 0 },
  ];

  const riskLevels = ['LOW', 'MEDIUM', 'HIGH', 'EXTREME'];

  return (
    <div className="mx-auto max-w-6xl px-5 py-12">
      <div className="mb-8">
        <p className="label">Overview</p>
        <h2 className="text-3xl font-bold text-white">Admin security dashboard</h2>
      </div>

      <div className="grid gap-4 md:grid-cols-3 xl:grid-cols-6">
        {statCards.map((card) => (
          <div key={card.label} className="card p-4">
            <p className="text-xs uppercase tracking-[0.2em] text-slate-400">{card.label}</p>
            <p className="mt-3 text-3xl font-black text-white">{card.value}</p>
          </div>
        ))}
      </div>

      <div className="mt-8 grid gap-8 lg:grid-cols-[0.9fr_1.1fr]">
        <div className="card p-5">
          <p className="label">Risk distribution</p>
          <div className="space-y-4">
            {riskLevels.map((level) => {
              const value = riskSummary?.[level] ?? 0;
              const max = Math.max(1, ...riskLevels.map((label) => riskSummary?.[label] ?? 0));
              return (
                <div key={level}>
                  <div className="mb-1 flex justify-between text-sm text-slate-300">
                    <span>{level}</span>
                    <span>{value}</span>
                  </div>
                  <div className="h-2 rounded-full bg-slate-800">
                    <div
                      className={`h-full rounded-full ${level === 'LOW' ? 'bg-emerald-400' : level === 'MEDIUM' ? 'bg-amber-400' : level === 'HIGH' ? 'bg-orange-400' : 'bg-red-400'}`}
                      style={{ width: `${(value / max) * 100}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        <div className="card p-5">
          <p className="label">Live event stream</p>
          <div className="space-y-3">
            {events.slice(0, 8).map((event, index) => (
              <div key={`${event.id}-${index}`} className="flex items-center justify-between rounded-xl border border-slate-800 bg-slate-900/60 p-3 text-sm text-slate-200">
                <div>
                  <span className="font-mono text-slate-400">{event.timestamp?.slice(11, 19)}</span> {event.type || 'Credential verified'}
                </div>
                <span className="rounded-full border border-slate-700 px-2 py-1 text-[10px] uppercase tracking-[0.18em] text-slate-300">
                  {event.severity || event.decision || 'LOW'}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

function LivePage() {
  const [status, setStatus] = useState({
    credential: 'VALID',
    signature: 'VALID',
    replay: 'NONE',
    requestRate: 'NORMAL',
    risk: 'LOW',
    decision: 'ALLOW',
  });

  useEffect(() => {
    const interval = setInterval(() => {
      setStatus((current) => ({
        ...current,
        risk: current.risk === 'LOW' ? 'HIGH' : 'LOW',
        decision: current.decision === 'ALLOW' ? 'STEP_UP' : 'ALLOW',
      }));
    }, 2500);

    return () => clearInterval(interval);
  }, []);

  return (
    <div className="mx-auto max-w-4xl px-5 py-12">
      <div className="card p-8">
        <p className="label">Live verification</p>
        <h2 className="text-3xl font-bold text-white">User → Sign request → Stamp → decision</h2>
        <div className="mt-8 flex flex-wrap items-center justify-center gap-4 text-sm font-medium text-slate-300">
          {['USER', 'SIGN REQUEST', 'STAMP', 'RISK ENGINE', 'DECISION'].map((step) => (
            <div key={step} className="flex items-center gap-2">
              <span className="rounded-full border border-slate-700 bg-slate-900 px-3 py-2">{step}</span>
              {step !== 'DECISION' && <span>↓</span>}
            </div>
          ))}
        </div>

        <div className="mt-8 grid gap-4 md:grid-cols-2">
          {Object.entries(status).map(([key, value]) => (
            <div key={key} className="rounded-xl border border-slate-700 bg-slate-900 p-4">
              <p className="text-xs uppercase tracking-[0.18em] text-slate-400">{key}</p>
              <p className="mt-2 text-2xl font-bold text-white">{value}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function PrivacyPage() {
  return (
    <div className="mx-auto max-w-4xl px-5 py-12">
      <div className="card p-8">
        <p className="label">Privacy</p>
        <h2 className="text-3xl font-bold text-white">Stored vs not stored</h2>
        <div className="mt-8 grid gap-6 md:grid-cols-2">
          <div className="rounded-2xl border border-emerald-500/30 bg-emerald-500/10 p-5">
            <h3 className="text-xl font-bold text-white">Stored</h3>
            <ul className="mt-4 space-y-2 text-slate-200">
              <li>• pseudonymous credential ID</li>
              <li>• public key</li>
              <li>• credential status</li>
              <li>• anti-abuse counters</li>
              <li>• verification events</li>
            </ul>
          </div>
          <div className="rounded-2xl border border-red-500/30 bg-red-500/10 p-5">
            <h3 className="text-xl font-bold text-white">Not stored</h3>
            <ul className="mt-4 space-y-2 text-slate-200">
              <li>• private key</li>
              <li>• browsing history</li>
              <li>• passwords</li>
              <li>• real-world identity</li>
              <li>• unnecessary personal data</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
}

export default App;
