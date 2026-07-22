'use strict';

const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');

const app = express();
const PORT = Number(process.env.PORT || 10000);
const HOST = '0.0.0.0';
const API_TOKEN = process.env.AUDIT_API_TOKEN;

if (!API_TOKEN) {
  console.error('Missing required environment variable: AUDIT_API_TOKEN');
  process.exit(1);
}

app.disable('x-powered-by');
app.use(helmet());
app.use(cors({
  origin: process.env.ALLOWED_ORIGIN || '*',
  methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Authorization', 'Content-Type', 'X-Request-Id'],
  maxAge: 86400,
}));
app.use(express.json({ limit: '1mb' }));

const jobs = new Map();
const auditEvents = [];

function now() {
  return new Date().toISOString();
}

function secureEqual(a, b) {
  const left = Buffer.from(String(a || ''));
  const right = Buffer.from(String(b || ''));
  if (left.length !== right.length) return false;
  return crypto.timingSafeEqual(left, right);
}

function authenticate(req, res, next) {
  const header = req.get('authorization') || '';
  const supplied = header.startsWith('Bearer ') ? header.slice(7) : '';
  if (!secureEqual(supplied, API_TOKEN)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

function record(action, jobId, details = {}) {
  auditEvents.push({
    id: crypto.randomUUID(),
    timestamp: now(),
    action,
    job_id: jobId || null,
    details,
  });
  if (auditEvents.length > 1000) auditEvents.shift();
}

function publicJob(job) {
  return {
    id: job.id,
    engagement_id: job.engagement_id,
    organization_id: job.organization_id,
    name: job.name,
    status: job.status,
    engine: job.engine,
    hash_type: job.hash_type,
    target_count: job.targets.length,
    recovered_count: job.results.filter((r) => r.recovered).length,
    progress: job.progress,
    created_at: job.created_at,
    updated_at: job.updated_at,
    started_at: job.started_at,
    completed_at: job.completed_at,
    max_runtime_minutes: job.max_runtime_minutes,
    authorization_confirmed: job.authorization_confirmed,
    scope_confirmed: job.scope_confirmed,
  };
}

app.get('/', (_req, res) => {
  res.json({
    service: 'cipher-audit-api',
    status: 'online',
    documentation: 'Use GET /health for connectivity checks.',
  });
});

app.get('/health', (_req, res) => {
  res.status(200).json({
    status: 'ok',
    service: 'cipher-audit-api',
    mode: 'safe-demo',
    timestamp: now(),
  });
});

app.use(authenticate);

app.get('/jobs', (req, res) => {
  const status = req.query.status;
  let list = Array.from(jobs.values());
  if (status) list = list.filter((job) => job.status === status);
  res.json({ jobs: list.map(publicJob), count: list.length });
});

app.post('/jobs', (req, res) => {
  const body = req.body || {};
  const authorizationConfirmed = body.authorization_confirmed === true;
  const scopeConfirmed = body.scope_confirmed === true;

  if (!authorizationConfirmed || !scopeConfirmed) {
    return res.status(400).json({
      error: 'Written authorization and confirmed scope are required.',
      required: ['authorization_confirmed', 'scope_confirmed'],
    });
  }

  const id = crypto.randomUUID();
  const createdAt = now();
  const job = {
    id,
    engagement_id: body.engagement_id || null,
    organization_id: body.organization_id || null,
    name: body.name || `Audit ${id.slice(0, 8)}`,
    status: 'queued',
    engine: body.engine || 'mock',
    hash_type: body.hash_type || 'unknown',
    targets: Array.isArray(body.targets) ? body.targets.map((target, index) => ({
      id: target.id || crypto.randomUUID(),
      account_identifier: target.account_identifier || `target-${index + 1}`,
      status: 'queued',
    })) : [],
    results: [],
    progress: 0,
    max_runtime_minutes: Number(body.max_runtime_minutes || 60),
    authorization_confirmed: true,
    scope_confirmed: true,
    created_at: createdAt,
    updated_at: createdAt,
    started_at: null,
    completed_at: null,
  };

  jobs.set(id, job);
  record('job.created', id, { engine: job.engine, target_count: job.targets.length });
  res.status(201).json({ job: publicJob(job) });
});

app.get('/jobs/:id', (req, res) => {
  const job = jobs.get(req.params.id);
  if (!job) return res.status(404).json({ error: 'Job not found' });
  res.json({ job: publicJob(job) });
});

app.patch('/jobs/:id', (req, res) => {
  const job = jobs.get(req.params.id);
  if (!job) return res.status(404).json({ error: 'Job not found' });

  const allowedStatuses = new Set(['queued', 'running', 'paused', 'completed', 'failed', 'cancelled']);
  if (req.body.status && !allowedStatuses.has(req.body.status)) {
    return res.status(400).json({ error: 'Invalid status' });
  }

  if (req.body.status) {
    job.status = req.body.status;
    if (job.status === 'running' && !job.started_at) job.started_at = now();
    if (['completed', 'failed', 'cancelled'].includes(job.status)) job.completed_at = now();
  }

  if (Number.isFinite(Number(req.body.progress))) {
    job.progress = Math.max(0, Math.min(100, Number(req.body.progress)));
  }

  job.updated_at = now();
  record('job.updated', job.id, { status: job.status, progress: job.progress });
  res.json({ job: publicJob(job) });
});

app.post('/jobs/:id/start', (req, res) => {
  const job = jobs.get(req.params.id);
  if (!job) return res.status(404).json({ error: 'Job not found' });
  if (!['queued', 'paused'].includes(job.status)) {
    return res.status(409).json({ error: `Cannot start a job with status ${job.status}` });
  }
  job.status = 'running';
  job.started_at = job.started_at || now();
  job.updated_at = now();
  record('job.started', job.id);
  res.json({ job: publicJob(job) });
});

app.post('/jobs/:id/pause', (req, res) => {
  const job = jobs.get(req.params.id);
  if (!job) return res.status(404).json({ error: 'Job not found' });
  if (job.status !== 'running') return res.status(409).json({ error: 'Only running jobs can be paused' });
  job.status = 'paused';
  job.updated_at = now();
  record('job.paused', job.id);
  res.json({ job: publicJob(job) });
});

app.post('/jobs/:id/cancel', (req, res) => {
  const job = jobs.get(req.params.id);
  if (!job) return res.status(404).json({ error: 'Job not found' });
  if (['completed', 'failed', 'cancelled'].includes(job.status)) {
    return res.status(409).json({ error: `Job is already ${job.status}` });
  }
  job.status = 'cancelled';
  job.completed_at = now();
  job.updated_at = now();
  record('job.cancelled', job.id);
  res.json({ job: publicJob(job) });
});

app.get('/jobs/:id/results', (req, res) => {
  const job = jobs.get(req.params.id);
  if (!job) return res.status(404).json({ error: 'Job not found' });
  const results = job.results.map((result) => ({
    id: result.id,
    account_identifier: result.account_identifier,
    recovered: result.recovered,
    verified: result.verified,
    password_length: result.password_length,
    pattern_category: result.pattern_category,
    risk_rating: result.risk_rating,
    created_at: result.created_at,
  }));
  res.json({ results, count: results.length });
});

app.post('/jobs/:id/results', (req, res) => {
  const job = jobs.get(req.params.id);
  if (!job) return res.status(404).json({ error: 'Job not found' });

  const body = req.body || {};
  if (!body.account_identifier) {
    return res.status(400).json({ error: 'account_identifier is required' });
  }

  const result = {
    id: crypto.randomUUID(),
    account_identifier: body.account_identifier,
    recovered: body.recovered === true,
    verified: body.verified === true,
    password_length: Number.isFinite(Number(body.password_length)) ? Number(body.password_length) : null,
    pattern_category: body.pattern_category || null,
    risk_rating: body.risk_rating || null,
    created_at: now(),
  };

  job.results.push(result);
  job.updated_at = now();
  record('result.recorded', job.id, {
    result_id: result.id,
    account_identifier: result.account_identifier,
    recovered: result.recovered,
    verified: result.verified,
  });

  res.status(201).json({ result });
});

app.post('/jobs/:id/verify', (req, res) => {
  const job = jobs.get(req.params.id);
  if (!job) return res.status(404).json({ error: 'Job not found' });
  const result = job.results.find((item) => item.id === req.body.result_id);
  if (!result) return res.status(404).json({ error: 'Result not found' });
  result.verified = req.body.verified === true;
  job.updated_at = now();
  record('result.verified', job.id, { result_id: result.id, verified: result.verified });
  res.json({ result: {
    id: result.id,
    account_identifier: result.account_identifier,
    recovered: result.recovered,
    verified: result.verified,
  }});
});

app.post('/jobs/:id/reveal', (req, res) => {
  const job = jobs.get(req.params.id);
  if (!job) return res.status(404).json({ error: 'Job not found' });
  if (!req.body.reason || String(req.body.reason).trim().length < 3) {
    return res.status(400).json({ error: 'A reveal reason is required' });
  }

  record('password.reveal.requested', job.id, {
    result_id: req.body.result_id || null,
    reason: String(req.body.reason).slice(0, 250),
    outcome: 'not_configured',
  });

  res.status(501).json({
    error: 'Plaintext reveal is not configured in this safe scaffold.',
    message: 'Connect an encrypted secret store and require application-level MFA before enabling this route.',
  });
});

app.get('/audit-events', (req, res) => {
  const limit = Math.max(1, Math.min(200, Number(req.query.limit || 50)));
  res.json({ events: auditEvents.slice(-limit).reverse() });
});

app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found', method: req.method, path: req.path });
});

app.use((error, req, res, _next) => {
  console.error(error);
  record('server.error', null, { request_id: req.get('x-request-id') || null });
  res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, HOST, () => {
  console.log(`cipher-audit-api listening on http://${HOST}:${PORT}`);
});
