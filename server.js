'use strict';

const crypto = require('crypto');
const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');
const { spawn } = require('child_process');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const multer = require('multer');

const app = express();
const PORT = Number(process.env.PORT || 10000);
const HOST = '0.0.0.0';
const API_TOKEN = process.env.AUDIT_API_TOKEN;
const DATA_DIR = process.env.DATA_DIR || '/tmp/cipher-audit';
const MAX_RUNTIME_MINUTES = Math.min(Number(process.env.MAX_RUNTIME_MINUTES || 30), 120);
const MAX_TARGETS = Math.min(Number(process.env.MAX_TARGETS || 500), 5000);
const MAX_WORDLIST_ENTRIES = Math.min(Number(process.env.MAX_WORDLIST_ENTRIES || 50000), 250000);
const MAX_ZIP_BYTES = Math.min(Number(process.env.MAX_ZIP_BYTES || 25 * 1024 * 1024), 100 * 1024 * 1024);
const UPLOAD_DIR = path.join(DATA_DIR, 'uploads');

if (!API_TOKEN) {
  console.error('Missing required environment variable: AUDIT_API_TOKEN');
  process.exit(1);
}

const HASH_TYPES = Object.freeze({
  md5: { hashcat: '0', john: 'raw-md5', regex: /^[a-fA-F0-9]{32}$/ },
  sha1: { hashcat: '100', john: 'raw-sha1', regex: /^[a-fA-F0-9]{40}$/ },
  sha256: { hashcat: '1400', john: 'raw-sha256', regex: /^[a-fA-F0-9]{64}$/ },
  ntlm: { hashcat: '1000', john: 'nt', regex: /^[a-fA-F0-9]{32}$/ },
  bcrypt: { hashcat: '3200', john: 'bcrypt', regex: /^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$/ },
  md5crypt: { hashcat: '500', john: 'md5crypt', regex: /^\$1\$/ },
  sha512crypt: { hashcat: '1800', john: 'sha512crypt', regex: /^\$6\$/ }
});

fs.mkdirSync(UPLOAD_DIR, { recursive: true, mode: 0o700 });

function sanitizeName(value) {
  return String(value || '').replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 100);
}

const upload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
    filename: (_req, file, cb) => cb(null, `${crypto.randomUUID()}-${sanitizeName(file.originalname || 'archive.zip')}`)
  }),
  limits: { fileSize: MAX_ZIP_BYTES, files: 1, fields: 20 },
  fileFilter: (_req, file, cb) => {
    const nameOk = String(file.originalname || '').toLowerCase().endsWith('.zip');
    const typeOk = ['application/zip', 'application/x-zip-compressed', 'application/octet-stream'].includes(file.mimetype);
    cb(nameOk && typeOk ? null : new Error('Only .zip uploads are accepted'), nameOk && typeOk);
  }
});

app.disable('x-powered-by');
app.use(helmet());
app.use(cors({
  origin: process.env.ALLOWED_ORIGIN || '*',
  methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Authorization', 'Content-Type', 'X-Request-Id'],
  maxAge: 86400
}));
app.use(express.json({ limit: '5mb' }));

const jobs = new Map();
const auditEvents = [];
const processes = new Map();

function now() { return new Date().toISOString(); }
function secureEqual(a, b) {
  const left = Buffer.from(String(a || ''));
  const right = Buffer.from(String(b || ''));
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}
function authenticate(req, res, next) {
  const header = req.get('authorization') || '';
  const supplied = header.startsWith('Bearer ') ? header.slice(7) : '';
  if (!secureEqual(supplied, API_TOKEN)) return res.status(401).json({ error: 'Unauthorized' });
  next();
}
function record(action, jobId, details = {}) {
  auditEvents.push({ id: crypto.randomUUID(), timestamp: now(), action, job_id: jobId || null, details });
  if (auditEvents.length > 2000) auditEvents.shift();
}
function classifyPassword(password) {
  if (/^[a-zA-Z]+\d{2,4}[!@#$%^&*]?$/u.test(password)) return 'word-plus-digits';
  if (/^\d+$/u.test(password)) return 'numeric';
  if (/^[a-z]+$/u.test(password)) return 'lowercase-word';
  return 'mixed';
}
function riskRating(password) {
  const length = [...password].length;
  if (length < 8) return 'critical';
  if (length < 12) return 'high';
  if (length < 16) return 'medium';
  return 'low';
}
function publicResult(result) {
  return {
    id: result.id,
    account_identifier: result.account_identifier,
    recovered: result.recovered,
    verified: result.verified,
    password_length: result.password ? [...result.password].length : null,
    pattern_category: result.pattern_category,
    risk_rating: result.risk_rating,
    created_at: result.created_at
  };
}
function publicJob(job) {
  return {
    id: job.id,
    engagement_id: job.engagement_id,
    organization_id: job.organization_id,
    name: job.name,
    job_type: job.job_type,
    status: job.status,
    engine: job.engine,
    hash_type: job.hash_type,
    target_count: job.targets.length,
    recovered_count: job.results.filter(result => result.recovered).length,
    progress: job.progress,
    created_at: job.created_at,
    updated_at: job.updated_at,
    started_at: job.started_at,
    completed_at: job.completed_at,
    max_runtime_minutes: job.max_runtime_minutes,
    authorization_confirmed: job.authorization_confirmed,
    scope_confirmed: job.scope_confirmed,
    error: job.error || null
  };
}
function normalizeWordlist(entries) {
  if (!Array.isArray(entries) || entries.length === 0) throw new Error('wordlist_entries must be a non-empty array');
  if (entries.length > MAX_WORDLIST_ENTRIES) throw new Error(`Wordlist exceeds ${MAX_WORDLIST_ENTRIES} entries`);
  const cleaned = entries.map(value => String(value).replace(/[\r\n\0]/g, '').slice(0, 256)).filter(Boolean);
  if (!cleaned.length) throw new Error('wordlist_entries contains no usable candidates');
  return cleaned;
}
function normalizeTargets(rawTargets, hashType) {
  if (!Array.isArray(rawTargets) || rawTargets.length === 0) throw new Error('targets must be a non-empty array');
  if (rawTargets.length > MAX_TARGETS) throw new Error(`Too many targets; maximum is ${MAX_TARGETS}`);
  const spec = HASH_TYPES[hashType];
  return rawTargets.map((target, index) => {
    const hash = String(target.hash || '').trim();
    if (!spec.regex.test(hash)) throw new Error(`Target ${index + 1} is not valid for ${hashType}`);
    return {
      id: target.id || crypto.randomUUID(),
      account_identifier: String(target.account_identifier || `target-${index + 1}`).slice(0, 200),
      hash
    };
  });
}
async function ensureJobDir(job) {
  const directory = path.join(DATA_DIR, job.id);
  await fsp.mkdir(directory, { recursive: true, mode: 0o700 });
  job.work_dir = directory;
  return directory;
}
function spawnBounded(command, args, options, timeoutMs, processId) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { ...options, shell: false, stdio: ['ignore', 'pipe', 'pipe'] });
    processes.set(processId, child);
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', data => { stdout = (stdout + data.toString()).slice(-500000); });
    child.stderr.on('data', data => { stderr = (stderr + data.toString()).slice(-500000); });
    const timer = setTimeout(() => {
      child.kill('SIGTERM');
      setTimeout(() => child.kill('SIGKILL'), 3000).unref();
    }, timeoutMs);
    child.on('error', error => {
      clearTimeout(timer);
      processes.delete(processId);
      reject(error);
    });
    child.on('close', code => {
      clearTimeout(timer);
      processes.delete(processId);
      resolve({ code, stdout, stderr });
    });
  });
}
function parsePotLine(line, hashes) {
  for (const hash of [...hashes].sort((a, b) => b.length - a.length)) {
    if (line.startsWith(`${hash}:`)) return { hash, password: line.slice(hash.length + 1) };
  }
  return null;
}
async function runHashcat(job, hashFile, wordlistFile, potFile) {
  const args = ['-m', HASH_TYPES[job.hash_type].hashcat, '-a', '0', hashFile, wordlistFile,
    '--potfile-path', potFile, '--session', `cipher_${sanitizeName(job.id)}`, '--quiet', '--force'];
  const result = await spawnBounded('hashcat', args, { cwd: job.work_dir }, job.max_runtime_minutes * 60000, job.id);
  if (![0, 1].includes(result.code)) throw new Error(`Hashcat failed (${result.code}): ${result.stderr.slice(-1000)}`);
}
async function runJohn(job, hashFile, wordlistFile, potFile) {
  const john = process.env.JOHN_PATH || '/opt/john/run/john';
  const args = [`--format=${HASH_TYPES[job.hash_type].john}`, `--wordlist=${wordlistFile}`, `--pot=${potFile}`, hashFile];
  const result = await spawnBounded(john, args, { cwd: job.work_dir }, job.max_runtime_minutes * 60000, job.id);
  if (![0, 1].includes(result.code)) throw new Error(`John failed (${result.code}): ${result.stderr.slice(-1000)}`);
}
async function readHashResults(job, potFile) {
  let text = '';
  try { text = await fsp.readFile(potFile, 'utf8'); } catch (_) { return []; }
  const hashes = job.targets.map(target => target.hash);
  const cracked = new Map();
  for (const line of text.split(/\r?\n/)) {
    const parsed = parsePotLine(line, hashes);
    if (parsed) cracked.set(parsed.hash, parsed.password);
  }
  return job.targets.filter(target => cracked.has(target.hash)).map(target => {
    const password = cracked.get(target.hash);
    return {
      id: crypto.randomUUID(), account_identifier: target.account_identifier,
      recovered: true, verified: true, password,
      pattern_category: classifyPassword(password), risk_rating: riskRating(password), created_at: now()
    };
  });
}
async function executeHashJob(job) {
  try {
    job.status = 'running'; job.started_at = now(); job.updated_at = now(); job.progress = 5;
    const directory = await ensureJobDir(job);
    const hashFile = path.join(directory, 'hashes.txt');
    const wordlistFile = path.join(directory, 'wordlist.txt');
    const potFile = path.join(directory, `${job.engine}.pot`);
    await fsp.writeFile(hashFile, `${job.targets.map(target => target.hash).join('\n')}\n`, { mode: 0o600 });
    await fsp.writeFile(wordlistFile, `${job.wordlist_entries.join('\n')}\n`, { mode: 0o600 });
    job.progress = 15;
    if (job.engine === 'hashcat') await runHashcat(job, hashFile, wordlistFile, potFile);
    else await runJohn(job, hashFile, wordlistFile, potFile);
    if (job.status === 'cancelled') return;
    job.progress = 90;
    job.results = await readHashResults(job, potFile);
    job.progress = 100; job.status = 'completed'; job.completed_at = now(); job.updated_at = now();
    record('hash.job.completed', job.id, { recovered_count: job.results.length });
  } catch (error) {
    if (job.status !== 'cancelled') {
      job.status = 'failed'; job.error = String(error.message || error).slice(0, 1500); job.completed_at = now(); job.updated_at = now();
      record('hash.job.failed', job.id, { error: job.error });
    }
  }
}
async function extractZipHash(archivePath, hashFile, jobId) {
  const zip2john = process.env.ZIP2JOHN_PATH || '/opt/john/run/zip2john';
  const result = await spawnBounded(zip2john, [archivePath], {}, 30000, `${jobId}-zip2john`);
  if (result.code !== 0 || !result.stdout.trim()) throw new Error(`zip2john failed: ${result.stderr.slice(-1000)}`);
  const line = result.stdout.split(/\r?\n/).find(Boolean);
  if (!line || !line.includes(':$')) throw new Error('ZIP encryption was not recognized by zip2john');
  await fsp.writeFile(hashFile, `${line}\n`, { mode: 0o600 });
  const ciphertext = line.slice(line.indexOf(':') + 1).trim();
  const format = ciphertext.startsWith('$pkzip2$') ? 'PKZIP' : ciphertext.startsWith('$zip2$') ? 'ZIP' : null;
  if (!format) throw new Error('Unsupported ZIP encryption format');
  return { ciphertext, format };
}
async function executeZipJob(job) {
  try {
    job.status = 'running'; job.started_at = now(); job.updated_at = now(); job.progress = 5;
    const directory = await ensureJobDir(job);
    const hashFile = path.join(directory, 'archive.hash');
    const wordlistFile = path.join(directory, 'wordlist.txt');
    const potFile = path.join(directory, 'zip-john.pot');
    await fsp.writeFile(wordlistFile, `${job.wordlist_entries.join('\n')}\n`, { mode: 0o600 });
    const extracted = await extractZipHash(job.archive_path, hashFile, job.id);
    job.zip_ciphertext = extracted.ciphertext;
    job.progress = 20;
    const john = process.env.JOHN_PATH || '/opt/john/run/john';
    const args = [`--format=${extracted.format}`, `--wordlist=${wordlistFile}`, `--pot=${potFile}`, hashFile];
    const result = await spawnBounded(john, args, { cwd: directory }, job.max_runtime_minutes * 60000, job.id);
    if (![0, 1].includes(result.code)) throw new Error(`John ZIP audit failed (${result.code}): ${result.stderr.slice(-1000)}`);
    if (job.status === 'cancelled') return;
    job.progress = 90;
    let potText = '';
    try { potText = await fsp.readFile(potFile, 'utf8'); } catch (_) {}
    job.results = [];
    for (const line of potText.split(/\r?\n/)) {
      if (line.startsWith(`${job.zip_ciphertext}:`)) {
        const password = line.slice(job.zip_ciphertext.length + 1);
        job.results.push({
          id: crypto.randomUUID(), account_identifier: job.archive_name,
          recovered: true, verified: true, password,
          pattern_category: classifyPassword(password), risk_rating: riskRating(password), created_at: now()
        });
        break;
      }
    }
    job.progress = 100; job.status = 'completed'; job.completed_at = now(); job.updated_at = now();
    record('zip.job.completed', job.id, { archive_name: job.archive_name, recovered_count: job.results.length });
  } catch (error) {
    if (job.status !== 'cancelled') {
      job.status = 'failed'; job.error = String(error.message || error).slice(0, 1500); job.completed_at = now(); job.updated_at = now();
      record('zip.job.failed', job.id, { archive_name: job.archive_name, error: job.error });
    }
  } finally {
    if (job.archive_path) await fsp.rm(job.archive_path, { force: true }).catch(() => {});
  }
}

app.get('/', (_req, res) => res.json({ service: 'cipher-audit-api', status: 'online', mode: 'bounded-live-worker', zip_uploads: true }));
app.get('/health', async (_req, res) => {
  const checks = {};
  for (const [name, command] of [['hashcat', 'hashcat'], ['jtr', process.env.JOHN_PATH || '/opt/john/run/john'], ['zip2john', process.env.ZIP2JOHN_PATH || '/opt/john/run/zip2john']]) {
    try {
      const args = name === 'zip2john' ? [] : ['--version'];
      const result = await spawnBounded(command, args, {}, 5000, `health-${name}-${Date.now()}`);
      checks[name] = [0, 1].includes(result.code) ? 'available' : 'unavailable';
    } catch (_) { checks[name] = 'unavailable'; }
  }
  res.json({ status: 'ok', service: 'cipher-audit-api', mode: 'bounded-live-worker', engines: checks, timestamp: now() });
});

app.use(authenticate);

app.get('/capabilities', (_req, res) => res.json({
  engines: ['hashcat', 'jtr'],
  attack_modes: ['wordlist'],
  archive_types: ['zip'],
  hash_types: Object.keys(HASH_TYPES),
  limits: { max_targets: MAX_TARGETS, max_wordlist_entries: MAX_WORDLIST_ENTRIES, max_runtime_minutes: MAX_RUNTIME_MINUTES, max_zip_bytes: MAX_ZIP_BYTES }
}));

app.post('/jobs', (req, res) => {
  try {
    const body = req.body || {};
    if (body.authorization_confirmed !== true || body.scope_confirmed !== true) return res.status(400).json({ error: 'Written authorization and confirmed scope are required.' });
    if (!['hashcat', 'jtr'].includes(body.engine)) return res.status(400).json({ error: 'engine must be hashcat or jtr' });
    const hashType = String(body.hash_type || '').toLowerCase();
    if (!HASH_TYPES[hashType]) return res.status(400).json({ error: `Unsupported hash_type: ${hashType}` });
    const id = crypto.randomUUID();
    const created = now();
    const job = {
      id, job_type: 'hash', engagement_id: body.engagement_id || null, organization_id: body.organization_id || null,
      name: body.name || `Hash Audit ${id.slice(0, 8)}`, status: 'queued', engine: body.engine, hash_type: hashType,
      targets: normalizeTargets(body.targets, hashType), wordlist_entries: normalizeWordlist(body.wordlist_entries),
      results: [], progress: 0, max_runtime_minutes: Math.max(1, Math.min(Number(body.max_runtime_minutes || 10), MAX_RUNTIME_MINUTES)),
      authorization_confirmed: true, scope_confirmed: true, created_at: created, updated_at: created, started_at: null, completed_at: null
    };
    jobs.set(id, job);
    record('hash.job.created', id, { engine: job.engine, target_count: job.targets.length });
    res.status(201).json({ job: publicJob(job) });
  } catch (error) { res.status(400).json({ error: String(error.message || error) }); }
});

app.post('/archives/zip', upload.single('archive'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'archive file is required' });
    const authorized = String(req.body.authorization_confirmed).toLowerCase() === 'true';
    const scoped = String(req.body.scope_confirmed).toLowerCase() === 'true';
    if (!authorized || !scoped) {
      await fsp.rm(req.file.path, { force: true });
      return res.status(400).json({ error: 'Written authorization and confirmed scope are required.' });
    }
    let entries;
    try { entries = JSON.parse(req.body.wordlist_entries || '[]'); }
    catch (_) { entries = String(req.body.wordlist_entries || '').split(/\r?\n/); }
    const id = crypto.randomUUID();
    const created = now();
    const job = {
      id, job_type: 'zip', engagement_id: req.body.engagement_id || null, organization_id: req.body.organization_id || null,
      name: req.body.name || `ZIP Audit ${id.slice(0, 8)}`, archive_name: req.file.originalname, archive_path: req.file.path,
      status: 'queued', engine: 'jtr', hash_type: 'zip',
      targets: [{ id: crypto.randomUUID(), account_identifier: req.file.originalname, hash: '[encrypted ZIP]' }],
      wordlist_entries: normalizeWordlist(entries), results: [], progress: 0,
      max_runtime_minutes: Math.max(1, Math.min(Number(req.body.max_runtime_minutes || 10), MAX_RUNTIME_MINUTES)),
      authorization_confirmed: true, scope_confirmed: true, created_at: created, updated_at: created, started_at: null, completed_at: null
    };
    jobs.set(id, job);
    record('zip.job.created', id, { archive_name: req.file.originalname, size_bytes: req.file.size });
    res.status(201).json({ job: publicJob(job) });
  } catch (error) {
    if (req.file?.path) await fsp.rm(req.file.path, { force: true }).catch(() => {});
    res.status(400).json({ error: String(error.message || error) });
  }
});

app.get('/jobs', (req, res) => {
  let list = [...jobs.values()];
  if (req.query.status) list = list.filter(job => job.status === req.query.status);
  res.json({ jobs: list.map(publicJob), count: list.length });
});
app.get('/jobs/:id', (req, res) => {
  const job = jobs.get(req.params.id);
  if (!job) return res.status(404).json({ error: 'Job not found' });
  res.json({ job: publicJob(job) });
});
app.post('/jobs/:id/start', (req, res) => {
  const job = jobs.get(req.params.id);
  if (!job) return res.status(404).json({ error: 'Job not found' });
  if (job.status !== 'queued') return res.status(409).json({ error: `Cannot start job with status ${job.status}` });
  setImmediate(() => job.job_type === 'zip' ? executeZipJob(job) : executeHashJob(job));
  record('job.started', job.id);
  res.status(202).json({ job: publicJob(job) });
});
app.post('/jobs/:id/cancel', (req, res) => {
  const job = jobs.get(req.params.id);
  if (!job) return res.status(404).json({ error: 'Job not found' });
  const child = processes.get(job.id);
  if (child) child.kill('SIGTERM');
  job.status = 'cancelled'; job.completed_at = now(); job.updated_at = now();
  if (job.archive_path) fsp.rm(job.archive_path, { force: true }).catch(() => {});
  record('job.cancelled', job.id);
  res.json({ job: publicJob(job) });
});
app.get('/jobs/:id/results', (req, res) => {
  const job = jobs.get(req.params.id);
  if (!job) return res.status(404).json({ error: 'Job not found' });
  res.json({ results: job.results.map(publicResult), count: job.results.length });
});
app.post('/jobs/:id/results/:resultId/reveal', (req, res) => {
  const job = jobs.get(req.params.id);
  if (!job) return res.status(404).json({ error: 'Job not found' });
  const result = job.results.find(item => item.id === req.params.resultId);
  if (!result) return res.status(404).json({ error: 'Result not found' });
  if (req.body?.authorization_confirmed !== true || !String(req.body?.reason || '').trim()) {
    return res.status(400).json({ error: 'authorization_confirmed and reason are required' });
  }
  record('result.revealed', job.id, { result_id: result.id, account_identifier: result.account_identifier, reason: String(req.body.reason).slice(0, 300) });
  res.set('Cache-Control', 'no-store, private');
  res.json({ result_id: result.id, password: result.password, expires_in_seconds: 30 });
});
app.get('/audit-events', (req, res) => {
  const list = req.query.job_id ? auditEvents.filter(event => event.job_id === req.query.job_id) : auditEvents;
  res.json({ events: list, count: list.length });
});

app.use((error, _req, res, _next) => {
  if (error instanceof multer.MulterError || error?.message === 'Only .zip uploads are accepted') {
    return res.status(400).json({ error: error.message });
  }
  console.error(error);
  res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, HOST, () => console.log(`Cipher Audit API listening on http://${HOST}:${PORT}`));
