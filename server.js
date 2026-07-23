'use strict';

const crypto = require('crypto');
const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');
const { spawn } = require('child_process');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');

const app = express();
const PORT = Number(process.env.PORT || 10000);
const HOST = '0.0.0.0';
const API_TOKEN = process.env.AUDIT_API_TOKEN;
const DATA_DIR = process.env.DATA_DIR || '/tmp/cipher-audit';
const MAX_RUNTIME_MINUTES = Math.min(Number(process.env.MAX_RUNTIME_MINUTES || 30), 120);
const MAX_TARGETS = Math.min(Number(process.env.MAX_TARGETS || 500), 5000);
const MAX_WORDLIST_ENTRIES = Math.min(Number(process.env.MAX_WORDLIST_ENTRIES || 50000), 250000);

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
  md5crypt: { hashcat: '500', john: 'md5crypt', regex: /^\$1\$[^$]{1,8}\$[./A-Za-z0-9]{22}$/ },
  sha512crypt: { hashcat: '1800', john: 'sha512crypt', regex: /^\$6\$/ },
});

app.disable('x-powered-by');
app.use(helmet());
app.use(cors({
  origin: process.env.ALLOWED_ORIGIN || '*',
  methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Authorization', 'Content-Type', 'X-Request-Id'],
  maxAge: 86400,
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
function sanitizeName(value) { return String(value || '').replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 80); }
function publicResult(r) {
  return {
    id: r.id,
    account_identifier: r.account_identifier,
    recovered: r.recovered,
    verified: r.verified,
    password_length: r.password ? [...r.password].length : null,
    pattern_category: r.pattern_category,
    risk_rating: r.risk_rating,
    created_at: r.created_at,
  };
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
    recovered_count: job.results.filter(r => r.recovered).length,
    progress: job.progress,
    created_at: job.created_at,
    updated_at: job.updated_at,
    started_at: job.started_at,
    completed_at: job.completed_at,
    max_runtime_minutes: job.max_runtime_minutes,
    authorization_confirmed: job.authorization_confirmed,
    scope_confirmed: job.scope_confirmed,
    error: job.error || null,
  };
}
function classifyPassword(pw) {
  if (!pw) return null;
  if (/^[a-zA-Z]+\d{2,4}[!@#$%^&*]?$/u.test(pw)) return 'word-plus-digits';
  if (/^\d+$/u.test(pw)) return 'numeric';
  if (/^[a-z]+$/u.test(pw)) return 'lowercase-word';
  return 'mixed';
}
function riskRating(pw) {
  const n = [...pw].length;
  if (n < 8) return 'critical';
  if (n < 12) return 'high';
  if (n < 16) return 'medium';
  return 'low';
}
async function ensureJobDir(job) {
  const dir = path.join(DATA_DIR, job.id);
  await fsp.mkdir(dir, { recursive: true, mode: 0o700 });
  job.work_dir = dir;
  return dir;
}
function normalizeTargets(rawTargets, hashType) {
  if (!Array.isArray(rawTargets) || rawTargets.length === 0) throw new Error('targets must be a non-empty array');
  if (rawTargets.length > MAX_TARGETS) throw new Error(`Too many targets; maximum is ${MAX_TARGETS}`);
  const spec = HASH_TYPES[hashType];
  return rawTargets.map((target, index) => {
    const hash = String(target.hash || '').trim();
    if (!spec.regex.test(hash)) throw new Error(`Target ${index + 1} is not valid for ${hashType}`);
    return { id: target.id || crypto.randomUUID(), account_identifier: String(target.account_identifier || `target-${index + 1}`).slice(0, 200), hash };
  });
}
function normalizeWordlist(entries) {
  if (!Array.isArray(entries) || entries.length === 0) throw new Error('wordlist_entries must be a non-empty array');
  if (entries.length > MAX_WORDLIST_ENTRIES) throw new Error(`Wordlist exceeds ${MAX_WORDLIST_ENTRIES} entries`);
  return entries.map(v => String(v).replace(/[\r\n\0]/g, '').slice(0, 256)).filter(Boolean);
}
function spawnBounded(command, args, options, timeoutMs, jobId) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { ...options, shell: false, stdio: ['ignore', 'pipe', 'pipe'] });
    processes.set(jobId, child);
    let stdout = '', stderr = '';
    child.stdout.on('data', d => { stdout += d.toString(); if (stdout.length > 500000) stdout = stdout.slice(-500000); });
    child.stderr.on('data', d => { stderr += d.toString(); if (stderr.length > 500000) stderr = stderr.slice(-500000); });
    const timer = setTimeout(() => { child.kill('SIGTERM'); setTimeout(() => child.kill('SIGKILL'), 3000).unref(); }, timeoutMs);
    child.on('error', err => { clearTimeout(timer); processes.delete(jobId); reject(err); });
    child.on('close', code => { clearTimeout(timer); processes.delete(jobId); resolve({ code, stdout, stderr }); });
  });
}
function parsePotLine(line, hashes) {
  for (const hash of hashes.sort((a,b)=>b.length-a.length)) {
    if (line.startsWith(hash + ':')) return { hash, password: line.slice(hash.length + 1) };
  }
  return null;
}
async function runHashcat(job, hashFile, wordlistFile, potFile) {
  const args = ['-m', HASH_TYPES[job.hash_type].hashcat, '-a', '0', hashFile, wordlistFile,
    '--potfile-path', potFile, '--session', `cipher_${sanitizeName(job.id)}`, '--quiet', '--force'];
  const result = await spawnBounded('hashcat', args, { cwd: job.work_dir }, job.max_runtime_minutes * 60000, job.id);
  if (![0,1].includes(result.code)) throw new Error(`Hashcat failed (${result.code}): ${result.stderr.slice(-1000)}`);
}
async function runJohn(job, hashFile, wordlistFile, potFile) {
  const args = [`--format=${HASH_TYPES[job.hash_type].john}`, `--wordlist=${wordlistFile}`, `--pot=${potFile}`, `--session=cipher_${sanitizeName(job.id)}`, hashFile];
  const result = await spawnBounded('john', args, { cwd: job.work_dir }, job.max_runtime_minutes * 60000, job.id);
  if (![0,1].includes(result.code)) throw new Error(`John failed (${result.code}): ${result.stderr.slice(-1000)}`);
}
async function readResults(job, potFile) {
  let text = '';
  try { text = await fsp.readFile(potFile, 'utf8'); } catch (_) { return []; }
  const targetHashes = job.targets.map(t => t.hash);
  const cracked = new Map();
  for (const line of text.split(/\r?\n/)) {
    const parsed = parsePotLine(line, [...targetHashes]);
    if (parsed) cracked.set(parsed.hash, parsed.password);
  }
  return job.targets.filter(t => cracked.has(t.hash)).map(t => {
    const password = cracked.get(t.hash);
    return {
      id: crypto.randomUUID(), account_identifier: t.account_identifier, target_id: t.id,
      recovered: true, verified: true, password,
      pattern_category: classifyPassword(password), risk_rating: riskRating(password), created_at: now(),
    };
  });
}
async function executeJob(job) {
  try {
    job.status = 'running'; job.started_at = now(); job.updated_at = now(); job.progress = 5;
    const dir = await ensureJobDir(job);
    const hashFile = path.join(dir, 'hashes.txt');
    const wordlistFile = path.join(dir, 'wordlist.txt');
    const potFile = path.join(dir, `${job.engine}.pot`);
    await fsp.writeFile(hashFile, job.targets.map(t => t.hash).join('\n') + '\n', { mode: 0o600 });
    await fsp.writeFile(wordlistFile, job.wordlist_entries.join('\n') + '\n', { mode: 0o600 });
    job.progress = 15; job.updated_at = now();
    if (job.engine === 'hashcat') await runHashcat(job, hashFile, wordlistFile, potFile);
    else if (job.engine === 'jtr') await runJohn(job, hashFile, wordlistFile, potFile);
    else throw new Error('Unsupported engine');
    if (job.status === 'cancelled') return;
    job.progress = 90; job.updated_at = now();
    job.results = await readResults(job, potFile);
    job.progress = 100; job.status = 'completed'; job.completed_at = now(); job.updated_at = now();
    record('job.completed', job.id, { recovered_count: job.results.length });
  } catch (err) {
    if (job.status !== 'cancelled') {
      job.status = 'failed'; job.error = String(err.message || err).slice(0, 1500); job.completed_at = now(); job.updated_at = now();
      record('job.failed', job.id, { error: job.error });
    }
  }
}

app.get('/', (_req, res) => res.json({ service: 'cipher-audit-api', status: 'online', mode: 'bounded-live-worker' }));
app.get('/health', async (_req, res) => {
  const checks = {};
  for (const [name, cmd] of [['hashcat','hashcat'], ['jtr','john']]) {
    try {
      const r = await spawnBounded(cmd, ['--version'], {}, 5000, `health-${name}-${Date.now()}`);
      checks[name] = r.code === 0 ? 'available' : 'unavailable';
    } catch (_) { checks[name] = 'unavailable'; }
  }
  res.status(200).json({ status: 'ok', service: 'cipher-audit-api', mode: 'bounded-live-worker', engines: checks, timestamp: now() });
});

app.use(authenticate);
app.get('/capabilities', (_req, res) => res.json({ engines: ['hashcat','jtr'], attack_modes: ['wordlist'], hash_types: Object.keys(HASH_TYPES), limits: { max_targets: MAX_TARGETS, max_wordlist_entries: MAX_WORDLIST_ENTRIES, max_runtime_minutes: MAX_RUNTIME_MINUTES } }));
app.get('/jobs', (req, res) => { let list = [...jobs.values()]; if (req.query.status) list = list.filter(j => j.status === req.query.status); res.json({ jobs: list.map(publicJob), count: list.length }); });
app.post('/jobs', (req, res) => {
  try {
    const body = req.body || {};
    if (body.authorization_confirmed !== true || body.scope_confirmed !== true) return res.status(400).json({ error: 'Written authorization and confirmed scope are required.' });
    if (!['hashcat','jtr'].includes(body.engine)) return res.status(400).json({ error: 'engine must be hashcat or jtr' });
    const hashType = String(body.hash_type || '').toLowerCase();
    if (!HASH_TYPES[hashType]) return res.status(400).json({ error: `Unsupported hash_type. Allowed: ${Object.keys(HASH_TYPES).join(', ')}` });
    const targets = normalizeTargets(body.targets, hashType);
    const wordlist = normalizeWordlist(body.wordlist_entries);
    const runtime = Math.max(1, Math.min(Number(body.max_runtime_minutes || 10), MAX_RUNTIME_MINUTES));
    const id = crypto.randomUUID(), created = now();
    const job = { id, engagement_id: body.engagement_id || null, organization_id: body.organization_id || null,
      name: body.name || `Audit ${id.slice(0,8)}`, status: 'queued', engine: body.engine, hash_type: hashType,
      targets, wordlist_entries: wordlist, results: [], progress: 0, max_runtime_minutes: runtime,
      authorization_confirmed: true, scope_confirmed: true, created_at: created, updated_at: created, started_at: null, completed_at: null };
    jobs.set(id, job); record('job.created', id, { engine: job.engine, target_count: targets.length, hash_type: hashType });
    res.status(201).json({ job: publicJob(job) });
  } catch (err) { res.status(400).json({ error: String(err.message || err) }); }
});
app.get('/jobs/:id', (req,res)=>{ const j=jobs.get(req.params.id); if(!j)return res.status(404).json({error:'Job not found'}); res.json({job:publicJob(j)}); });
app.post('/jobs/:id/start', (req,res)=>{ const j=jobs.get(req.params.id); if(!j)return res.status(404).json({error:'Job not found'}); if(j.status!=='queued')return res.status(409).json({error:`Cannot start job with status ${j.status}`}); setImmediate(()=>executeJob(j)); record('job.started',j.id); res.status(202).json({job:publicJob(j)}); });
app.post('/jobs/:id/cancel', (req,res)=>{ const j=jobs.get(req.params.id); if(!j)return res.status(404).json({error:'Job not found'}); const p=processes.get(j.id); if(p){p.kill('SIGTERM');} j.status='cancelled';j.completed_at=now();j.updated_at=now();record('job.cancelled',j.id);res.json({job:publicJob(j)}); });
app.get('/jobs/:id/results', (req,res)=>{ const j=jobs.get(req.params.id); if(!j)return res.status(404).json({error:'Job not found'}); res.json({results:j.results.map(publicResult),count:j.results.length}); });
app.post('/jobs/:id/results/:resultId/reveal', (req,res)=>{
  const j=jobs.get(req.params.id); if(!j)return res.status(404).json({error:'Job not found'});
  const r=j.results.find(x=>x.id===req.params.resultId); if(!r)return res.status(404).json({error:'Result not found'});
  if (req.body?.authorization_confirmed !== true || !String(req.body?.reason || '').trim()) return res.status(400).json({error:'authorization_confirmed and reason are required'});
  record('result.revealed',j.id,{result_id:r.id,account_identifier:r.account_identifier,reason:String(req.body.reason).slice(0,300)});
  res.set('Cache-Control','no-store, private'); res.json({result_id:r.id,password:r.password,expires_in_seconds:30});
});
app.get('/audit-events', (req,res)=>{ const jobId=req.query.job_id; const list=jobId?auditEvents.filter(e=>e.job_id===jobId):auditEvents; res.json({events:list,count:list.length}); });

app.listen(PORT, HOST, () => console.log(`Cipher Audit API listening on http://${HOST}:${PORT}`));
