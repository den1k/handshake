// Handshake local server: Google sign-in, ledgers with members and one-time invites,
// rules kept append-only in SQLite (the database itself refuses updates and deletes of
// entries and agreements), and rule checks through a fast model behind an
// OpenAI-compatible API (Groq's gpt-oss-20b by default).
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import net from 'node:net';
import tls from 'node:tls';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT) || 4317;
const HOST = process.env.HOST || '127.0.0.1';
const BASE_URL = (process.env.BASE_URL || `http://localhost:${PORT}`).replace(/\/$/, '');
const BASE = new URL(BASE_URL);
const DATA_DIR = process.env.DATA_DIR || path.join(ROOT, 'data');
const DB_FILE = path.join(DATA_DIR, 'handshake.db');
const GOOGLE_ID = process.env.GOOGLE_CLIENT_ID || '';
const GOOGLE_SECRET = process.env.GOOGLE_CLIENT_SECRET || '';
const REDIRECT_URI = `${BASE_URL}/auth/google/callback`;
const SESSION_DAYS = 30;
const INVITE_DAYS = 7;
const ID_RE = /^[A-Za-z0-9_-]{6,64}$/;
const TOKEN_RE = /^[A-Za-z0-9_-]{20,100}$/;
const MAX_PROMPT = 40000;

// The model that checks drafts. Any OpenAI-compatible chat endpoint works (a local
// Ollama or LM Studio server too); the defaults are Groq's gpt-oss-20b.
const AI_URL = process.env.AI_URL || 'https://api.groq.com/openai/v1/chat/completions';
const AI_MODEL = process.env.AI_MODEL || 'openai/gpt-oss-20b';
const AI_KEY = process.env.GROQ_API_KEY || process.env.AI_API_KEY || '';
const AI_TIMEOUT_MS = 30 * 1000;
// Behind a reverse proxy, the client's address arrives in X-Forwarded-For; only trust it when told to.
const TRUST_PROXY = process.env.TRUST_PROXY === '1';
// Email: Resend's API if RESEND_API_KEY is set, else an SMTP server from SMTP_URL (smtps://user:pass@host:465 or
// smtp://user:pass@host:587 with STARTTLS), else messages are written to DATA_DIR/outbox for development.
const RESEND_KEY = process.env.RESEND_API_KEY || '';
const SMTP_URL = process.env.SMTP_URL || '';
const MAIL_FROM = process.env.MAIL_FROM || 'Handshake <handshake@localhost>';
const MAIL_TRANSPORT = RESEND_KEY ? 'resend' : SMTP_URL ? 'smtp' : 'outbox';
const CODE_MINUTES = 10;
// The notice each person accepts once before signing electronically. Bump the version when the text changes.
const ESIGN_VERSION = '2026-10-19';
const ESIGN_NOTICE = 'I agree to use electronic records and electronic signatures for Handshake ledgers marked as legally binding. My electronic signature has the same effect as my handwritten one. I can view, print or save a certificate of anything I sign, and I can ask the other members for a paper copy. I can withdraw this consent by leaving a ledger; that doesn’t undo signatures I’ve already made.';

/* ---------- storage ---------- */
// Entries and agreements are append-only: triggers make SQLite itself reject any UPDATE or
// DELETE. (Tables from the single-ledger version, rules/agreements/people, are left as they were.)
fs.mkdirSync(DATA_DIR, { recursive: true });
const sql = new DatabaseSync(DB_FILE);
sql.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA synchronous = FULL;
  PRAGMA foreign_keys = ON;
  CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, email TEXT NOT NULL, name TEXT NOT NULL, picture TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL) STRICT;
  CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), expires_at TEXT NOT NULL) STRICT;
  CREATE TABLE IF NOT EXISTS ledgers (id TEXT PRIMARY KEY, name TEXT NOT NULL, created_by TEXT NOT NULL REFERENCES users(id), created_at TEXT NOT NULL) STRICT;
  CREATE TABLE IF NOT EXISTS members (ledger_id TEXT NOT NULL REFERENCES ledgers(id), user_id TEXT NOT NULL REFERENCES users(id), role TEXT NOT NULL, joined_at TEXT NOT NULL, PRIMARY KEY (ledger_id, user_id)) STRICT;
  CREATE TABLE IF NOT EXISTS invites (token TEXT PRIMARY KEY, ledger_id TEXT NOT NULL REFERENCES ledgers(id), created_by TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL, used_by TEXT, used_at TEXT) STRICT;
  CREATE TABLE IF NOT EXISTS entries (id TEXT PRIMARY KEY, ledger_id TEXT NOT NULL REFERENCES ledgers(id), author_id TEXT NOT NULL REFERENCES users(id), created_at TEXT NOT NULL, required TEXT NOT NULL, doc TEXT NOT NULL) STRICT;
  CREATE TABLE IF NOT EXISTS entry_agreements (entry_id TEXT NOT NULL REFERENCES entries(id), user_id TEXT NOT NULL REFERENCES users(id), at TEXT NOT NULL, PRIMARY KEY (entry_id, user_id)) STRICT;
  CREATE INDEX IF NOT EXISTS entries_by_ledger ON entries (ledger_id, created_at);
  CREATE TRIGGER IF NOT EXISTS entries_no_update BEFORE UPDATE ON entries BEGIN SELECT RAISE(ABORT, 'entries are append-only'); END;
  CREATE TRIGGER IF NOT EXISTS entries_no_delete BEFORE DELETE ON entries BEGIN SELECT RAISE(ABORT, 'entries are append-only'); END;
  CREATE TRIGGER IF NOT EXISTS entry_agreements_no_update BEFORE UPDATE ON entry_agreements BEGIN SELECT RAISE(ABORT, 'agreements are append-only'); END;
  CREATE TRIGGER IF NOT EXISTS entry_agreements_no_delete BEFORE DELETE ON entry_agreements BEGIN SELECT RAISE(ABORT, 'agreements are append-only'); END;
  -- Legally binding ledgers: a hash chain over entries, consent to e-signatures, and signatures with an audit trail.
  CREATE TABLE IF NOT EXISTS entry_hashes (entry_id TEXT PRIMARY KEY REFERENCES entries(id), ledger_id TEXT NOT NULL, seq INTEGER NOT NULL, prev_hash TEXT NOT NULL, hash TEXT NOT NULL) STRICT;
  CREATE TABLE IF NOT EXISTS esign_consents (user_id TEXT NOT NULL REFERENCES users(id), version TEXT NOT NULL, notice TEXT NOT NULL, at TEXT NOT NULL, ip TEXT NOT NULL, ua TEXT NOT NULL, PRIMARY KEY (user_id, version)) STRICT;
  CREATE TABLE IF NOT EXISTS ledger_signatures (ledger_id TEXT NOT NULL REFERENCES ledgers(id), user_id TEXT NOT NULL REFERENCES users(id), at TEXT NOT NULL, typed_name TEXT NOT NULL, statement TEXT NOT NULL, head_hash TEXT NOT NULL, entry_count INTEGER NOT NULL, email TEXT NOT NULL, ip TEXT NOT NULL, ua TEXT NOT NULL, PRIMARY KEY (ledger_id, user_id)) STRICT;
  CREATE TABLE IF NOT EXISTS entry_signatures (entry_id TEXT NOT NULL REFERENCES entries(id), user_id TEXT NOT NULL REFERENCES users(id), at TEXT NOT NULL, typed_name TEXT NOT NULL, statement TEXT NOT NULL, entry_hash TEXT NOT NULL, email TEXT NOT NULL, ip TEXT NOT NULL, ua TEXT NOT NULL, PRIMARY KEY (entry_id, user_id)) STRICT;
  CREATE TRIGGER IF NOT EXISTS entry_hashes_no_update BEFORE UPDATE ON entry_hashes BEGIN SELECT RAISE(ABORT, 'append-only'); END;
  CREATE TRIGGER IF NOT EXISTS entry_hashes_no_delete BEFORE DELETE ON entry_hashes BEGIN SELECT RAISE(ABORT, 'append-only'); END;
  CREATE TRIGGER IF NOT EXISTS esign_consents_no_update BEFORE UPDATE ON esign_consents BEGIN SELECT RAISE(ABORT, 'append-only'); END;
  CREATE TRIGGER IF NOT EXISTS esign_consents_no_delete BEFORE DELETE ON esign_consents BEGIN SELECT RAISE(ABORT, 'append-only'); END;
  CREATE TRIGGER IF NOT EXISTS ledger_signatures_no_update BEFORE UPDATE ON ledger_signatures BEGIN SELECT RAISE(ABORT, 'append-only'); END;
  CREATE TRIGGER IF NOT EXISTS ledger_signatures_no_delete BEFORE DELETE ON ledger_signatures BEGIN SELECT RAISE(ABORT, 'append-only'); END;
  CREATE TRIGGER IF NOT EXISTS entry_signatures_no_update BEFORE UPDATE ON entry_signatures BEGIN SELECT RAISE(ABORT, 'append-only'); END;
  CREATE TRIGGER IF NOT EXISTS entry_signatures_no_delete BEFORE DELETE ON entry_signatures BEGIN SELECT RAISE(ABORT, 'append-only'); END;
`);
// Columns added after the first release of accounts.
const hasColumn = (table, col) => sql.prepare(`PRAGMA table_info(${table})`).all().some(c => c.name === col);
if (!hasColumn('ledgers', 'binding_since')) sql.exec(`ALTER TABLE ledgers ADD COLUMN binding_since TEXT NOT NULL DEFAULT ''`);
if (!hasColumn('ledgers', 'governing_law')) sql.exec(`ALTER TABLE ledgers ADD COLUMN governing_law TEXT NOT NULL DEFAULT ''`);
if (!hasColumn('ledgers', 'verify_email')) sql.exec(`ALTER TABLE ledgers ADD COLUMN verify_email INTEGER NOT NULL DEFAULT 0`);
if (!hasColumn('sessions', 'auth_at')) sql.exec(`ALTER TABLE sessions ADD COLUMN auth_at TEXT NOT NULL DEFAULT ''`);
for (const t of ['ledger_signatures', 'entry_signatures']) {
  if (!hasColumn(t, 'method')) sql.exec(`ALTER TABLE ${t} ADD COLUMN method TEXT NOT NULL DEFAULT 'Google sign-in'`);
  if (!hasColumn(t, 'auth_at')) sql.exec(`ALTER TABLE ${t} ADD COLUMN auth_at TEXT NOT NULL DEFAULT ''`);
}
sql.exec(`
  -- One-time codes emailed to confirm a signature (stored hashed, short-lived, few attempts).
  CREATE TABLE IF NOT EXISTS signing_codes (user_id TEXT NOT NULL, ledger_id TEXT NOT NULL, purpose TEXT NOT NULL, code_hash TEXT NOT NULL, expires_at TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (user_id, ledger_id, purpose)) STRICT;
  CREATE TABLE IF NOT EXISTS email_log (at TEXT NOT NULL, to_addr TEXT NOT NULL, subject TEXT NOT NULL, transport TEXT NOT NULL, status TEXT NOT NULL, error TEXT NOT NULL DEFAULT '') STRICT;
`);
const q = {
  upsertUser: sql.prepare(`INSERT INTO users (id, email, name, picture, created_at) VALUES (?, ?, ?, ?, ?)
    ON CONFLICT (id) DO UPDATE SET email = excluded.email, name = excluded.name, picture = excluded.picture`),
  user: sql.prepare('SELECT id, email, name, picture FROM users WHERE id = ?'),
  addSession: sql.prepare('INSERT INTO sessions (id, user_id, expires_at, auth_at) VALUES (?, ?, ?, ?)'),
  session: sql.prepare('SELECT user_id, expires_at, auth_at FROM sessions WHERE id = ?'),
  dropSession: sql.prepare('DELETE FROM sessions WHERE id = ?'),
  dropExpired: sql.prepare('DELETE FROM sessions WHERE expires_at < ?'),
  addLedger: sql.prepare('INSERT INTO ledgers (id, name, created_by, created_at, binding_since, governing_law) VALUES (?, ?, ?, ?, ?, ?)'),
  ledger: sql.prepare('SELECT id, name, created_by, created_at, binding_since, governing_law, verify_email FROM ledgers WHERE id = ?'),
  setVerify: sql.prepare('UPDATE ledgers SET verify_email = ? WHERE id = ?'),
  leave: sql.prepare(`DELETE FROM members WHERE ledger_id = ? AND user_id = ? AND role != 'owner'`),
  setCode: sql.prepare('INSERT OR REPLACE INTO signing_codes (user_id, ledger_id, purpose, code_hash, expires_at, attempts) VALUES (?, ?, ?, ?, ?, 0)'),
  code: sql.prepare('SELECT code_hash, expires_at, attempts FROM signing_codes WHERE user_id = ? AND ledger_id = ? AND purpose = ?'),
  codeMiss: sql.prepare('UPDATE signing_codes SET attempts = attempts + 1 WHERE user_id = ? AND ledger_id = ? AND purpose = ?'),
  codeDone: sql.prepare('DELETE FROM signing_codes WHERE user_id = ? AND ledger_id = ? AND purpose = ?'),
  logMail: sql.prepare('INSERT INTO email_log (at, to_addr, subject, transport, status, error) VALUES (?, ?, ?, ?, ?, ?)'),
  // Binding can be switched on, never off: only rows still non-binding change.
  makeBinding: sql.prepare(`UPDATE ledgers SET binding_since = ?, governing_law = ? WHERE id = ? AND binding_since = ''`),
  setLaw: sql.prepare('UPDATE ledgers SET governing_law = ? WHERE id = ?'),
  lastHash: sql.prepare('SELECT seq, hash FROM entry_hashes WHERE ledger_id = ? ORDER BY seq DESC LIMIT 1'),
  addHash: sql.prepare('INSERT INTO entry_hashes (entry_id, ledger_id, seq, prev_hash, hash) VALUES (?, ?, ?, ?, ?)'),
  hashes: sql.prepare('SELECT entry_id, seq, prev_hash, hash FROM entry_hashes WHERE ledger_id = ? ORDER BY seq'),
  entryHash: sql.prepare('SELECT hash, prev_hash, seq FROM entry_hashes WHERE entry_id = ?'),
  unhashed: sql.prepare(`SELECT e.id, e.ledger_id, e.author_id, e.created_at, e.required, e.doc FROM entries e
    LEFT JOIN entry_hashes h ON h.entry_id = e.id WHERE h.entry_id IS NULL ORDER BY e.ledger_id, e.created_at, e.id`),
  fullEntries: sql.prepare('SELECT e.id, e.ledger_id, e.author_id, e.created_at, e.required, e.doc FROM entries e JOIN entry_hashes h ON h.entry_id = e.id WHERE e.ledger_id = ? ORDER BY h.seq'),
  consent: sql.prepare('SELECT at FROM esign_consents WHERE user_id = ? AND version = ?'),
  consents: sql.prepare('SELECT version, at, ip, ua FROM esign_consents WHERE user_id = ? ORDER BY at'),
  addConsent: sql.prepare('INSERT OR IGNORE INTO esign_consents (user_id, version, notice, at, ip, ua) VALUES (?, ?, ?, ?, ?, ?)'),
  ledgerSig: sql.prepare('SELECT at FROM ledger_signatures WHERE ledger_id = ? AND user_id = ?'),
  ledgerSigs: sql.prepare(`SELECT s.user_id, s.at, s.typed_name, s.statement, s.head_hash, s.entry_count, s.email, s.ip, s.ua, s.method, s.auth_at, u.name
    FROM ledger_signatures s JOIN users u ON u.id = s.user_id WHERE s.ledger_id = ? ORDER BY s.at`),
  addLedgerSig: sql.prepare('INSERT OR IGNORE INTO ledger_signatures (ledger_id, user_id, at, typed_name, statement, head_hash, entry_count, email, ip, ua, method, auth_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'),
  entrySigs: sql.prepare(`SELECT s.entry_id, s.user_id, s.at, s.typed_name, s.statement, s.entry_hash, s.email, s.ip, s.ua, s.method, s.auth_at, u.name
    FROM entry_signatures s JOIN entries e ON e.id = s.entry_id JOIN users u ON u.id = s.user_id WHERE e.ledger_id = ? ORDER BY s.at`),
  addEntrySig: sql.prepare('INSERT OR IGNORE INTO entry_signatures (entry_id, user_id, at, typed_name, statement, entry_hash, email, ip, ua, method, auth_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'),
  myLedgers: sql.prepare(`SELECT l.id, l.name, m.role, l.binding_since != '' AS binding, (SELECT COUNT(*) FROM members x WHERE x.ledger_id = l.id) AS members
    FROM ledgers l JOIN members m ON m.ledger_id = l.id WHERE m.user_id = ? ORDER BY l.created_at`),
  addMember: sql.prepare('INSERT OR IGNORE INTO members (ledger_id, user_id, role, joined_at) VALUES (?, ?, ?, ?)'),
  member: sql.prepare('SELECT role FROM members WHERE ledger_id = ? AND user_id = ?'),
  members: sql.prepare(`SELECT u.id, u.name, u.email, u.picture, m.role, m.joined_at FROM members m JOIN users u ON u.id = m.user_id
    WHERE m.ledger_id = ? ORDER BY m.joined_at`),
  addInvite: sql.prepare('INSERT INTO invites (token, ledger_id, created_by, created_at, expires_at) VALUES (?, ?, ?, ?, ?)'),
  invite: sql.prepare(`SELECT i.ledger_id, i.expires_at, i.used_by, l.name AS ledger_name, u.name AS inviter
    FROM invites i JOIN ledgers l ON l.id = i.ledger_id JOIN users u ON u.id = i.created_by WHERE i.token = ?`),
  useInvite: sql.prepare('UPDATE invites SET used_by = ?, used_at = ? WHERE token = ? AND used_by IS NULL'),
  addEntry: sql.prepare('INSERT INTO entries (id, ledger_id, author_id, created_at, required, doc) VALUES (?, ?, ?, ?, ?, ?)'),
  entry: sql.prepare('SELECT ledger_id, author_id, required FROM entries WHERE id = ?'),
  entries: sql.prepare('SELECT id, author_id, created_at, required, doc FROM entries WHERE ledger_id = ? ORDER BY created_at, id'),
  entryIds: sql.prepare('SELECT id FROM entries WHERE ledger_id = ?'),
  agree: sql.prepare('INSERT OR IGNORE INTO entry_agreements (entry_id, user_id, at) VALUES (?, ?, ?)'),
  agreements: sql.prepare(`SELECT a.entry_id, a.user_id, a.at FROM entry_agreements a JOIN entries e ON e.id = a.entry_id
    WHERE e.ledger_id = ? ORDER BY a.at`),
};
const now = () => new Date().toISOString();
const later = days => new Date(Date.now() + days * 864e5).toISOString();
const token = (bytes = 24) => crypto.randomBytes(bytes).toString('base64url');
// Sessions and invite tokens are stored only as hashes, so a copy of the database can't be used to sign in or join.
const digest = t => crypto.createHash('sha256').update(String(t)).digest('hex');

/* ---------- the hash chain ----------
   Each entry's fingerprint covers its exact stored content plus the previous entry's fingerprint, so changing,
   removing or reordering anything in a ledger's history breaks every fingerprint after it. */
const genesis = lid => digest('handshake:ledger:' + lid);
const entryDigest = (e, prev) => digest(prev + '\n' + JSON.stringify([e.id, e.ledger_id, e.author_id, e.created_at, e.required, e.doc]));
function chainEntry(e) {
  const last = q.lastHash.get(e.ledger_id);
  const prev = last ? last.hash : genesis(e.ledger_id), hash = entryDigest(e, prev);
  q.addHash.run(e.id, e.ledger_id, last ? last.seq + 1 : 1, prev, hash);
  return hash;
}
function headOf(lid) { const last = q.lastHash.get(lid); return { hash: last ? last.hash : genesis(lid), count: last ? last.seq : 0 }; }
function verifyLedger(lid) {
  let prev = genesis(lid), n = 0;
  const stored = new Map(q.hashes.all(lid).map(h => [h.entry_id, h]));
  for (const e of q.fullEntries.all(lid)) {
    const h = stored.get(e.id); n++;
    if (h.prev_hash !== prev || h.hash !== entryDigest(e, prev)) return { ok: false, count: n, brokenAt: n };
    prev = h.hash;
  }
  return { ok: true, count: n, head: prev };
}

function tx(fn) {
  sql.exec('BEGIN');
  try { const out = fn(); sql.exec('COMMIT'); return out; } catch (e) { sql.exec('ROLLBACK'); throw e; }
}

// Entries written before the hash chain existed get their fingerprints once, in recorded order.
{
  const pendingHash = q.unhashed.all();
  if (pendingHash.length) { sql.exec('BEGIN'); try { for (const e of pendingHash) chainEntry(e); sql.exec('COMMIT'); } catch (err) { sql.exec('ROLLBACK'); throw err; } }
}

/* ---------- sessions ---------- */
function cookies(req) {
  const out = {};
  for (const part of String(req.headers.cookie || '').split(';')) {
    const i = part.indexOf('=');
    if (i < 1) continue;
    try { out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim()); } catch { /* malformed: ignore */ }
  }
  return out;
}
const cookie = (name, value, maxAge) => `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${BASE.protocol === 'https:' ? '; Secure' : ''}`;
function currentUser(req) {
  const sid = cookies(req).hs_session;
  if (!sid) return null;
  const s = q.session.get(digest(sid));
  if (!s || s.expires_at < now()) return null;
  const u = q.user.get(s.user_id);
  return u ? Object.assign(u, { authAt: s.auth_at }) : null;
}

/* ---------- Google sign-in (authorization code flow with PKCE) ---------- */
const pending = new Map(); // state → { verifier, next, at }
function startGoogle(res, next) {
  const state = token(16), verifier = token(32);
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  for (const [k, v] of pending) if (Date.now() - v.at > 10 * 60 * 1000) pending.delete(k);
  while (pending.size >= 5000) pending.delete(pending.keys().next().value); // bounded, oldest first
  pending.set(state, { verifier, next, at: Date.now() });
  const u = new URL('https://accounts.google.com/o/oauth2/v2/auth');
  u.search = new URLSearchParams({ client_id: GOOGLE_ID, redirect_uri: REDIRECT_URI, response_type: 'code', scope: 'openid email profile',
    state, code_challenge: challenge, code_challenge_method: 'S256', prompt: 'select_account' }).toString();
  res.writeHead(302, { ...SECURITY, location: u.toString(), 'set-cookie': cookie('hs_state', state, 600), 'cache-control': 'no-store' });
  res.end();
}
async function finishGoogle(req, res, url) {
  const state = url.searchParams.get('state'), code = url.searchParams.get('code');
  const p = state && pending.get(state);
  // The state must be one this server issued, to this same browser, in the last ten minutes.
  if (!p || cookies(req).hs_state !== state || !code || !GOOGLE_ID) return page(res, 400, 'Sign-in didn’t complete', 'The sign-in link expired or was opened in another browser. Go back and try again.');
  pending.delete(state);
  const r = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ code, client_id: GOOGLE_ID, client_secret: GOOGLE_SECRET, redirect_uri: REDIRECT_URI, grant_type: 'authorization_code', code_verifier: p.verifier }),
  });
  const out = await r.json().catch(() => ({}));
  if (!r.ok || !out.id_token) return page(res, 502, 'Sign-in didn’t complete', `Google said: ${String(out.error_description || out.error || r.status).slice(0, 200)}`);
  // The ID token came straight from Google over TLS in exchange for our code, so its claims can be read directly.
  let claims = {};
  try { claims = JSON.parse(Buffer.from(String(out.id_token).split('.')[1] || '', 'base64url').toString('utf8')); } catch { /* checked below */ }
  if (!['https://accounts.google.com', 'accounts.google.com'].includes(claims.iss) || claims.aud !== GOOGLE_ID || claims.exp * 1000 < Date.now() || !claims.email_verified)
    return page(res, 400, 'Sign-in didn’t complete', 'Google returned an account this app can’t accept (an unverified email address).');
  const uid = 'g_' + claims.sub;
  q.upsertUser.run(uid, String(claims.email), String(claims.name || claims.email).slice(0, 80), String(claims.picture || ''), now());
  const sid = token();
  q.dropExpired.run(now());
  q.addSession.run(digest(sid), uid, later(SESSION_DAYS), now());
  res.writeHead(302, { ...SECURITY, location: safeNext(p.next), 'set-cookie': [cookie('hs_session', sid, SESSION_DAYS * 86400), cookie('hs_state', '', 0)], 'cache-control': 'no-store' });
  res.end();
}

/* ---------- email ---------- */
const addrOf = s => { const m = String(s).match(/<([^>]+)>/); return (m ? m[1] : String(s)).trim(); };
const b64 = s => Buffer.from(s, 'utf8').toString('base64').replace(/.{76}/g, '$&\r\n');
function mime({ from, to, subject, text, html }) {
  const boundary = 'hs_' + token(12);
  const head = [`From: ${from}`, `To: ${to.join(', ')}`, `Subject: =?UTF-8?B?${Buffer.from(subject, 'utf8').toString('base64')}?=`,
    `Date: ${new Date().toUTCString()}`, `Message-ID: <${token(16)}@${BASE.hostname}>`, 'MIME-Version: 1.0', `Content-Type: multipart/alternative; boundary="${boundary}"`];
  const part = (type, body) => `--${boundary}\r\nContent-Type: ${type}; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n${b64(body)}\r\n`;
  return head.join('\r\n') + '\r\n\r\n' + part('text/plain', text) + (html ? part('text/html', html) : '') + `--${boundary}--\r\n`;
}
// A minimal SMTP client: implicit TLS (smtps) or STARTTLS (smtp); plain text only to a local test server.
function smtpSend(urlStr, from, to, raw) {
  return new Promise((resolve, reject) => {
    const u = new URL(urlStr), secure = u.protocol === 'smtps:', host = u.hostname, port = Number(u.port) || (secure ? 465 : 587);
    const local = ['localhost', '127.0.0.1', '::1'].includes(host);
    let sock = secure ? tls.connect({ host, port, servername: host }) : net.connect({ host, port });
    let buf = '', waiting = null;
    const timer = setTimeout(() => { sock.destroy(); reject(new Error('SMTP timed out')); }, 20000);
    const onData = d => { buf += d; flush(); };
    const flush = () => {
      if (!waiting) return;
      const lines = buf.split('\r\n'), done = lines.findIndex(l => /^\d{3} /.test(l));
      if (done < 0) return;
      const reply = lines.slice(0, done + 1).join('\n'); buf = lines.slice(done + 1).join('\r\n');
      const w = waiting; waiting = null; w(reply);
    };
    const read = () => new Promise(r => { waiting = r; flush(); });
    const cmd = async (line, ok) => { if (line != null) sock.write(line + '\r\n'); const r = await read(); if (!ok.includes(r.slice(0, 3))) throw new Error(`SMTP ${line ? line.split(' ')[0] : 'greeting'}: ${r.slice(0, 200)}`); return r; };
    sock.setEncoding('utf8'); sock.on('data', onData);
    sock.on('error', e => { clearTimeout(timer); reject(e); });
    (async () => {
      await cmd(null, ['220']);
      let ehlo = await cmd(`EHLO ${BASE.hostname}`, ['250']);
      if (!secure) {
        if (/STARTTLS/i.test(ehlo)) {
          await cmd('STARTTLS', ['220']);
          sock.off('data', onData);
          sock = tls.connect({ socket: sock, servername: host }); sock.setEncoding('utf8'); sock.on('data', onData);
          await new Promise((r, j) => { sock.once('secureConnect', r); sock.once('error', j); });
          ehlo = await cmd(`EHLO ${BASE.hostname}`, ['250']);
        } else if (!local) throw new Error('SMTP server offers no STARTTLS; refusing to send in plain text');
      }
      if (u.username) await cmd('AUTH PLAIN ' + Buffer.from(`\0${decodeURIComponent(u.username)}\0${decodeURIComponent(u.password)}`).toString('base64'), ['235']);
      await cmd(`MAIL FROM:<${addrOf(from)}>`, ['250']);
      for (const t of to) await cmd(`RCPT TO:<${addrOf(t)}>`, ['250', '251']);
      await cmd('DATA', ['354']);
      await cmd(raw.replace(/\r?\n/g, '\r\n').replace(/^\./gm, '..') + '\r\n.', ['250']);
      sock.write('QUIT\r\n'); sock.end();
      clearTimeout(timer); resolve();
    })().catch(e => { clearTimeout(timer); sock.destroy(); reject(e); });
  });
}
// Fire-and-forget delivery, logged; a failed email never fails the request that caused it.
async function sendMail({ to, subject, text, html }) {
  to = [...new Set(to.filter(Boolean))];
  if (!to.length) return false;
  const at = now();
  try {
    if (MAIL_TRANSPORT === 'resend') {
      const r = await fetch('https://api.resend.com/emails', { method: 'POST', headers: { authorization: `Bearer ${RESEND_KEY}`, 'content-type': 'application/json' },
        body: JSON.stringify({ from: MAIL_FROM, to, subject, text, html }) });
      if (!r.ok) throw new Error(`Resend ${r.status}: ${(await r.text()).slice(0, 200)}`);
    } else if (MAIL_TRANSPORT === 'smtp') {
      await smtpSend(SMTP_URL, MAIL_FROM, to, mime({ from: MAIL_FROM, to, subject, text, html }));
    } else {
      const dir = path.join(DATA_DIR, 'outbox');
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
      fs.writeFileSync(path.join(dir, `${at.replace(/[:.]/g, '-')}-${token(4)}.eml`), mime({ from: MAIL_FROM, to, subject, text, html }), { mode: 0o600 });
    }
    for (const t of to) q.logMail.run(at, t, subject, MAIL_TRANSPORT, 'sent', '');
    return true;
  } catch (e) {
    console.error('[mail]', e.message);
    for (const t of to) q.logMail.run(at, t, subject, MAIL_TRANSPORT, 'failed', String(e.message).slice(0, 300));
    return false;
  }
}

/* ---------- limits ---------- */
// A small in-memory sliding window per key: enough to stop one account from hammering the server or the model.
const hits = new Map();
function allow(key, max, windowMs) {
  const t = Date.now(), list = (hits.get(key) || []).filter(x => t - x < windowMs);
  if (list.length >= max) { hits.set(key, list); return false; }
  list.push(t); hits.set(key, list);
  if (hits.size > 20000) for (const [k, v] of hits) if (!v.length || t - v[v.length - 1] > 3600e3) hits.delete(k);
  return true;
}
// Only ever redirect within this site: a path on BASE_URL, never another origin (including "/\\evil.com").
function safeNext(next) {
  try {
    const u = new URL(String(next || '/'), BASE_URL);
    return u.origin === BASE.origin ? u.pathname + u.search : '/';
  } catch { return '/'; }
}

/* ---------- the fast model ---------- */
async function askModel(prompt, res) {
  if (!AI_KEY && AI_URL.includes('groq.com')) throw Object.assign(new Error('No API key. Start the server with GROQ_API_KEY set.'), { code: 'no_key' });
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), AI_TIMEOUT_MS);
  // The browser pressed Stop (or left) if the response closes before we answered.
  const onAbort = () => { if (!res.writableEnded) ctl.abort(); };
  res.on('close', onAbort);
  try {
    const r = await fetch(AI_URL, {
      method: 'POST',
      signal: ctl.signal,
      headers: { 'content-type': 'application/json', ...(AI_KEY ? { authorization: `Bearer ${AI_KEY}` } : {}) },
      body: JSON.stringify({
        model: AI_MODEL,
        messages: [
          { role: 'system', content: 'You are a careful, neutral drafting assistant. Follow the instructions exactly and reply with one JSON object only.' },
          { role: 'user', content: prompt },
        ],
        response_format: { type: 'json_object' },
        reasoning_effort: 'low',
        temperature: 0.2,
        max_completion_tokens: 2500,
      }),
    });
    const out = await r.json().catch(() => ({}));
    if (!r.ok) throw Object.assign(new Error(String((out.error && out.error.message) || `HTTP ${r.status}`).slice(0, 300)), { code: r.status === 429 ? 'rate_limited' : 'upstream_error' });
    const text = out.choices && out.choices[0] && out.choices[0].message && out.choices[0].message.content;
    if (typeof text !== 'string' || !text.trim()) throw Object.assign(new Error('Empty answer'), { code: 'empty_completion' });
    return text;
  } catch (e) {
    if (e.name === 'AbortError') throw Object.assign(new Error('The check took too long or was stopped.'), { code: 'cancelled' });
    if (!e.code) e.code = 'upstream_error';
    throw e;
  } finally {
    clearTimeout(timer);
    res.off('close', onAbort);
  }
}

/* ---------- ledgers ---------- */
const clientIp = req => String((TRUST_PROXY && String(req.headers['x-forwarded-for'] || '').split(',')[0].trim()) || req.socket.remoteAddress || '').slice(0, 64);
const clientUa = req => String(req.headers['user-agent'] || '').slice(0, 300);
const ledgerStatement = (l, count, head) => `I have read the rules recorded in the ledger “${l.name}” (${count} entr${count === 1 ? 'y' : 'ies'}, fingerprint ${head}). I intend to be legally bound by every rule in it that is in force, and by each rule I sign from now on${l.governing_law ? `, under ${l.governing_law}` : ''}. I am signing electronically.`;
const entryStatement = (l, n, hash) => `I intend to be legally bound by § ${n} of the ledger “${l.name}” exactly as written (fingerprint ${hash})${l.governing_law ? `, under ${l.governing_law}` : ''}. I am signing electronically.`;
// What a signature in a binding ledger must carry from the page.
function signatureFrom(body) {
  const name = typeof body.typedName === 'string' ? body.typedName.trim().replace(/\s+/g, ' ').slice(0, 120) : '';
  if (name.length < 2 || body.intent !== true) return null;
  return name;
}
// Before signing anything in a binding ledger: consent to e-signatures, then sign the ledger itself.
function bindingBlock(lid, me) {
  if (!q.consent.get(me.id, ESIGN_VERSION)) return { code: 'needs_consent', message: 'Accept the notice about electronic signatures first.' };
  if (!q.ledgerSig.get(lid, me.id)) return { code: 'needs_ledger_signature', message: 'Sign the ledger before signing rules in it.' };
  return null;
}
const entryNumber = (lid, eid) => { const h = q.entryHash.get(eid); return h ? h.seq : 0; };
// Ledgers that ask for it confirm every signature with a six-digit code emailed to the signer's Google address.
function checkCode(l, me, purpose, code) {
  if (!l.verify_email) return null;
  const c = q.code.get(me.id, l.id, purpose);
  if (!c || c.expires_at < now()) return { code: 'needs_code', message: 'Email yourself a code and enter it to sign.' };
  if (c.attempts >= 5) { q.codeDone.run(me.id, l.id, purpose); return { code: 'needs_code', message: 'Too many wrong codes. Email yourself a new one.' }; }
  if (!/^\d{6}$/.test(String(code || '')) || digest(me.id + ':' + code) !== c.code_hash) { q.codeMiss.run(me.id, l.id, purpose); return { code: 'bad_code', message: 'That code isn’t right. Check the email and try again.' }; }
  q.codeDone.run(me.id, l.id, purpose);
  return null;
}
const methodOf = l => l.verify_email ? 'Google sign-in + code emailed to the account address' : 'Google sign-in';
// When the last required signature lands, everyone gets the certificate by email.
function mailIfComplete(lid, eid) {
  const ent = q.entry.get(eid);
  if (!ent) return;
  const req = JSON.parse(ent.required), sigs = q.entrySigs.all(lid).filter(s => s.entry_id === eid);
  if (!req.every(u => sigs.some(s => s.user_id === u))) return;
  const l = q.ledger.get(lid), doc = JSON.parse(q.fullEntries.all(lid).find(x => x.id === eid).doc), n = entryNumber(lid, eid);
  sendMail({ to: req.map(u => (q.user.get(u) || {}).email), subject: `Signed by everyone: § ${n} · ${doc.title || 'Untitled'} (${l.name})`,
    text: `Everyone has signed § ${n} of “${l.name}”. It is now in effect.\n\n${doc.text}\n\nThe certificate is attached as the HTML version of this email, and online at ${BASE_URL}/certificate/${lid}/${eid}`,
    html: certificateHtml(lid, eid).html });
}

function ledgerState(lid, me) {
  const l = q.ledger.get(lid);
  const head = headOf(lid);
  const sigs = q.entrySigs.all(lid);
  const hashes = new Map(q.hashes.all(lid).map(h => [h.entry_id, h.hash]));
  return {
    ledger: { id: l.id, name: l.name, createdBy: l.created_by, createdAt: l.created_at, binding: !!l.binding_since, bindingSince: l.binding_since, governingLaw: l.governing_law, verifyEmail: !!l.verify_email,
      head: head.hash, headCount: head.count, statement: l.binding_since ? ledgerStatement(l, head.count, head.hash) : '' },
    me: me.id,
    myEmail: me.email,
    mail: MAIL_TRANSPORT,
    consent: { version: ESIGN_VERSION, notice: ESIGN_NOTICE, given: !!q.consent.get(me.id, ESIGN_VERSION) },
    ledgerSignatures: q.ledgerSigs.all(lid).map(s => ({ userId: s.user_id, at: s.at, typedName: s.typed_name, entryCount: s.entry_count })),
    signatures: sigs.map(s => ({ entryId: s.entry_id, userId: s.user_id, at: s.at, typedName: s.typed_name })),
    members: q.members.all(lid).map(m => ({ id: m.id, name: m.name, email: m.email, picture: m.picture, role: m.role, joinedAt: m.joined_at })),
    entries: q.entries.all(lid).map(e => Object.assign(JSON.parse(e.doc), { id: e.id, authorId: e.author_id, createdAt: e.created_at, required: JSON.parse(e.required), hash: hashes.get(e.id) || '' })),
    agreements: q.agreements.all(lid).map(a => ({ entryId: a.entry_id, userId: a.user_id, at: a.at })),
  };
}
// What a client may store in an entry. Everything that says who and when is set by the server.
function cleanDoc(doc, lid) {
  const ids = new Set(q.entryIds.all(lid).map(r => r.id));
  const own = v => Array.isArray(v) ? [...new Set(v.map(String))].filter(id => ids.has(id)) : [];
  const s = (v, n) => typeof v === 'string' ? v.slice(0, n) : '';
  return {
    kind: doc.kind === 'repeal' ? 'repeal' : 'rule',
    title: s(doc.title, 120), text: s(doc.text, 20000), draft: s(doc.draft, 20000),
    supersedes: own(doc.supersedes), relates: own(doc.relates),
    relations: (Array.isArray(doc.relations) ? doc.relations : []).filter(r => r && ids.has(String(r.ruleId))).slice(0, 50).map(r => ({
      ruleId: String(r.ruleId), kind: s(r.kind, 20), explanation: s(r.explanation, 600), quoteOld: s(r.quoteOld, 300), quoteNew: s(r.quoteNew, 300), resolution: s(r.resolution, 20) })),
    edgeCases: (Array.isArray(doc.edgeCases) ? doc.edgeCases : []).map(c => s(c, 600)).filter(Boolean).slice(0, 10),
  };
}

/* ---------- certificates ---------- */
function certificate(res, lid, eid) {
  const out = certificateHtml(lid, eid);
  if (!out) return page(res, 404, 'Certificate not found', 'No such entry in this ledger.');
  res.writeHead(200, { ...SECURITY, 'content-security-policy': csp(token(12)), 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
  res.end(out.html);
}
function certificateHtml(lid, eid) {
  const l = q.ledger.get(lid), v = verifyLedger(lid), members = q.members.all(lid);
  const who = id => members.find(m => m.id === id) || q.user.get(id) || { name: id, email: '' };
  const e = s => escHtml(s == null ? '' : s);
  const when = iso => e(new Date(iso).toUTCString());
  const audit = s => `<dl><dt>Signed as</dt><dd>${e(s.typed_name)}</dd><dt>Account</dt><dd>${e(s.name)} &lt;${e(s.email)}&gt; (Google)</dd><dt>Time</dt><dd>${when(s.at)}</dd><dt>Verified by</dt><dd>${e(s.method)}${s.auth_at ? `; signed in with Google ${when(s.auth_at)}` : ''}</dd><dt>IP address</dt><dd>${e(s.ip)}</dd><dt>Device</dt><dd>${e(s.ua)}</dd><dt>Statement</dt><dd>${e(s.statement)}</dd></dl>`;
  const consentRows = id => q.consents.all(id).map(c => `<li>Accepted the electronic-signature notice (version ${e(c.version)}) on ${when(c.at)} from ${e(c.ip)}</li>`).join('');
  let title, body;
  if (eid) {
    const ent = q.fullEntries.all(lid).find(x => x.id === eid), h = ent && q.entryHash.get(eid);
    if (!ent) return null;
    const doc = JSON.parse(ent.doc), req = JSON.parse(ent.required);
    const sigs = q.entrySigs.all(lid).filter(s => s.entry_id === eid);
    const done = req.every(u => sigs.some(s => s.user_id === u));
    title = `§ ${h.seq} · ${doc.title || 'Untitled'}`;
    body = `<p class="state ${done ? 'ok' : 'wait'}">${done ? 'Signed by every required member' : 'Not yet signed by every required member'}</p>
      <h2>Text as recorded</h2><blockquote>${e(doc.text)}</blockquote>
      <dl><dt>Ledger</dt><dd>${e(l.name)}${l.governing_law ? ` · governing law: ${e(l.governing_law)}` : ''}</dd><dt>Written by</dt><dd>${e(who(ent.author_id).name)} &lt;${e(who(ent.author_id).email)}&gt;</dd>
      <dt>Recorded</dt><dd>${when(ent.created_at)}</dd><dt>Entry fingerprint</dt><dd><code>${e(h.hash)}</code></dd><dt>Previous fingerprint</dt><dd><code>${e(h.prev_hash)}</code></dd></dl>
      <h2>Signatures</h2>${req.map(u => { const s = sigs.find(x => x.user_id === u); return s ? `<section>${audit(s)}<ul>${consentRows(u)}</ul></section>` : `<section><p><strong>${e(who(u).name)}</strong> hasn’t signed.</p></section>`; }).join('')}`;
  } else {
    const sigs = q.ledgerSigs.all(lid);
    title = l.name;
    body = `<p class="state ${l.binding_since ? 'ok' : 'wait'}">${l.binding_since ? `Legally binding since ${when(l.binding_since)}` : 'Not marked as legally binding'}</p>
      <dl><dt>Governing law</dt><dd>${e(l.governing_law || 'Not stated')}</dd><dt>Entries</dt><dd>${v.count}</dd><dt>Current fingerprint</dt><dd><code>${e(headOf(lid).hash)}</code></dd></dl>
      <h2>Ledger signatures</h2>${members.map(m => { const s = sigs.find(x => x.user_id === m.id); return s ? `<section><p>Signed covering the first ${s.entry_count} entr${s.entry_count === 1 ? 'y' : 'ies'} (fingerprint <code>${e(s.head_hash)}</code>).</p>${audit(s)}<ul>${consentRows(m.id)}</ul></section>` : `<section><p><strong>${e(m.name)}</strong> hasn’t signed the ledger.</p></section>`; }).join('')}`;
  }
  return { html: `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Certificate · ${e(title)}</title>
<style>body{margin:0;background:#f6f2ec;color:#2b2622;font:15px/1.55 Georgia,serif;padding:32px 16px}main{max-width:46rem;margin:0 auto;background:#fffdf9;border:1px solid #958879;border-radius:16px;padding:32px 36px}
h1{font-weight:500;font-size:28px;margin:0 0 4px}h2{font-size:15px;letter-spacing:.08em;text-transform:uppercase;margin:28px 0 8px;font-family:system-ui,sans-serif}.k{color:#6b625a;font:13px system-ui,sans-serif}
dl{display:grid;grid-template-columns:10rem 1fr;gap:4px 16px;margin:8px 0}dt{color:#6b625a;font:13px system-ui,sans-serif}dd{margin:0;overflow-wrap:anywhere}code{font-size:12px}blockquote{margin:0;padding:12px 16px;border-left:3px double #ddd2c3;white-space:pre-wrap}
section{border-top:1px solid #e8dfd2;padding-top:12px;margin-top:12px}ul{font:13px system-ui,sans-serif;color:#4a423b;padding-left:18px}.state{font:600 14px system-ui,sans-serif}.ok{color:#4f6f5f}.wait{color:#7a4e1d}
.integrity{font:13px system-ui,sans-serif;margin-top:28px;padding:10px 12px;border-radius:10px;background:${v.ok ? '#eef3ef' : '#fbeae4'}}@media print{body{background:#fff;padding:0}main{border:0}}</style>
<main><p class="k">Handshake · certificate · generated ${when(now())}</p><h1>${e(title)}</h1>${body}
<p class="integrity">${v.ok ? `Integrity check passed: all ${v.count} fingerprints in this ledger match their recorded content and order.` : `Integrity check FAILED at entry ${v.brokenAt}: the stored history doesn’t match its fingerprints.`}</p>
<p class="k">Print this page or save it as a PDF to keep a copy.</p></main>` };
}

/* ---------- http ---------- */
const SECURITY = {
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'no-referrer',
  'cross-origin-opener-policy': 'same-origin',
  'permissions-policy': 'camera=(), microphone=(), geolocation=()',
  ...(BASE.protocol === 'https:' ? { 'strict-transport-security': 'max-age=31536000' } : {}),
};
// The page's only scripts are its own two inline ones, allowed by a fresh nonce per response.
const csp = nonce => [
  "default-src 'self'", `script-src 'nonce-${nonce}'`, "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "font-src https://fonts.gstatic.com", "img-src 'self' data: https://*.googleusercontent.com", "connect-src 'self'",
  "base-uri 'none'", "form-action 'self'", "frame-ancestors 'none'", "object-src 'none'",
].join('; ');
function send(res, status, body) {
  res.writeHead(status, { ...SECURITY, 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
  res.end(JSON.stringify(body));
}
const escHtml = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
function page(res, status, title, text) {
  res.writeHead(status, { ...SECURITY, 'content-security-policy': csp(token(12)), 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
  res.end(`<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escHtml(title)} · Handshake</title>
<body style="margin:0;min-height:100vh;display:grid;place-items:center;background:#f6f2ec;color:#2b2622;font:16px/1.5 system-ui,sans-serif;padding:24px;box-sizing:border-box">
<main style="max-width:28rem;background:#fffdf9;border:1px solid #958879;border-radius:18px;padding:28px 32px"><h1 style="margin:0 0 8px;font:500 26px Georgia,serif">${escHtml(title)}</h1><p style="margin:0 0 16px">${escHtml(text)}</p><a href="/" style="color:#2b2622">Back to Handshake</a></main></body>`);
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', c => { size += c.length; if (size > 1 << 20) { reject(Object.assign(new Error('too large'), { status: 413 })); req.destroy(); } else chunks.push(c); });
    req.on('end', () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}')); } catch (e) { reject(Object.assign(e, { status: 400 })); } });
    req.on('error', reject);
  });
}
const isPlainObject = v => v && typeof v === 'object' && !Array.isArray(v);

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://local');
  const parts = url.pathname.split('/').filter(Boolean);
  // Only this page may use the API: refuse other host names (DNS rebinding), other sites'
  // pages (Origin), and writes not sent as JSON (which browsers can't send cross-site unasked).
  const hostName = String(req.headers.host || '').replace(/:\d+$/, '').replace(/^\[|\]$/g, '');
  if (!['localhost', '127.0.0.1', '::1', BASE.hostname].includes(hostName)) return send(res, 403, { code: 'forbidden', message: 'Unexpected host' });
  if (req.method === 'POST') {
    const origin = req.headers.origin;
    let sameSite = !origin;
    try { sameSite = sameSite || new URL(origin).host === req.headers.host; } catch { /* "null" or junk: not this page */ }
    if (!sameSite) return send(res, 403, { code: 'forbidden', message: 'Cross-site request' });
    if (!String(req.headers['content-type'] || '').startsWith('application/json')) return send(res, 415, { code: 'invalid_request', message: 'Send JSON' });
  }
  // Pages are served from BASE_URL's host only, so the sign-in cookie always lands on the host Google returns to.
  if (req.method === 'GET' && !url.pathname.startsWith('/api/') && req.headers.host !== BASE.host) {
    res.writeHead(302, { ...SECURITY, location: BASE_URL + url.pathname + url.search }); res.end(); return;
  }
  try {
    const me = currentUser(req);

    if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html')) {
      const nonce = token(16);
      res.writeHead(200, { ...SECURITY, 'content-security-policy': csp(nonce), 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
      res.end('<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
        + fs.readFileSync(path.join(ROOT, 'index.html'), 'utf8').replaceAll('<script>', `<script nonce="${nonce}">`));
      return;
    }

    /* sign-in */
    if (req.method === 'GET' && url.pathname === '/auth/google') {
      if (!GOOGLE_ID || !GOOGLE_SECRET) return page(res, 503, 'Sign-in isn’t set up yet', 'Add GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET to .env, then restart the server.');
      return startGoogle(res, safeNext(url.searchParams.get('next')));
    }
    if (req.method === 'GET' && url.pathname === '/auth/google/callback') return await finishGoogle(req, res, url);
    if (req.method === 'POST' && url.pathname === '/auth/logout') {
      const sid = cookies(req).hs_session;
      if (sid) q.dropSession.run(digest(sid));
      res.writeHead(200, { ...SECURITY, 'content-type': 'application/json', 'set-cookie': cookie('hs_session', '', 0) });
      res.end('{"ok":true}');
      return;
    }

    /* invites: /invite/<token> opens the page, which asks before joining (a visit alone never joins) */
    if (req.method === 'GET' && parts[0] === 'invite' && parts.length === 2) {
      const dest = '/?invite=' + encodeURIComponent(parts[1]);
      res.writeHead(302, { ...SECURITY, location: me ? dest : '/auth/google?next=' + encodeURIComponent(dest), 'cache-control': 'no-store' }); res.end(); return;
    }

    /* certificates: printable records of a binding ledger or one entry, for its members */
    if (req.method === 'GET' && parts[0] === 'certificate' && (parts.length === 2 || parts.length === 3)) {
      if (!me) { res.writeHead(302, { ...SECURITY, location: '/auth/google?next=' + encodeURIComponent(url.pathname) }); res.end(); return; }
      const lid = parts[1];
      if (!q.ledger.get(lid) || !q.member.get(lid, me.id)) return page(res, 404, 'Certificate not found', 'No such ledger, or you aren’t a member.');
      return certificate(res, lid, parts[2]);
    }

    /* everything below needs a signed-in user */
    if (url.pathname.startsWith('/api/') && !me) return send(res, 401, { code: 'signed_out', message: 'Sign in first.', signIn: Boolean(GOOGLE_ID && GOOGLE_SECRET) });

    if (req.method === 'GET' && url.pathname === '/api/me') return send(res, 200, { user: me, ledgers: q.myLedgers.all(me.id) });

    // Writes and checks are rate-limited per account.
    if (req.method === 'POST' && !allow('w:' + me.id, 120, 60e3)) return send(res, 429, { code: 'rate_limited', message: 'Too many changes at once. Wait a minute and try again.' });

    if (parts[0] === 'api' && parts[1] === 'invites' && parts.length >= 3) {
      if (!TOKEN_RE.test(parts[2])) return send(res, 404, { code: 'not_found', message: 'This invite link isn’t valid. Ask for a new one.' });
      const inv = q.invite.get(digest(parts[2]));
      if (!inv) return send(res, 404, { code: 'not_found', message: 'This invite link isn’t valid. Ask for a new one.' });
      const member = !!q.member.get(inv.ledger_id, me.id);
      const status = member ? 'member' : inv.used_by ? 'used' : inv.expires_at < now() ? 'expired' : 'open';
      if (req.method === 'GET' && parts.length === 3)
        return send(res, 200, { status, ledgerName: inv.ledger_name, invitedBy: inv.inviter, ledgerId: member ? inv.ledger_id : undefined });
      if (req.method === 'POST' && parts[3] === 'accept' && parts.length === 4) {
        if (status === 'member') return send(res, 200, { ledgerId: inv.ledger_id });
        if (status !== 'open') return send(res, 410, { code: status, message: status === 'used' ? 'Each invite link works once. Ask for a new one.' : `Invite links last ${INVITE_DAYS} days. Ask for a new one.` });
        const joined = tx(() => {
          if (q.useInvite.run(me.id, now(), digest(parts[2])).changes !== 1) return false; // someone else used it a moment ago
          q.addMember.run(inv.ledger_id, me.id, 'member', now());
          return true;
        });
        return joined ? send(res, 200, { ledgerId: inv.ledger_id }) : send(res, 410, { code: 'used', message: 'Each invite link works once. Ask for a new one.' });
      }
    }


    if (req.method === 'POST' && url.pathname === '/api/esign-consent') {
      const { version } = await readBody(req);
      if (version !== ESIGN_VERSION) return send(res, 409, { code: 'stale', message: 'The notice changed. Reload and read it again.' });
      q.addConsent.run(me.id, ESIGN_VERSION, ESIGN_NOTICE, now(), clientIp(req), clientUa(req));
      return send(res, 200, { ok: true });
    }

    if (req.method === 'POST' && url.pathname === '/api/ledgers') {
      const { name, binding, governingLaw } = await readBody(req);
      const n = typeof name === 'string' ? name.trim().slice(0, 80) : '';
      if (!n) return send(res, 400, { code: 'invalid_argument', message: 'Give the ledger a name.' });
      const law = typeof governingLaw === 'string' ? governingLaw.trim().slice(0, 120) : '';
      const id = token(9), at = now();
      tx(() => { q.addLedger.run(id, n, me.id, at, binding === true ? at : '', law); q.addMember.run(id, me.id, 'owner', at); });
      return send(res, 201, { id });
    }

    if (parts[0] === 'api' && parts[1] === 'ledgers' && parts[2]) {
      const lid = parts[2];
      if (!q.ledger.get(lid) || !q.member.get(lid, me.id)) return send(res, 404, { code: 'not_found', message: 'No such ledger, or you aren’t a member.' });

      if (req.method === 'GET' && parts.length === 3) return send(res, 200, ledgerState(lid, me));
      if (req.method === 'GET' && parts[3] === 'verify' && parts.length === 4) return send(res, 200, verifyLedger(lid));

      // Settings: only the author can make a ledger binding (one way) or set its governing law.
      if (req.method === 'POST' && parts[3] === 'settings' && parts.length === 4) {
        if (q.member.get(lid, me.id).role !== 'owner') return send(res, 403, { code: 'forbidden', message: 'Only the ledger’s author can change its settings.' });
        const { binding, governingLaw, verifyEmail } = await readBody(req);
        const l = q.ledger.get(lid);
        if (typeof verifyEmail === 'boolean') q.setVerify.run(verifyEmail ? 1 : 0, lid);
        const law = typeof governingLaw === 'string' ? governingLaw.trim().slice(0, 120) : l.governing_law;
        if (binding === true && !l.binding_since) q.makeBinding.run(now(), law, lid);
        else if (law !== l.governing_law) {
          if (l.binding_since && q.ledgerSigs.all(lid).length) return send(res, 409, { code: 'locked', message: 'The governing law can’t change once someone has signed the ledger.' });
          q.setLaw.run(law, lid);
        }
        if (binding === false && l.binding_since) return send(res, 409, { code: 'locked', message: 'A legally binding ledger can’t be made non-binding.' });
        return send(res, 200, { ok: true });
      }

      // Leaving: members only (the author stays). Past signatures and agreements stay on record.
      if (req.method === 'POST' && parts[3] === 'leave' && parts.length === 4) {
        if (q.member.get(lid, me.id).role === 'owner') return send(res, 409, { code: 'owner', message: 'The ledger’s author can’t leave it.' });
        q.leave.run(lid, me.id);
        return send(res, 200, { ok: true });
      }

      // A six-digit code for one signature, emailed to the signer's Google address.
      if (req.method === 'POST' && parts[3] === 'code' && parts.length === 4) {
        const l = q.ledger.get(lid);
        if (!l.binding_since || !l.verify_email) return send(res, 409, { code: 'not_needed', message: 'This ledger doesn’t ask for codes.' });
        const { purpose } = await readBody(req);
        if (!/^(ledger|entry:[A-Za-z0-9_-]{6,64})$/.test(String(purpose))) return send(res, 400, { code: 'invalid_argument', message: 'Bad purpose.' });
        if (!allow('code:' + me.id, 6, 10 * 60e3)) return send(res, 429, { code: 'rate_limited', message: 'That’s a lot of codes. Wait a few minutes.' });
        const code = String(crypto.randomInt(0, 1e6)).padStart(6, '0');
        q.setCode.run(me.id, lid, purpose, digest(me.id + ':' + code), later(CODE_MINUTES / 1440));
        const what = purpose === 'ledger' ? `sign the ledger “${l.name}”` : `sign a rule in “${l.name}”`;
        const sent = await sendMail({ to: [me.email], subject: `Your Handshake signing code: ${code}`,
          text: `Your code to ${what} is ${code}. It expires in ${CODE_MINUTES} minutes. If you didn’t ask for it, ignore this email.` });
        if (!sent) return send(res, 502, { code: 'mail_failed', message: 'The code email couldn’t be sent. Try again, or ask the ledger’s author to check the server’s email settings.' });
        return send(res, 200, { ok: true, to: me.email });
      }

      // Signing the whole ledger: the exact history the signer saw (its head fingerprint) must still be current.
      if (req.method === 'POST' && parts[3] === 'sign' && parts.length === 4) {
        const l = q.ledger.get(lid);
        if (!l.binding_since) return send(res, 409, { code: 'not_binding', message: 'This ledger isn’t legally binding.' });
        if (!q.consent.get(me.id, ESIGN_VERSION)) return send(res, 403, { code: 'needs_consent', message: 'Accept the notice about electronic signatures first.' });
        const body = await readBody(req);
        const name = signatureFrom(body);
        if (!name) return send(res, 400, { code: 'invalid_argument', message: 'Type your full name and confirm that you intend to be legally bound.' });
        const head = headOf(lid);
        if (body.headHash !== head.hash) return send(res, 409, { code: 'stale', message: 'The ledger changed while you were reading it. Review it again before signing.' });
        if (q.ledgerSig.get(lid, me.id)) return send(res, 200, { ok: true });
        const bad = checkCode(l, me, 'ledger', body.code);
        if (bad) return send(res, 403, bad);
        q.addLedgerSig.run(lid, me.id, now(), name, ledgerStatement(l, head.count, head.hash), head.hash, head.count, me.email, clientIp(req), clientUa(req), methodOf(l), me.authAt || '');
        sendMail({ to: [me.email], subject: `You signed the ledger “${l.name}”`,
          text: `You signed the ledger “${l.name}” as “${name}”. Your copy of the ledger certificate is the HTML version of this email, and online at ${BASE_URL}/certificate/${lid}`,
          html: certificateHtml(lid).html });
        return send(res, 201, { ok: true });
      }

      if (req.method === 'POST' && parts[3] === 'invites' && parts.length === 4) {
        if (!allow('i:' + me.id, 30, 3600e3)) return send(res, 429, { code: 'rate_limited', message: 'That’s a lot of invites. Try again later.' });
        const t = token(), exp = later(INVITE_DAYS);
        q.addInvite.run(digest(t), lid, me.id, now(), exp);
        return send(res, 201, { url: `${BASE_URL}/invite/${t}`, expiresAt: exp });
      }

      // A new entry: the author and time come from the session, and it needs every current member's agreement.
      if (req.method === 'POST' && parts[3] === 'entries' && parts.length === 4) {
        const body = await readBody(req);
        const { id, doc } = body;
        if (!ID_RE.test(String(id)) || !isPlainObject(doc)) return send(res, 400, { code: 'invalid_argument', message: 'Need an id and an entry.' });
        const l = q.ledger.get(lid);
        // In a binding ledger, saving an entry is signing it.
        let signer = null;
        if (l.binding_since && !q.entry.get(id)) {
          const block = bindingBlock(lid, me);
          if (block) return send(res, 403, block);
          signer = signatureFrom(body);
          if (!signer) return send(res, 400, { code: 'invalid_argument', message: 'Type your full name and confirm that you intend to be legally bound.' });
          const bad = checkCode(l, me, 'entry:' + id, body.code);
          if (bad) return send(res, 403, bad);
        }
        const existing = q.entry.get(id);
        if (existing) return existing.ledger_id === lid && existing.author_id === me.id ? send(res, 200, { ok: true })
          : send(res, 409, { code: 'invalid_argument', message: 'Entries cannot be changed once recorded.' });
        const clean = cleanDoc(doc, lid);
        if (clean.kind === 'rule' && !clean.text.trim()) return send(res, 400, { code: 'invalid_argument', message: 'The rule has no wording.' });
        if (clean.kind === 'repeal' && !clean.supersedes.length) return send(res, 400, { code: 'invalid_argument', message: 'Nothing to repeal.' });
        const at = now(), required = q.members.all(lid).map(m => m.id);
        tx(() => {
          const e = { id, ledger_id: lid, author_id: me.id, created_at: at, required: JSON.stringify(required), doc: JSON.stringify(clean) };
          q.addEntry.run(e.id, e.ledger_id, e.author_id, e.created_at, e.required, e.doc);
          const hash = chainEntry(e);
          q.agree.run(id, me.id, at);
          if (signer) q.addEntrySig.run(id, me.id, at, signer, entryStatement(l, entryNumber(lid, id), hash), hash, me.email, clientIp(req), clientUa(req), methodOf(l), me.authAt || '');
        });
        if (signer) mailIfComplete(lid, id);
        return send(res, 201, { ok: true });
      }

      if (req.method === 'POST' && parts[3] === 'entries' && parts[5] === 'agree' && parts.length === 6) {
        const e = q.entry.get(parts[4]);
        if (!e || e.ledger_id !== lid) return send(res, 404, { code: 'not_found', message: 'No such entry.' });
        if (!JSON.parse(e.required).includes(me.id)) return send(res, 403, { code: 'forbidden', message: 'You weren’t a member when this entry was written, so it doesn’t need your agreement.' });
        const l = q.ledger.get(lid);
        if (!l.binding_since) { q.agree.run(parts[4], me.id, now()); return send(res, 200, { ok: true }); }
        // Binding: a signature over the exact text the signer was shown.
        const block = bindingBlock(lid, me);
        if (block) return send(res, 403, block);
        const body = await readBody(req);
        const name = signatureFrom(body);
        if (!name) return send(res, 400, { code: 'invalid_argument', message: 'Type your full name and confirm that you intend to be legally bound.' });
        const h = q.entryHash.get(parts[4]);
        if (!h || body.entryHash !== h.hash) return send(res, 409, { code: 'stale', message: 'This isn’t the exact text that was recorded. Reload and read it again before signing.' });
        const bad = checkCode(l, me, 'entry:' + parts[4], body.code);
        if (bad) return send(res, 403, bad);
        const at = now();
        tx(() => { q.agree.run(parts[4], me.id, at); q.addEntrySig.run(parts[4], me.id, at, name, entryStatement(l, h.seq, h.hash), h.hash, me.email, clientIp(req), clientUa(req), methodOf(l), me.authAt || ''); });
        mailIfComplete(lid, parts[4]);
        return send(res, 200, { ok: true });
      }
    }

    if (req.method === 'POST' && url.pathname === '/api/check') {
      const { prompt } = await readBody(req);
      if (typeof prompt !== 'string' || !prompt.trim()) return send(res, 400, { code: 'invalid_request', message: 'Empty prompt' });
      if (prompt.length > MAX_PROMPT) return send(res, 413, { code: 'invalid_request', message: 'The rule and ledger are too long to check in one go.' });
      // Checks spend the server's API credit: only for members of a ledger, and a few per minute each.
      if (!q.myLedgers.all(me.id).length) return send(res, 403, { code: 'forbidden', message: 'Join or create a ledger first.' });
      if (!allow('c:' + me.id, 20, 10 * 60e3)) return send(res, 429, { code: 'rate_limited', message: 'That’s a lot of checks in a short time. Wait a few minutes and try again.' });
      try {
        const text = await askModel(prompt, res);
        if (!res.destroyed) send(res, 200, { text });
      } catch (e) {
        console.error('[check]', e.message);
        if (!res.destroyed) send(res, 502, { code: e.code || 'upstream_error', message: e.message });
      }
      return;
    }

    send(res, 404, { code: 'not_found' });
  } catch (e) {
    if (e && e.status) { if (!res.headersSent) send(res, e.status, { code: 'invalid_request', message: e.status === 413 ? 'Too large.' : 'Malformed request.' }); return; }
    console.error(e);
    if (!res.headersSent) send(res, 500, { code: 'unavailable', message: 'Something went wrong on the server. Try again.' });
  }
});

server.listen(PORT, HOST, () => {
  console.log(`Handshake running at ${BASE_URL}`);
  console.log(`Database: ${DB_FILE}`);
  console.log(GOOGLE_ID && GOOGLE_SECRET ? `Google sign-in on; redirect URI: ${REDIRECT_URI}` : 'Google sign-in is off until GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET are set.');
  console.log(AI_KEY || !AI_URL.includes('groq.com') ? `Rule checks: ${AI_MODEL} at ${new URL(AI_URL).host}` : 'Rule checks are off until GROQ_API_KEY is set.');
  console.log(MAIL_TRANSPORT === 'outbox' ? `Email: not configured; messages are saved to ${path.join(DATA_DIR, 'outbox')}` : `Email: ${MAIL_TRANSPORT}, from ${MAIL_FROM}`);
});
