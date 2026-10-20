// Handshake local server: Google sign-in, ledgers with members and one-time invites,
// rules kept append-only in SQLite (the database itself refuses updates and deletes of
// entries and agreements), and rule checks through a fast model behind an
// OpenAI-compatible API (Groq's gpt-oss-20b by default).
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import zlib from 'node:zlib';
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
// Sessions slide: using Handshake renews them, so only this long without a visit signs you out (400 days is browsers' cookie limit).
const SESSION_DAYS = 400;
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
// Push notifications go straight to the browsers' own push services (Web Push with VAPID), so they need no account.
// The server's key pair is made on first run and kept in DATA_DIR/vapid.json.
const VAPID_SUBJECT = process.env.VAPID_SUBJECT || '';
// Only the push services of the browsers people actually use; anything else would let a client make the server fetch any URL.
const PUSH_HOSTS = /(^|\.)(fcm\.googleapis\.com|push\.services\.mozilla\.com|push\.apple\.com|notify\.windows\.com)$/;
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
  -- Joining an agreement that already has rules in force: agreeing to it as a whole, once (legally binding
  -- agreements use the agreement signature for this). Append-only, with the agreement's fingerprint at the time.
  CREATE TABLE IF NOT EXISTS acceptances (ledger_id TEXT NOT NULL REFERENCES ledgers(id), user_id TEXT NOT NULL REFERENCES users(id), at TEXT NOT NULL, head_hash TEXT NOT NULL, entry_count INTEGER NOT NULL, ip TEXT NOT NULL, ua TEXT NOT NULL, PRIMARY KEY (ledger_id, user_id, at)) STRICT;
  CREATE TRIGGER IF NOT EXISTS acceptances_no_update BEFORE UPDATE ON acceptances BEGIN SELECT RAISE(ABORT, 'append-only'); END;
  CREATE TRIGGER IF NOT EXISTS acceptances_no_delete BEFORE DELETE ON acceptances BEGIN SELECT RAISE(ABORT, 'append-only'); END;
  -- Members the author removed: who, by whom and when. Append-only.
  CREATE TABLE IF NOT EXISTS removals (ledger_id TEXT NOT NULL REFERENCES ledgers(id), user_id TEXT NOT NULL REFERENCES users(id), removed_by TEXT NOT NULL REFERENCES users(id), at TEXT NOT NULL, PRIMARY KEY (ledger_id, user_id, at)) STRICT;
  CREATE TRIGGER IF NOT EXISTS removals_no_update BEFORE UPDATE ON removals BEGIN SELECT RAISE(ABORT, 'append-only'); END;
  CREATE TRIGGER IF NOT EXISTS removals_no_delete BEFORE DELETE ON removals BEGIN SELECT RAISE(ABORT, 'append-only'); END;
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
  -- One row per device that asked for notifications.
  CREATE TABLE IF NOT EXISTS push_subs (endpoint TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), p256dh TEXT NOT NULL, auth TEXT NOT NULL, created_at TEXT NOT NULL) STRICT;
`);
const q = {
  upsertUser: sql.prepare(`INSERT INTO users (id, email, name, picture, created_at) VALUES (?, ?, ?, ?, ?)
    ON CONFLICT (id) DO UPDATE SET email = excluded.email, name = excluded.name, picture = excluded.picture`),
  user: sql.prepare('SELECT id, email, name, picture FROM users WHERE id = ?'),
  addSession: sql.prepare('INSERT INTO sessions (id, user_id, expires_at, auth_at) VALUES (?, ?, ?, ?)'),
  session: sql.prepare('SELECT user_id, expires_at, auth_at FROM sessions WHERE id = ?'),
  dropSession: sql.prepare('DELETE FROM sessions WHERE id = ?'),
  dropExpired: sql.prepare('DELETE FROM sessions WHERE expires_at < ?'),
  renewSession: sql.prepare('UPDATE sessions SET expires_at = ? WHERE id = ?'),
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
  entry: sql.prepare('SELECT ledger_id, author_id, created_at, required, doc FROM entries WHERE id = ?'),
  entryAgreements: sql.prepare('SELECT user_id, at FROM entry_agreements WHERE entry_id = ?'),
  addAcceptance: sql.prepare('INSERT OR IGNORE INTO acceptances (ledger_id, user_id, at, head_hash, entry_count, ip, ua) VALUES (?, ?, ?, ?, ?, ?, ?)'),
  acceptances: sql.prepare('SELECT user_id, at FROM acceptances WHERE ledger_id = ? ORDER BY at'),
  addRemoval: sql.prepare('INSERT INTO removals (ledger_id, user_id, removed_by, at) VALUES (?, ?, ?, ?)'),
  removals: sql.prepare('SELECT user_id, removed_by, at FROM removals WHERE ledger_id = ? ORDER BY at'),
  entries: sql.prepare('SELECT id, author_id, created_at, required, doc FROM entries WHERE ledger_id = ? ORDER BY created_at, id'),
  entryIds: sql.prepare('SELECT id FROM entries WHERE ledger_id = ?'),
  agree: sql.prepare('INSERT OR IGNORE INTO entry_agreements (entry_id, user_id, at) VALUES (?, ?, ?)'),
  agreements: sql.prepare(`SELECT a.entry_id, a.user_id, a.at FROM entry_agreements a JOIN entries e ON e.id = a.entry_id
    WHERE e.ledger_id = ? ORDER BY a.at`),
  addSub: sql.prepare(`INSERT INTO push_subs (endpoint, user_id, p256dh, auth, created_at) VALUES (?, ?, ?, ?, ?)
    ON CONFLICT (endpoint) DO UPDATE SET user_id = excluded.user_id, p256dh = excluded.p256dh, auth = excluded.auth`),
  subs: sql.prepare('SELECT endpoint, p256dh, auth FROM push_subs WHERE user_id = ?'),
  dropSub: sql.prepare('DELETE FROM push_subs WHERE endpoint = ?'),
  dropMySub: sql.prepare('DELETE FROM push_subs WHERE endpoint = ? AND user_id = ?'),
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
// At most once a day per session, push its expiry (and the cookie's) back out to the full SESSION_DAYS.
function renewSession(req, res) {
  const sid = cookies(req).hs_session, s = sid && q.session.get(digest(sid));
  if (!s || s.expires_at < now() || s.expires_at > later(SESSION_DAYS - 1)) return;
  q.renewSession.run(later(SESSION_DAYS), digest(sid));
  res.setHeader('set-cookie', cookie('hs_session', sid, SESSION_DAYS * 86400));
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
function mime({ from, to, subject, text, html, attachments = [] }) {
  const alt = 'hs_' + token(12), mix = 'hs_' + token(12);
  const head = [`From: ${from}`, `To: ${to.join(', ')}`, `Subject: =?UTF-8?B?${Buffer.from(subject, 'utf8').toString('base64')}?=`,
    `Date: ${new Date().toUTCString()}`, `Message-ID: <${token(16)}@${BASE.hostname}>`, 'MIME-Version: 1.0',
    attachments.length ? `Content-Type: multipart/mixed; boundary="${mix}"` : `Content-Type: multipart/alternative; boundary="${alt}"`];
  const part = (type, body) => `--${alt}\r\nContent-Type: ${type}; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n${b64(body)}\r\n`;
  const body = part('text/plain', text) + (html ? part('text/html', html) : '') + `--${alt}--\r\n`;
  if (!attachments.length) return head.join('\r\n') + '\r\n\r\n' + body;
  const files = attachments.map(a => `--${mix}\r\nContent-Type: ${a.contentType}; name="${a.filename}"\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename="${a.filename}"\r\n\r\n${a.content.toString('base64').replace(/.{76}/g, '$&\r\n')}\r\n`).join('');
  return head.join('\r\n') + '\r\n\r\n' + `--${mix}\r\nContent-Type: multipart/alternative; boundary="${alt}"\r\n\r\n` + body + files + `--${mix}--\r\n`;
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
async function sendMail({ to, subject, text, html, attachments = [] }) {
  to = [...new Set(to.filter(Boolean))];
  if (!to.length) return false;
  const at = now();
  try {
    if (MAIL_TRANSPORT === 'resend') {
      const r = await fetch('https://api.resend.com/emails', { method: 'POST', headers: { authorization: `Bearer ${RESEND_KEY}`, 'content-type': 'application/json' },
        body: JSON.stringify({ from: MAIL_FROM, to, subject, text, html, attachments: attachments.map(a => ({ filename: a.filename, content: a.content.toString('base64') })) }) });
      if (!r.ok) throw new Error(`Resend ${r.status}: ${(await r.text()).slice(0, 200)}`);
    } else if (MAIL_TRANSPORT === 'smtp') {
      await smtpSend(SMTP_URL, MAIL_FROM, to, mime({ from: MAIL_FROM, to, subject, text, html, attachments }));
    } else {
      const dir = path.join(DATA_DIR, 'outbox');
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
      fs.writeFileSync(path.join(dir, `${at.replace(/[:.]/g, '-')}-${token(4)}.eml`), mime({ from: MAIL_FROM, to, subject, text, html, attachments }), { mode: 0o600 });
    }
    for (const t of to) q.logMail.run(at, t, subject, MAIL_TRANSPORT, 'sent', '');
    return true;
  } catch (e) {
    console.error('[mail]', e.message);
    for (const t of to) q.logMail.run(at, t, subject, MAIL_TRANSPORT, 'failed', String(e.message).slice(0, 300));
    return false;
  }
}

/* ---------- push notifications ---------- */
const VAPID = (() => {
  const file = path.join(DATA_DIR, 'vapid.json');
  let jwk;
  try { jwk = JSON.parse(fs.readFileSync(file, 'utf8')); } catch {
    jwk = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({ format: 'jwk' });
    fs.writeFileSync(file, JSON.stringify(jwk), { mode: 0o600 });
  }
  const key = crypto.createPrivateKey({ key: jwk, format: 'jwk' });
  const pub = Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url')]).toString('base64url');
  return { key, pub };
})();
const b64u = v => Buffer.from(typeof v === 'string' ? v : JSON.stringify(v)).toString('base64url');
function vapidAuth(endpoint) {
  const sub = VAPID_SUBJECT || (BASE.protocol === 'https:' ? BASE_URL : 'mailto:' + addrOf(MAIL_FROM));
  const data = b64u({ typ: 'JWT', alg: 'ES256' }) + '.' + b64u({ aud: new URL(endpoint).origin, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub });
  const sig = crypto.sign('sha256', Buffer.from(data), { key: VAPID.key, dsaEncoding: 'ieee-p1363' }).toString('base64url');
  return `vapid t=${data}.${sig}, k=${VAPID.pub}`;
}
// The message is encrypted for the one device (RFC 8291, aes128gcm), so the push service can't read it.
function encryptPush(s, payload) {
  const uaPub = Buffer.from(s.p256dh, 'base64url'), auth = Buffer.from(s.auth, 'base64url');
  const ecdh = crypto.createECDH('prime256v1'); ecdh.generateKeys();
  const asPub = ecdh.getPublicKey(), salt = crypto.randomBytes(16);
  const ikm = Buffer.from(crypto.hkdfSync('sha256', ecdh.computeSecret(uaPub), auth, Buffer.concat([Buffer.from('WebPush: info\0'), uaPub, asPub]), 32));
  const cek = Buffer.from(crypto.hkdfSync('sha256', ikm, salt, 'Content-Encoding: aes128gcm\0', 16));
  const nonce = Buffer.from(crypto.hkdfSync('sha256', ikm, salt, 'Content-Encoding: nonce\0', 12));
  const c = crypto.createCipheriv('aes-128-gcm', cek, nonce);
  const body = Buffer.concat([c.update(Buffer.concat([Buffer.from(JSON.stringify(payload)), Buffer.from([2])])), c.final(), c.getAuthTag()]);
  const head = Buffer.alloc(21); salt.copy(head); head.writeUInt32BE(4096, 16); head[20] = asPub.length;
  return Buffer.concat([head, asPub, body]);
}
// Fire-and-forget, like email: a device that's gone (404/410) is forgotten; other failures are only logged.
function notify(userIds, payload) {
  for (const uid of new Set(userIds)) for (const s of q.subs.all(uid)) {
    fetch(s.endpoint, { method: 'POST', body: encryptPush(s, payload), signal: AbortSignal.timeout(15000),
      headers: { authorization: vapidAuth(s.endpoint), 'content-encoding': 'aes128gcm', 'content-type': 'application/octet-stream', ttl: '86400', urgency: 'normal' } })
      .then(r => { if (r.status === 404 || r.status === 410) q.dropSub.run(s.endpoint); else if (!r.ok) console.error('[push]', r.status, new URL(s.endpoint).host); })
      .catch(e => console.error('[push]', e.message));
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
const ledgerStatement = (l, count, head) => `I have read the rules recorded in the agreement “${l.name}” (${count} entr${count === 1 ? 'y' : 'ies'}, fingerprint ${head}). I intend to be legally bound by every rule in it that is in force or signed to take effect later, and by each rule I sign from now on${l.governing_law ? `, under ${l.governing_law}` : ''}. I am signing electronically.`;
// A rule in a legally binding agreement can carry an effective date: a calendar day, from the start of that day UTC.
// It is part of the recorded text, so the fingerprint and every signature cover it.
const isDay = v => typeof v === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(v) && !isNaN(Date.parse(v + 'T00:00:00Z')) && new Date(v + 'T00:00:00Z').toISOString().slice(0, 10) === v;
const longDay = d => new Date(d + 'T00:00:00Z').toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric', timeZone: 'UTC' });
const entryStatement = (l, n, hash, eff) => `I intend to be legally bound by § ${n} of the agreement “${l.name}” exactly as written (fingerprint ${hash})${eff ? `, effective from ${longDay(eff)}` : ''}${l.governing_law ? `, under ${l.governing_law}` : ''}. I am signing electronically.`;
// What a signature in a binding ledger must carry from the page.
function signatureFrom(body) {
  const name = typeof body.typedName === 'string' ? body.typedName.trim().replace(/\s+/g, ' ').slice(0, 120) : '';
  if (name.length < 2 || body.intent !== true) return null;
  return name;
}
// Before signing anything in a binding agreement: consent to e-signatures, once per account. The agreement itself is
// signed with a member's first signature in it, unless it has rules they must review first (rules everyone had agreed
// to before they joined, still standing): then signing the agreement is its own, deliberate step.
function bindingBlock(lid, me) {
  if (!q.consent.get(me.id, ESIGN_VERSION)) return { code: 'needs_consent', message: 'Accept the notice about electronic signatures first.' };
  if (!q.ledgerSig.get(lid, me.id) && coveredFor(lid, me.id)) return { code: 'needs_ledger_signature', message: 'Review and sign the agreement first: it has rules that were agreed before you joined.' };
  return null;
}
function signLedgerOnce(l, me, name, req) {
  if (q.ledgerSig.get(l.id, me.id)) return false;
  const head = headOf(l.id);
  q.addLedgerSig.run(l.id, me.id, now(), name, ledgerStatement(l, head.count, head.hash), head.hash, head.count, me.email, clientIp(req), clientUa(req), methodOf(l), me.authAt || '');
  return true;
}
const entryNumber = (lid, eid) => { const h = q.entryHash.get(eid); return h ? h.seq : 0; };
// Agreements that ask for it confirm signatures with a six-digit code emailed to the signer's Google address, once per
// signing session: a code entered on a device covers everything signed in that agreement there for SIGN_WINDOW_MIN minutes.
const SIGN_WINDOW_MIN = 15, signWindows = new Map();
const windowKey = (req, lid) => digest(String(cookies(req).hs_session || '')) + ':' + lid;
const inSigningWindow = (req, lid) => (signWindows.get(windowKey(req, lid)) || 0) > Date.now();
function checkCode(l, me, req, code) {
  if (!l.verify_email || inSigningWindow(req, l.id)) return null;
  const purpose = 'signing';
  const c = q.code.get(me.id, l.id, purpose);
  if (!c || c.expires_at < now()) return { code: 'needs_code', message: 'Email yourself a code and enter it to sign.' };
  if (c.attempts >= 5) { q.codeDone.run(me.id, l.id, purpose); return { code: 'needs_code', message: 'Too many wrong codes. Email yourself a new one.' }; }
  if (!/^\d{6}$/.test(String(code || '')) || digest(me.id + ':' + code) !== c.code_hash) { q.codeMiss.run(me.id, l.id, purpose); return { code: 'bad_code', message: 'That code isn’t right. Check the email and try again.' }; }
  q.codeDone.run(me.id, l.id, purpose);
  signWindows.set(windowKey(req, l.id), Date.now() + SIGN_WINDOW_MIN * 60e3);
  if (signWindows.size > 5000) for (const [k, t] of signWindows) if (t < Date.now()) signWindows.delete(k);
  return null;
}
const methodOf = l => l.verify_email ? `Google sign-in + code emailed to the account address (one code per ${SIGN_WINDOW_MIN}-minute signing session)` : 'Google sign-in';
// Every other member's devices hear when an entry is added or someone agrees to it.
function notifyLedger(lid, me, eid, agreed) {
  const l = q.ledger.get(lid), ents = q.entries.all(lid), ent = ents.find(e => e.id === eid), doc = JSON.parse(ent.doc);
  const label = id => `§ ${entryNumber(lid, id)} · ${JSON.parse(ents.find(e => e.id === id).doc).title || 'Untitled'}`;
  const targets = (doc.supersedes || []).map(label).join(', '), repeal = doc.kind === 'repeal';
  let body;
  if (!agreed) body = doc.kind === 'withdraw' ? `${me.name} withdrew ${targets}` : repeal ? `${me.name} proposed repealing ${targets}` : `${me.name} added ${label(eid)}${targets ? `, replacing ${targets}` : ''}`;
  else {
    const has = new Set(q.agreements.all(lid).filter(a => a.entry_id === eid).map(a => a.user_id));
    const done = neededFor(lid, eid).every(u => has.has(u)), signed = !!l.binding_since;
    body = `${me.name} ${signed ? 'signed' : 'agreed to'} ${repeal ? `${signed ? 'the repeal of' : 'repeal'} ${targets}` : label(eid)}.${done ? ` Everyone has ${signed ? 'signed' : 'agreed'}.` : ''}`;
  }
  notify(q.members.all(lid).map(m => m.id).filter(id => id !== me.id), { title: l.name, body, url: `/?l=${encodeURIComponent(lid)}` });
}
// Agree to several entries this member is needed for (not legally binding: no signatures).
function agreeMany(lid, me, entries) {
  let agreed = 0;
  for (const eid of Array.isArray(entries) ? entries.slice(0, 200).map(String) : []) {
    const e = q.entry.get(eid);
    if (!e || e.ledger_id !== lid || !neededFor(lid, eid).includes(me.id)) continue;
    if (q.agree.run(eid, me.id, now()).changes) { agreed++; notifyLedger(lid, me, eid, true); announceIfComplete(lid, eid); }
  }
  return agreed;
}
/* ---------- emails: one design ----------
   The app's black station sign with its white rule and the logo, a heading, the message, a black button and a quiet
   footer. Tables and inline styles, as email clients need. heading/intro/quote/code are text; note is trusted HTML. */
function emailHtml({ heading, intro, quote, code, note, button }) {
  const e = escHtml, F = `'Helvetica Neue',Helvetica,Arial,sans-serif`;
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#e8e6e0">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#e8e6e0"><tr><td align="center" style="padding:28px 12px">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width:560px;background:#ffffff;border-radius:8px;overflow:hidden;font-family:${F};color:#000000">
<tr><td style="background:#000000;padding:12px 0 0"><div style="height:4px;line-height:4px;font-size:0;background:#ffffff">&nbsp;</div></td></tr>
<tr><td style="background:#000000;padding:18px 28px 22px"><table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>
<td style="padding-right:12px;vertical-align:middle"><img src="${e(BASE_URL)}/icon-192.png" width="40" height="40" alt="" style="display:block;border:0;border-radius:6px"></td>
<td style="vertical-align:middle;color:#ffffff;font:700 24px/1 ${F};letter-spacing:-0.5px">handshake</td></tr></table></td></tr>
<tr><td style="padding:30px 28px 8px">
<h1 style="margin:0 0 12px;font:700 24px/1.25 ${F};letter-spacing:-0.4px;color:#000000">${e(heading)}</h1>
${intro ? `<p style="margin:0 0 18px;font:16px/1.5 ${F};color:#3a3c3f">${e(intro)}</p>` : ''}
${quote ? `<p style="margin:0 0 20px;padding:12px 16px;border-left:4px solid #000000;background:#f7f6f2;font:16px/1.5 ${F};color:#000000;white-space:pre-wrap">${e(quote)}</p>` : ''}
${code ? `<p style="margin:4px 0 22px;font:700 40px/1 ${F};letter-spacing:10px;color:#000000">${e(code)}</p>` : ''}
${button ? `<p style="margin:0 0 22px"><a href="${e(button.href)}" style="display:inline-block;background:#000000;color:#ffffff;padding:12px 22px;border-radius:6px;text-decoration:none;font:700 15px ${F}">${e(button.label)}</a></p>` : ''}
${note ? `<p style="margin:0 0 22px;font:14px/1.5 ${F};color:#53565a">${note}</p>` : ''}
</td></tr>
<tr><td style="padding:16px 28px 22px;border-top:1px solid #e3e3e0;font:12px/1.5 ${F};color:#53565a">Handshake keeps agreements on record: agreed, recorded, never erased. <a href="${e(BASE_URL)}" style="color:#53565a">${e(BASE.host)}</a></td></tr>
</table></td></tr></table></body></html>`;
}
function codeEmail(me, l, code) {
  const covers = `It works for ${CODE_MINUTES} minutes, and covers everything you sign in this agreement on that device for the next ${SIGN_WINDOW_MIN} minutes.`;
  return { to: [me.email], subject: `${code} is your Handshake signing code`,
    text: `Your code to sign in “${l.name}” is ${code}. ${covers} If you didn’t ask for it, ignore this email.`,
    html: emailHtml({ heading: 'Your signing code', intro: `Enter this code to sign in “${l.name}”.`, code, note: `${covers} If you didn’t ask for it, you can ignore this email.` }) };
}
// Every member gets the whole agreement, as it now stands, as a PDF.
function mailAgreement(lid, { subject, heading, intro, quote, cert }) {
  const l = q.ledger.get(lid), link = `${BASE_URL}/?l=${encodeURIComponent(lid)}`;
  const file = `Handshake - ${l.name.replace(/[^\w\- ]+/g, '').trim() || 'agreement'}.pdf`;
  sendMail({ to: q.members.all(lid).map(m => m.email), subject,
    text: `${intro}\n\n${quote ? quote + '\n\n' : ''}The whole agreement, as it now stands, is attached as a PDF.${cert ? `\nThe certificate with the full audit trail: ${cert}` : ''}\nOpen it in Handshake: ${link}`,
    html: emailHtml({ heading, intro, quote, button: { href: link, label: `Open “${l.name}”` },
      note: `The whole agreement, as it now stands, is attached as a PDF.${cert ? ` The <a href="${escHtml(cert)}" style="color:#000000">certificate</a> has the full audit trail.` : ''}` }),
    attachments: [{ filename: file, contentType: 'application/pdf', content: agreementPdf(lid) }] });
}
// A rule agreed (or signed) by everyone: tell everyone, with the agreement attached.
function announceIfComplete(lid, eid) {
  const ent = q.entry.get(eid);
  if (!ent || JSON.parse(ent.doc).kind === 'withdraw' || !isComplete(lid, eid)) return;
  const l = q.ledger.get(lid), doc = JSON.parse(ent.doc), n = entryNumber(lid, eid), signed = !!l.binding_since;
  const later = doc.effectiveOn > now().slice(0, 10);
  mailAgreement(lid, { subject: `${l.name}: § ${n} ${signed ? 'signed' : 'agreed'} by everyone`,
    heading: `§ ${n} · ${doc.title || 'Untitled'}`,
    intro: `Everyone in “${l.name}” has ${signed ? 'signed' : 'agreed to'} § ${n}. ${later ? `It takes effect on ${longDay(doc.effectiveOn)}.` : 'It is now in effect.'}`,
    quote: doc.text, cert: signed ? `${BASE_URL}/certificate/${lid}/${eid}` : '' });
}
// Someone signed (or agreed to) the agreement as a whole.
function announceAgreement(lid, me, signed) {
  const l = q.ledger.get(lid);
  mailAgreement(lid, { subject: `${l.name}: ${me.name} ${signed ? 'signed' : 'agreed to'} the agreement`,
    heading: `${me.name} ${signed ? 'signed' : 'agreed to'} “${l.name}”`,
    intro: `${me.name} ${signed ? 'signed' : 'agreed to'} the agreement as a whole, with every rule in force.`,
    cert: signed ? `${BASE_URL}/certificate/${lid}` : '' });
}

/* ---------- the agreement as a PDF ----------
   Lean and readable, and enough to stand as a record: who the parties are and how each signed (or agreed to) the
   agreement, the rules in force with initials and dates, what's still waiting, a one-line history, and, for a legally
   binding agreement, its fingerprint and the certificate that holds the full audit trail. A small writer: A4 pages and
   the PDF's built-in Helvetica (nothing to embed), WinAnsi text wrapped by the fonts' own widths. */
const HELV = [278,278,355,556,556,889,667,191,333,333,389,584,278,333,278,278,556,556,556,556,556,556,556,556,556,556,278,278,584,584,584,556,1015,667,667,722,722,667,611,778,722,278,500,667,556,833,722,778,667,778,722,667,611,722,667,944,667,667,611,278,278,278,469,556,333,556,556,500,556,556,278,556,556,222,222,500,222,833,556,556,556,556,333,500,278,556,500,722,500,500,500,334,260,334,584];
const HELV_B = [278,333,474,556,556,889,722,238,333,333,389,584,278,333,278,278,556,556,556,556,556,556,556,556,556,556,333,333,584,584,584,611,975,722,722,722,722,667,611,778,722,278,556,722,611,833,722,778,667,778,722,667,611,722,667,944,667,667,611,333,278,333,584,556,333,556,611,556,611,556,333,611,611,278,278,556,278,889,611,611,611,611,389,556,333,611,556,778,556,556,500,389,280,389,584];
const WIN = { '€': 128, '‚': 130, '„': 132, '…': 133, '‘': 145, '’': 146, '“': 147, '”': 148, '•': 149, '–': 150, '—': 151, '™': 153 };
const winByte = ch => { const c = ch.codePointAt(0); return (c >= 32 && c <= 126) || (c >= 160 && c <= 255) ? c : WIN[ch] || 63; };
const pdfStr = s => '(' + [...String(s)].map(ch => { const b = winByte(ch); return b === 40 || b === 41 || b === 92 ? '\\' + String.fromCharCode(b) : b < 128 ? String.fromCharCode(b) : '\\' + b.toString(8).padStart(3, '0'); }).join('') + ')';
const widthOf = (s, size, bold) => [...String(s)].reduce((w, ch) => { const c = winByte(ch); return w + (c >= 32 && c <= 126 ? (bold ? HELV_B : HELV)[c - 32] : 500); }, 0) * size / 1000;
function pdfDoc() {
  const W = 595.28, H = 841.89, M = 50, pages = [];
  let ops = null, y = 0;
  const rgb = hex => { const n = parseInt(hex.slice(1), 16); return [(n >> 16) & 255, (n >> 8) & 255, n & 255].map(v => (v / 255).toFixed(3)).join(' '); };
  const f = v => v.toFixed(2);
  const d = {
    W, H, M, pages, get y() { return y; },
    newPage() { ops = []; pages.push(ops); y = H - M; },
    room(h) { if (y - h < M + 24) d.newPage(); },
    gap(h) { y -= h; },
    rect(x, top, w, h, hex) { ops.push(`${rgb(hex)} rg ${f(x)} ${f(top - h)} ${f(w)} ${f(h)} re f`); },
    pill(x, top, w, h, fill, stroke, lw) {
      const r = h / 2, k = r * 0.5523, b = top - h;
      ops.push(`${rgb(fill)} rg ${rgb(stroke)} RG ${lw} w ${f(x + r)} ${f(b)} m ${f(x + w - r)} ${f(b)} l ${f(x + w - r + k)} ${f(b)} ${f(x + w)} ${f(b + r - k)} ${f(x + w)} ${f(b + r)} c ${f(x + w)} ${f(b + r + k)} ${f(x + w - r + k)} ${f(top)} ${f(x + w - r)} ${f(top)} c ${f(x + r)} ${f(top)} l ${f(x + r - k)} ${f(top)} ${f(x)} ${f(b + r + k)} ${f(x)} ${f(b + r)} c ${f(x)} ${f(b + r - k)} ${f(x + r - k)} ${f(b)} ${f(x + r)} ${f(b)} c B`);
    },
    at(str, x, base, size, bold, hex = '#000000', page = ops) { page.push(`BT ${rgb(hex)} rg /${bold ? 'F2' : 'F1'} ${size} Tf ${f(x)} ${f(base)} Td ${pdfStr(str)} Tj ET`); },
    // Text wrapped to a width, from the cursor down.
    para(str, { x = M, width = W - 2 * M, size = 10.5, bold = false, hex = '#000000', lead = 1.45 } = {}) {
      const lh = size * lead;
      for (const raw of String(str).split('\n')) {
        const words = raw.split(/\s+/).filter(Boolean);
        if (!words.length) { y -= lh * 0.5; continue; }
        let line = '';
        const out = () => { d.room(lh); y -= lh; d.at(line, x, y + (lh - size) / 2 + size * 0.22, size, bold, hex); line = ''; };
        for (const w of words) { const t = line ? line + ' ' + w : w; if (line && widthOf(t, size, bold) > width) { out(); line = w; } else line = t; }
        if (line) out();
      }
    },
    build(title, footer) {
      pages.forEach((p, i) => d.at(footer(i + 1, pages.length), M, M - 26, 8, false, '#8d8f92', p));
      const objs = [];
      const add = o => { objs.push(o); return objs.length; };
      add('<< /Type /Catalog /Pages 2 0 R >>'); add('');
      add('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>');
      add('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>');
      const kids = pages.map(p => {
        const content = zlib.deflateSync(Buffer.from(p.join('\n'), 'latin1'));
        const c = add({ dict: `<< /Length ${content.length} /Filter /FlateDecode >>`, stream: content });
        return add(`<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${W} ${H}] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents ${c} 0 R >>`);
      });
      objs[1] = `<< /Type /Pages /Kids [${kids.map(k => k + ' 0 R').join(' ')}] /Count ${kids.length} >>`;
      const info = add(`<< /Title ${pdfStr(title)} /Producer (Handshake) /CreationDate (D:${now().replace(/[-:T]/g, '').slice(0, 14)}Z) >>`);
      const chunks = [Buffer.from('%PDF-1.4\n%\xe2\xe3\xcf\xd3\n', 'latin1')], xref = [];
      let off = chunks[0].length;
      objs.forEach((o, i) => {
        const b = typeof o === 'string' ? Buffer.from(`${i + 1} 0 obj\n${o}\nendobj\n`, 'latin1')
          : Buffer.concat([Buffer.from(`${i + 1} 0 obj\n${o.dict}\nstream\n`, 'latin1'), o.stream, Buffer.from('\nendstream\nendobj\n', 'latin1')]);
        xref.push(off); chunks.push(b); off += b.length;
      });
      chunks.push(Buffer.from(`xref\n0 ${objs.length + 1}\n0000000000 65535 f \n${xref.map(o => String(o).padStart(10, '0') + ' 00000 n \n').join('')}trailer\n<< /Size ${objs.length + 1} /Root 1 0 R /Info ${info} 0 R >>\nstartxref\n${off}\n%%EOF\n`, 'latin1'));
      return Buffer.concat(chunks);
    },
  };
  return d;
}
const LINE_COLORS = ['#0080c7', '#f38400', '#009a63', '#dc1440', '#af3788', '#fdd200', '#74b02e', '#979799', '#996633'];
function agreementPdf(lid) {
  const l = q.ledger.get(lid), binding = !!l.binding_since, members = q.members.all(lid), ents = q.fullEntries.all(lid);
  const agreements = q.agreements.all(lid), lsigs = q.ledgerSigs.all(lid), accs = q.acceptances.all(lid), rems = q.removals.all(lid);
  const today = now().slice(0, 10), user = id => q.user.get(id) || { name: 'someone', email: '' };
  const initials = id => { const w = user(id).name.split(/\s+/).filter(Boolean); return ((w[0] || '?')[0] + (w.length > 1 ? w[w.length - 1][0] : '')).toUpperCase(); };
  const day = iso => new Date(iso).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'UTC' });
  const stamp = iso => `${day(iso)}, ${new Date(iso).toISOString().slice(11, 16)} UTC`;
  // Each entry's state, as the app shows it.
  const E = ents.map((e, i) => {
    const doc = JSON.parse(e.doc), got = new Map(agreements.filter(a => a.entry_id === e.id).map(a => [a.user_id, a.at])), need = neededFor(lid, e.id);
    const all = need.length > 0 && need.every(u => got.has(u)), doneAt = all ? need.map(u => got.get(u)).sort().pop() : '', later = all && doc.effectiveOn > today;
    return { e, doc, n: i + 1, got, need, all, later, effective: all && !later, since: all ? [doneAt, doc.effectiveOn ? doc.effectiveOn + 'T00:00:00.000Z' : ''].sort().pop() : '' };
  });
  for (const x of E) x.by = E.filter(o => o.effective && (o.doc.supersedes || []).includes(x.e.id));
  const sigOf = id => lsigs.find(s => s.user_id === id), accOf = id => accs.filter(a => a.user_id === id).pop();
  const d = pdfDoc();
  d.newPage();
  // The station sign: black band, white rule, the mark and the name.
  d.rect(0, d.H, d.W, 62, '#000000'); d.rect(0, d.H - 10, d.W, 3, '#ffffff');
  const mx = d.M, mt = d.H - 24;
  d.rect(mx + 3.5, mt, 5.2, 26, '#0080c7'); d.rect(mx + 17.3, mt, 5.2, 26, '#f38400'); d.pill(mx + 1.7, mt - 9.1, 22.6, 7.8, '#ffffff', '#ffffff', 0.5);
  d.at('handshake', mx + 36, d.H - 44, 18, true, '#ffffff');
  d.gap(62);
  d.para(l.name, { size: 22, bold: true, lead: 1.25 });
  d.para(`${binding ? `Legally binding agreement${l.governing_law ? ` · governing law: ${l.governing_law}` : ''}` : 'Agreement'} · copy of ${stamp(now())}`, { size: 9.5, hex: '#53565a' });
  const section = t => { d.room(60); d.gap(16); d.para(t, { size: 12.5, bold: true, lead: 1.3 }); d.rect(d.M, d.y - 2, d.W - 2 * d.M, 0.8, '#d6d3cb'); d.gap(8); };

  section('Parties');
  members.forEach((m, i) => {
    d.room(36);
    const top = d.y;
    d.rect(d.M, top - 2, 4, 26, LINE_COLORS[i % LINE_COLORS.length]);
    d.at(m.name, d.M + 12, top - 12, 10.5, true);
    d.at(m.email, d.M + 16 + widthOf(m.name, 10.5, true), top - 12, 9, false, '#53565a');
    const s = sigOf(m.id), a = accOf(m.id);
    const how = binding ? (s ? `Signed the agreement as “${s.typed_name}”, ${stamp(s.at)}` : 'Hasn’t signed the agreement yet')
      : a ? `Agreed to the whole agreement, ${stamp(a.at)}` : m.role === 'owner' ? `Started the agreement, ${stamp(l.created_at)}`
        : coveredFor(lid, m.id) ? 'Hasn’t agreed to the whole agreement yet' : `Member since ${stamp(m.joined_at)}`;
    d.at(how, d.M + 12, top - 25, 9, false, '#3a3c3f');
    d.gap(34);
  });
  const former = [...new Set(ents.flatMap(e => [e.author_id, ...JSON.parse(e.required)]))].filter(u => !members.some(m => m.id === u));
  if (former.length) d.para('Former members: ' + former.map(u => { const r = rems.filter(x => x.user_id === u).pop(); return `${user(u).name} (${r ? `removed by ${user(r.removed_by).name}, ${day(r.at)}` : 'left'})`; }).join('; '), { size: 9, hex: '#53565a' });

  const force = E.filter(x => x.doc.kind === 'rule' && x.all && !x.by.length);
  section(`Rules in force${force.some(x => x.later) ? ' (and signed to take effect later)' : ''}`);
  if (!force.length) d.para('None yet.', { size: 10, hex: '#53565a' });
  for (const x of force) {
    d.room(70);
    d.para(`§ ${x.n}  ${x.doc.title || 'Untitled'}`, { size: 11.5, bold: true, lead: 1.35 });
    d.para(x.doc.text, { size: 10.5 });
    const covered = members.filter(m => !x.got.has(m.id) && m.joined_at > x.e.created_at && (binding ? sigOf(m.id) : accOf(m.id))).map(m => `${initials(m.id)} (with the agreement)`);
    const marks = [...x.got].map(([u, at]) => `${initials(u)} ${day(at)}`).concat(covered).join('   ');
    d.para(`${x.later ? `Takes effect ${longDay(x.doc.effectiveOn)}` : `In force since ${day(x.since)}`}   ·   ${binding ? 'Signed' : 'Agreed'}: ${marks}`, { size: 8.5, hex: '#53565a' });
    if (binding) { const h = q.entryHash.get(x.e.id); if (h) d.para(`Fingerprint ${h.hash}`, { size: 7, hex: '#8d8f92' }); }
    d.gap(8);
  }
  const waiting = E.filter(x => !x.all && !x.by.length && x.doc.kind !== 'withdraw');
  if (waiting.length) {
    section('Waiting for agreement');
    for (const x of waiting) d.para(`§ ${x.n}  ${x.doc.title || 'Untitled'}  ·  waiting for ${x.need.filter(u => !x.got.has(u)).map(u => user(u).name).join(', ')}`, { size: 9.5 });
  }
  const past = E.filter(x => x.by.length || (x.doc.kind !== 'rule' && x.all));
  if (past.length) {
    section('History');
    for (const x of past) {
      const b = x.by[0];
      const what = x.doc.kind === 'withdraw' ? `withdrew § ${(x.doc.supersedes || []).map(id => (E.find(o => o.e.id === id) || {}).n).join(', ')}`
        : x.doc.kind === 'repeal' ? `repeal, in effect since ${day(x.since)}`
        : b ? `${b.doc.kind === 'withdraw' ? 'withdrawn' : b.doc.kind === 'repeal' ? 'repealed' : 'replaced'} by § ${b.n}, ${day(b.since)}` : '';
      d.para(`§ ${x.n}  ${x.doc.title || 'Untitled'}  ·  ${what}`, { size: 9.5, hex: '#3a3c3f' });
    }
  }
  d.gap(14);
  const head = headOf(lid);
  d.para(binding
    ? `This copy shows the agreement as it stood on ${stamp(now())}. Agreement fingerprint: ${head.hash} (${head.count} entries). Each signature was made electronically after the signer accepted the notice on electronic records and signatures; the certificate at ${BASE_URL}/certificate/${lid} has the full audit trail: times, IP addresses, devices and each signature’s statement.`
    : `This copy shows the agreement as it stood on ${stamp(now())}. Open it in Handshake: ${BASE_URL}/?l=${lid}`, { size: 8, hex: '#8d8f92' });
  return d.build(`${l.name} · Handshake`, (i, n) => `${l.name}  ·  Handshake  ·  page ${i} of ${n}`);
}

// Who an entry needs: the members it required who are still members, plus anyone who agreed before leaving (leaving
// stops blocking; what someone agreed to stays on record), plus anyone who joined while it was still waiting. Joining
// means agreeing to the agreement as a whole, which covers what everyone had already agreed to, not what was pending.
function neededFor(lid, eid) {
  const ent = q.entry.get(eid);
  if (!ent) return [];
  const agreed = new Map(q.entryAgreements.all(eid).map(a => [a.user_id, a.at]));
  const base = JSON.parse(ent.required).filter(u => agreed.has(u) || q.member.get(lid, u));
  const doneAt = base.length && base.every(u => agreed.has(u)) ? base.map(u => agreed.get(u)).sort().pop() : '';
  const late = q.members.all(lid).filter(m => !base.includes(m.id) && m.joined_at > ent.created_at && !(doneAt && doneAt <= m.joined_at)).map(m => m.id);
  return base.concat(late);
}
// Everyone the entry needs has agreed (for a binding agreement, agreeing and signing are recorded together).
const isComplete = (lid, eid) => { const a = new Set(q.entryAgreements.all(eid).map(x => x.user_id)), need = neededFor(lid, eid); return need.length > 0 && need.every(u => a.has(u)); };
// An entry still standing: not replaced, repealed or withdrawn by a complete one.
const isStanding = (lid, eid, ents = q.entries.all(lid)) => !ents.some(o => o.id !== eid && (JSON.parse(o.doc).supersedes || []).includes(eid) && isComplete(lid, o.id));
// Rules everyone had agreed to before this member joined and that still stand: what they take on by signing the agreement.
function coveredFor(lid, uid) {
  const m = q.members.all(lid).find(x => x.id === uid), ents = q.entries.all(lid);
  if (!m) return 0;
  return ents.filter(e => e.created_at < m.joined_at && JSON.parse(e.doc).kind !== 'withdraw' && !neededFor(lid, e.id).includes(uid) && isComplete(lid, e.id) && isStanding(lid, e.id, ents)).length;
}
const signersOf = (lid, eid) => new Set(q.entrySigs.all(lid).filter(s => s.entry_id === eid).map(s => s.user_id));
const allSigned = (lid, eid) => { const s = signersOf(lid, eid), need = neededFor(lid, eid); return need.length > 0 && need.every(u => s.has(u)); };

function ledgerState(lid, me) {
  const l = q.ledger.get(lid);
  const head = headOf(lid);
  const sigs = q.entrySigs.all(lid);
  const hashes = new Map(q.hashes.all(lid).map(h => [h.entry_id, h.hash]));
  const members = q.members.all(lid), ents = q.entries.all(lid), removals = q.removals.all(lid);
  return {
    ledger: { id: l.id, name: l.name, createdBy: l.created_by, createdAt: l.created_at, binding: !!l.binding_since, bindingSince: l.binding_since, governingLaw: l.governing_law, verifyEmail: !!l.verify_email,
      head: head.hash, headCount: head.count, statement: l.binding_since ? ledgerStatement(l, head.count, head.hash) : '' },
    me: me.id,
    myEmail: me.email,
    mail: MAIL_TRANSPORT,
    consent: { version: ESIGN_VERSION, notice: ESIGN_NOTICE, given: !!q.consent.get(me.id, ESIGN_VERSION) },
    ledgerSignatures: q.ledgerSigs.all(lid).map(s => ({ userId: s.user_id, at: s.at, typedName: s.typed_name, entryCount: s.entry_count })),
    signatures: sigs.map(s => ({ entryId: s.entry_id, userId: s.user_id, at: s.at, typedName: s.typed_name })),
    members: members.map(m => ({ id: m.id, name: m.name, email: m.email, picture: m.picture, role: m.role, joinedAt: m.joined_at })),
    // People named in the history who have since left, so they can still be shown by name.
    formerMembers: [...new Set(ents.flatMap(e => [e.author_id, ...JSON.parse(e.required)]))].filter(u => !members.some(m => m.id === u))
      .map(u => q.user.get(u)).filter(Boolean).map(u => ({ id: u.id, name: u.name, removed: removals.some(r => r.user_id === u.id) })),
    entries: ents.map(e => Object.assign(JSON.parse(e.doc), { id: e.id, authorId: e.author_id, createdAt: e.created_at, required: JSON.parse(e.required), hash: hashes.get(e.id) || '' })),
    agreements: q.agreements.all(lid).map(a => ({ entryId: a.entry_id, userId: a.user_id, at: a.at })),
    acceptances: q.acceptances.all(lid).map(a => ({ userId: a.user_id, at: a.at })),
  };
}
// What a client may store in an entry. Everything that says who and when is set by the server.
function cleanDoc(doc, lid) {
  const ids = new Set(q.entryIds.all(lid).map(r => r.id));
  const own = v => Array.isArray(v) ? [...new Set(v.map(String))].filter(id => ids.has(id)) : [];
  const s = (v, n) => typeof v === 'string' ? v.slice(0, n) : '';
  const eff = q.ledger.get(lid).binding_since && isDay(doc.effectiveOn) ? doc.effectiveOn : '';
  return {
    kind: doc.kind === 'repeal' || doc.kind === 'withdraw' ? doc.kind : 'rule',
    title: s(doc.title, 120), text: s(doc.text, 20000), draft: s(doc.draft, 20000),
    supersedes: own(doc.supersedes), relates: own(doc.relates),
    relations: (Array.isArray(doc.relations) ? doc.relations : []).filter(r => r && ids.has(String(r.ruleId))).slice(0, 50).map(r => ({
      ruleId: String(r.ruleId), kind: s(r.kind, 20), explanation: s(r.explanation, 600), quoteOld: s(r.quoteOld, 300), quoteNew: s(r.quoteNew, 300), resolution: s(r.resolution, 20) })),
    edgeCases: (Array.isArray(doc.edgeCases) ? doc.edgeCases : []).map(c => s(c, 600)).filter(Boolean).slice(0, 10),
    ...(eff ? { effectiveOn: eff } : {}),
  };
}

/* ---------- certificates ---------- */
function certificate(res, lid, eid) {
  const out = certificateHtml(lid, eid);
  if (!out) return page(res, 404, 'Certificate not found', 'No such entry in this agreement.');
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
    const doc = JSON.parse(ent.doc), signers = signersOf(lid, eid), req = neededFor(lid, eid);
    const sigs = q.entrySigs.all(lid).filter(s => s.entry_id === eid);
    const done = req.every(u => signers.has(u));
    title = `§ ${h.seq} · ${doc.title || 'Untitled'}`;
    const later = done && doc.effectiveOn > now().slice(0, 10);
    body = `<p class="state ${done ? 'ok' : 'wait'}">${done ? `Signed by every required member${later ? `; takes effect on ${longDay(doc.effectiveOn)}` : ''}` : 'Not yet signed by every required member'}</p>
      <h2>Text as recorded</h2><blockquote>${e(doc.text)}</blockquote>
      <dl><dt>Agreement</dt><dd>${e(l.name)}${l.governing_law ? ` · governing law: ${e(l.governing_law)}` : ''}</dd><dt>Written by</dt><dd>${e(who(ent.author_id).name)} &lt;${e(who(ent.author_id).email)}&gt;</dd>
      <dt>Recorded</dt><dd>${when(ent.created_at)}</dd><dt>Effective</dt><dd>${doc.effectiveOn ? `From ${longDay(doc.effectiveOn)}, or when the last required member signs if later` : 'When every required member has signed'}</dd><dt>Entry fingerprint</dt><dd><code>${e(h.hash)}</code></dd><dt>Previous fingerprint</dt><dd><code>${e(h.prev_hash)}</code></dd></dl>
      <h2>Signatures</h2>${req.map(u => { const s = sigs.find(x => x.user_id === u); return s ? `<section>${audit(s)}<ul>${consentRows(u)}</ul></section>` : `<section><p><strong>${e(who(u).name)}</strong> hasn’t signed.</p></section>`; }).join('')}`;
  } else {
    const sigs = q.ledgerSigs.all(lid);
    title = l.name;
    body = `<p class="state ${l.binding_since ? 'ok' : 'wait'}">${l.binding_since ? `Legally binding since ${when(l.binding_since)}` : 'Not marked as legally binding'}</p>
      <dl><dt>Governing law</dt><dd>${e(l.governing_law || 'Not stated')}</dd><dt>Entries</dt><dd>${v.count}</dd><dt>Current fingerprint</dt><dd><code>${e(headOf(lid).hash)}</code></dd></dl>
      <h2>Agreement signatures</h2>${members.map(m => { const s = sigs.find(x => x.user_id === m.id); return s ? `<section><p>Signed covering the first ${s.entry_count} entr${s.entry_count === 1 ? 'y' : 'ies'} (fingerprint <code>${e(s.head_hash)}</code>).</p>${audit(s)}<ul>${consentRows(m.id)}</ul></section>` : `<section><p><strong>${e(m.name)}</strong> hasn’t signed the agreement.</p></section>`; }).join('')}`;
  }
  return { html: `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Certificate · ${e(title)}</title>
<style>body{margin:0;background:#e8e6e0;color:#000;font:15px/1.55 'Helvetica Neue',Helvetica,Arial,sans-serif;padding:32px 16px}main{max-width:46rem;margin:0 auto;background:#fff;border:1px solid #d6d3cb;border-radius:8px;padding:32px 36px}
h1{font-weight:700;font-size:28px;letter-spacing:-.02em;margin:0 0 4px}h2{font-size:17px;margin:28px 0 8px}.k{color:#53565a;font-size:13px}
dl{display:grid;grid-template-columns:10rem 1fr;gap:4px 16px;margin:8px 0}dt{color:#53565a;font-size:13px}dd{margin:0;overflow-wrap:anywhere}code{font-size:12px}blockquote{margin:0;padding:12px 16px;border-left:4px solid #000;white-space:pre-wrap}
section{border-top:1px solid #e3e3e0;padding-top:12px;margin-top:12px}ul{font-size:13px;color:#3a3c3f;padding-left:18px}.state{font-weight:700;font-size:14px}.ok{color:#007a4f}.wait{color:#9a4f00}
.integrity{font-size:13px;margin-top:28px;padding:10px 12px;border-radius:6px;background:${v.ok ? '#eaf5ef' : '#fbdde3'}}@media print{body{background:#fff;padding:0}main{border:0}}</style>
<main><p class="k">Handshake · certificate · generated ${when(now())}</p><h1>${e(title)}</h1>${body}
<p class="integrity">${v.ok ? `Integrity check passed: all ${v.count} fingerprints in this agreement match their recorded content and order.` : `Integrity check FAILED at entry ${v.brokenAt}: the stored history doesn’t match its fingerprints.`}</p>
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
  "font-src https://fonts.gstatic.com", "img-src 'self' data: https://*.googleusercontent.com", "connect-src 'self'", "worker-src 'self'",
  "base-uri 'none'", "form-action 'self'", "frame-ancestors 'none'", "object-src 'none'",
].join('; ');
// The installable app's files, served as they are from public/.
const STATIC = { '/manifest.webmanifest': 'application/manifest+json', '/sw.js': 'text/javascript; charset=utf-8',
  '/icon.svg': 'image/svg+xml', '/icon-192.png': 'image/png', '/icon-512.png': 'image/png', '/apple-touch-icon.png': 'image/png', '/og.png': 'image/png' };
function send(res, status, body) {
  res.writeHead(status, { ...SECURITY, 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
  res.end(JSON.stringify(body));
}
const escHtml = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
function page(res, status, title, text) {
  res.writeHead(status, { ...SECURITY, 'content-security-policy': csp(token(12)), 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
  res.end(`<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escHtml(title)} · Handshake</title>
<body style="margin:0;min-height:100vh;display:grid;place-items:center;background:#e8e6e0;color:#000;font:16px/1.5 'Helvetica Neue',Helvetica,Arial,sans-serif;padding:24px;box-sizing:border-box">
<main style="max-width:28rem;background:#fff;border:1px solid #d6d3cb;border-radius:8px;padding:28px 32px"><h1 style="margin:0 0 8px;font:700 26px 'Helvetica Neue',Helvetica,Arial,sans-serif;letter-spacing:-.02em">${escHtml(title)}</h1><p style="margin:0 0 16px">${escHtml(text)}</p><a href="/" style="color:#000;font-weight:700">Back to Handshake</a></main></body>`);
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
    if (me) renewSession(req, res);

    // Signed out, the bare address shows the landing page; anything with a query (?l=, ?invite=) goes to the app's own gate.
    if (req.method === 'GET' && url.pathname === '/' && !me && !url.search) {
      res.writeHead(200, { ...SECURITY, 'content-security-policy': csp(token(12)), 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
      res.end('<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
        + fs.readFileSync(path.join(ROOT, 'landing.html'), 'utf8').replaceAll('%BASE_URL%', escHtml(BASE_URL)));
      return;
    }
    if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html')) {
      const nonce = token(16);
      res.writeHead(200, { ...SECURITY, 'content-security-policy': csp(nonce), 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
      res.end('<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
        + fs.readFileSync(path.join(ROOT, 'index.html'), 'utf8').replaceAll('<script>', `<script nonce="${nonce}">`).replaceAll('%BASE_URL%', escHtml(BASE_URL)));
      return;
    }

    if (req.method === 'GET' && Object.hasOwn(STATIC, url.pathname)) {
      res.writeHead(200, { ...SECURITY, 'content-type': STATIC[url.pathname], 'cache-control': 'no-cache' });
      res.end(fs.readFileSync(path.join(ROOT, 'public', url.pathname.slice(1))));
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

    /* invites: /invite/<token> opens the page, which asks before joining (a visit alone never joins).
       Signed out (as link-preview bots always are), it answers with a page whose preview tags name the
       invitation, then moves on to sign-in. */
    if (req.method === 'GET' && parts[0] === 'invite' && parts.length === 2) {
      const dest = '/?invite=' + encodeURIComponent(parts[1]);
      if (me) { res.writeHead(302, { ...SECURITY, location: dest, 'cache-control': 'no-store' }); res.end(); return; }
      const inv = TOKEN_RE.test(parts[1]) ? q.invite.get(digest(parts[1])) : null;
      const open = inv && !inv.used_by && inv.expires_at >= now(), next = '/auth/google?next=' + encodeURIComponent(dest);
      const title = open ? `${inv.inviter} invited you to “${inv.ledger_name}”` : 'An invitation to Handshake';
      const desc = open ? 'Join this agreement on Handshake to agree on its rules together. The link works once.'
        : 'Agreements between partners, housemates, family and friends: the rules everyone has agreed to, recorded and never erased.';
      const e = escHtml;
      res.writeHead(200, { ...SECURITY, 'content-security-policy': csp(token(12)), 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'x-robots-tag': 'noindex' });
      res.end(`<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${e(title)} · Handshake</title>
<meta property="og:type" content="website"><meta property="og:site_name" content="Handshake"><meta property="og:title" content="${e(title)}">
<meta property="og:description" content="${e(desc)}"><meta property="og:url" content="${e(BASE_URL + url.pathname)}"><meta property="og:image" content="${e(BASE_URL)}/og.png">
<meta property="og:image:width" content="1200"><meta property="og:image:height" content="630"><meta name="twitter:card" content="summary_large_image">
<meta name="description" content="${e(desc)}"><meta http-equiv="refresh" content="0; url=${e(next)}">
<body style="margin:0;min-height:100vh;display:grid;place-items:center;background:#e8e6e0;color:#000;font:16px/1.5 'Helvetica Neue',Helvetica,Arial,sans-serif"><a href="${e(next)}" style="color:#000;font-weight:700">Continue to Handshake</a></body>`);
      return;
    }

    /* certificates: printable records of a binding ledger or one entry, for its members */
    if (req.method === 'GET' && parts[0] === 'certificate' && (parts.length === 2 || parts.length === 3)) {
      if (!me) { res.writeHead(302, { ...SECURITY, location: '/auth/google?next=' + encodeURIComponent(url.pathname) }); res.end(); return; }
      const lid = parts[1];
      if (!q.ledger.get(lid) || !q.member.get(lid, me.id)) return page(res, 404, 'Certificate not found', 'No such agreement, or you aren’t a member.');
      return certificate(res, lid, parts[2]);
    }

    /* everything below needs a signed-in user */
    if (url.pathname.startsWith('/api/') && !me) return send(res, 401, { code: 'signed_out', message: 'Sign in first.', signIn: Boolean(GOOGLE_ID && GOOGLE_SECRET) });

    if (req.method === 'GET' && url.pathname === '/api/me') return send(res, 200, { user: me, ledgers: q.myLedgers.all(me.id) });
    if (req.method === 'GET' && url.pathname === '/api/push') return send(res, 200, { key: VAPID.pub });

    // Writes and checks are rate-limited per account.
    if (req.method === 'POST' && !allow('w:' + me.id, 120, 60e3)) return send(res, 429, { code: 'rate_limited', message: 'Too many changes at once. Wait a minute and try again.' });

    /* notifications: each device subscribes itself, and can only remove its own subscription */
    if (req.method === 'POST' && url.pathname === '/api/push/subscribe') {
      const { endpoint, keys } = await readBody(req);
      let host = '';
      try { const u = new URL(endpoint); if (u.protocol === 'https:') host = u.hostname; } catch { /* not a URL */ }
      const key = (v, n) => typeof v === 'string' && /^[A-Za-z0-9_-]+=*$/.test(v) && Buffer.from(v, 'base64url').length === n;
      if (!PUSH_HOSTS.test(host) || endpoint.length > 1000 || !isPlainObject(keys) || !key(keys.p256dh, 65) || !key(keys.auth, 16))
        return send(res, 400, { code: 'invalid_argument', message: 'This browser’s push service isn’t supported.' });
      q.addSub.run(endpoint, me.id, keys.p256dh, keys.auth, now());
      return send(res, 200, { ok: true });
    }
    if (req.method === 'POST' && url.pathname === '/api/push/unsubscribe') {
      const { endpoint } = await readBody(req);
      q.dropMySub.run(String(endpoint), me.id);
      return send(res, 200, { ok: true });
    }

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
      if (!n) return send(res, 400, { code: 'invalid_argument', message: 'Give the agreement a name.' });
      const law = typeof governingLaw === 'string' ? governingLaw.trim().slice(0, 120) : '';
      const id = token(9), at = now();
      tx(() => { q.addLedger.run(id, n, me.id, at, binding === true ? at : '', law); q.addMember.run(id, me.id, 'owner', at); });
      return send(res, 201, { id });
    }

    if (parts[0] === 'api' && parts[1] === 'ledgers' && parts[2]) {
      const lid = parts[2];
      if (!q.ledger.get(lid) || !q.member.get(lid, me.id)) return send(res, 404, { code: 'not_found', message: 'No such agreement, or you aren’t a member.' });

      if (req.method === 'GET' && parts.length === 3) return send(res, 200, Object.assign(ledgerState(lid, me), { signingConfirmed: inSigningWindow(req, lid) }));
      if (req.method === 'GET' && parts[3] === 'verify' && parts.length === 4) return send(res, 200, verifyLedger(lid));

      // Settings: only the author can make a ledger binding (one way) or set its governing law.
      if (req.method === 'POST' && parts[3] === 'settings' && parts.length === 4) {
        if (q.member.get(lid, me.id).role !== 'owner') return send(res, 403, { code: 'forbidden', message: 'Only the agreement’s author can change its settings.' });
        const { binding, governingLaw, verifyEmail } = await readBody(req);
        const l = q.ledger.get(lid);
        if (typeof verifyEmail === 'boolean') q.setVerify.run(verifyEmail ? 1 : 0, lid);
        const law = typeof governingLaw === 'string' ? governingLaw.trim().slice(0, 120) : l.governing_law;
        if (binding === true && !l.binding_since) q.makeBinding.run(now(), law, lid);
        else if (law !== l.governing_law) {
          if (l.binding_since && q.ledgerSigs.all(lid).length) return send(res, 409, { code: 'locked', message: 'The governing law can’t change once someone has signed the agreement.' });
          q.setLaw.run(law, lid);
        }
        if (binding === false && l.binding_since) return send(res, 409, { code: 'locked', message: 'A legally binding agreement can’t be made non-binding.' });
        return send(res, 200, { ok: true });
      }

      // Leaving: members only (the author stays). Past signatures and agreements stay on record.
      // Joining an agreement that already has rules: agree to all of it, as it stands, in one go.
      if (req.method === 'POST' && parts[3] === 'accept' && parts.length === 4) {
        const l = q.ledger.get(lid);
        if (l.binding_since) return send(res, 409, { code: 'binding', message: 'This agreement is legally binding: sign it instead.' });
        const { headHash, entries } = await readBody(req);
        const head = headOf(lid);
        if (headHash !== head.hash) return send(res, 409, { code: 'stale', message: 'The agreement changed while you were reading it. Review it again.' });
        q.addAcceptance.run(lid, me.id, now(), head.hash, head.count, clientIp(req), clientUa(req));
        notify(q.members.all(lid).map(m => m.id).filter(id => id !== me.id), { title: l.name, body: `${me.name} agreed to the whole agreement.`, url: `/?l=${encodeURIComponent(lid)}` });
        // The rules still waiting for this member can be agreed in the same step.
        const agreed = agreeMany(lid, me, entries);
        announceAgreement(lid, me, false);
        return send(res, 200, { ok: true, agreed });
      }

      // Agreeing to several waiting rules at once (signing does this in a binding agreement).
      if (req.method === 'POST' && parts[3] === 'agree' && parts.length === 4) {
        if (q.ledger.get(lid).binding_since) return send(res, 409, { code: 'binding', message: 'This agreement is legally binding: sign the rules instead.' });
        const { entries } = await readBody(req);
        return send(res, 200, { ok: true, agreed: agreeMany(lid, me, entries) });
      }

      // The author can remove a member (someone who no longer takes part). Recorded, and everyone is told; rules stop
      // waiting for them, and what they agreed to or signed stays on record.
      if (req.method === 'POST' && parts[3] === 'members' && parts[5] === 'remove' && parts.length === 6) {
        if (q.member.get(lid, me.id).role !== 'owner') return send(res, 403, { code: 'forbidden', message: 'Only the agreement’s author can remove members.' });
        const uid = parts[4], m = q.member.get(lid, uid), who = q.user.get(uid);
        if (!m || !who) return send(res, 404, { code: 'not_found', message: 'They aren’t a member.' });
        if (m.role === 'owner') return send(res, 409, { code: 'owner', message: 'The author can’t be removed.' });
        const l = q.ledger.get(lid), waiting = q.entries.all(lid).filter(e => !isComplete(lid, e.id));
        tx(() => { q.leave.run(lid, uid); q.addRemoval.run(lid, uid, me.id, now()); });
        notify(q.members.all(lid).map(x => x.id).concat(uid).filter(id => id !== me.id), { title: l.name, body: `${me.name} removed ${who.name} from the agreement.`, url: `/?l=${encodeURIComponent(lid)}` });
        for (const e of waiting) announceIfComplete(lid, e.id);
        return send(res, 200, { ok: true });
      }

      if (req.method === 'POST' && parts[3] === 'leave' && parts.length === 4) {
        if (q.member.get(lid, me.id).role === 'owner') return send(res, 409, { code: 'owner', message: 'The agreement’s author can’t leave it.' });
        // Rules that were only waiting on this member come into effect, and everyone gets the agreement as it now stands.
        const waiting = q.entries.all(lid).filter(e => !isComplete(lid, e.id));
        q.leave.run(lid, me.id);
        for (const e of waiting) announceIfComplete(lid, e.id);
        return send(res, 200, { ok: true });
      }

      // A six-digit code for one signature, emailed to the signer's Google address.
      if (req.method === 'POST' && parts[3] === 'code' && parts.length === 4) {
        const l = q.ledger.get(lid);
        if (!l.binding_since || !l.verify_email) return send(res, 409, { code: 'not_needed', message: 'This agreement doesn’t ask for codes.' });
        if (!allow('code:' + me.id, 6, 10 * 60e3)) return send(res, 429, { code: 'rate_limited', message: 'That’s a lot of codes. Wait a few minutes.' });
        const code = String(crypto.randomInt(0, 1e6)).padStart(6, '0');
        q.setCode.run(me.id, lid, 'signing', digest(me.id + ':' + code), later(CODE_MINUTES / 1440));
        const sent = await sendMail(codeEmail(me, l, code));
        if (!sent) return send(res, 502, { code: 'mail_failed', message: 'The code email couldn’t be sent. Try again, or ask the agreement’s author to check the server’s email settings.' });
        return send(res, 200, { ok: true, to: me.email });
      }

      // Signing the whole ledger: the exact history the signer saw (its head fingerprint) must still be current.
      if (req.method === 'POST' && parts[3] === 'sign' && parts.length === 4) {
        const l = q.ledger.get(lid);
        if (!l.binding_since) return send(res, 409, { code: 'not_binding', message: 'This agreement isn’t legally binding.' });
        if (!q.consent.get(me.id, ESIGN_VERSION)) return send(res, 403, { code: 'needs_consent', message: 'Accept the notice about electronic signatures first.' });
        const body = await readBody(req);
        const name = signatureFrom(body);
        if (!name) return send(res, 400, { code: 'invalid_argument', message: 'Type your full name and confirm that you intend to be legally bound.' });
        // Someone who already signed the agreement uses this to sign the rules waiting for them, all at once.
        const already = !!q.ledgerSig.get(lid, me.id);
        if (!already && body.headHash !== headOf(lid).hash) return send(res, 409, { code: 'stale', message: 'The agreement changed while you were reading it. Review it again before signing.' });
        const bad = checkCode(l, me, req, body.code);
        if (bad) return send(res, 403, bad);
        if (!already) signLedgerOnce(l, me, name, req);
        // The rules waiting for this signer can be signed in the same step (one code covers it); each still gets
        // its own signature, over its own fingerprint and statement.
        const signed = [];
        for (const it of Array.isArray(body.entries) ? body.entries.slice(0, 200) : []) {
          const eid = String(it && it.id), e = q.entry.get(eid), h = q.entryHash.get(eid);
          if (!e || e.ledger_id !== lid || !h || it.entryHash !== h.hash || !neededFor(lid, eid).includes(me.id)) continue;
          const at = now();
          const added = tx(() => { const c = q.agree.run(eid, me.id, at).changes; if (c) q.addEntrySig.run(eid, me.id, at, name, entryStatement(l, h.seq, h.hash, JSON.parse(e.doc).effectiveOn), h.hash, me.email, clientIp(req), clientUa(req), methodOf(l), me.authAt || ''); return c; });
          if (added) { signed.push(eid); notifyLedger(lid, me, eid, true); announceIfComplete(lid, eid); }
        }
        if (!already) announceAgreement(lid, me, true);
        return send(res, 201, { ok: true, signed: signed.length });
      }

      if (req.method === 'POST' && parts[3] === 'invites' && parts.length === 4) {
        if (!allow('i:' + me.id, 30, 3600e3)) return send(res, 429, { code: 'rate_limited', message: 'That’s a lot of invites. Try again later.' });
        const t = token(), exp = later(INVITE_DAYS);
        q.addInvite.run(digest(t), lid, me.id, now(), exp);
        return send(res, 201, { url: `${BASE_URL}/invite/${t}`, expiresAt: exp });
      }
      // The same one-time link, made fresh and emailed to one address.
      if (req.method === 'POST' && parts[3] === 'invites' && parts[4] === 'email' && parts.length === 5) {
        const email = String((await readBody(req)).email || '').trim();
        if (email.length > 254 || !/^[^\s@<>,;:"()\[\]\\]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$/.test(email))
          return send(res, 400, { code: 'invalid_argument', message: 'That doesn’t look like an email address.' });
        if (!allow('i:' + me.id, 30, 3600e3)) return send(res, 429, { code: 'rate_limited', message: 'That’s a lot of invites. Try again later.' });
        const l = q.ledger.get(lid), t = token(), exp = later(INVITE_DAYS), url = `${BASE_URL}/invite/${t}`;
        q.addInvite.run(digest(t), lid, me.id, now(), exp);
        const sent = await sendMail({ to: [email], subject: `${me.name} invited you to “${l.name}” on Handshake`,
          text: `${me.name} (${me.email}) invited you to join the agreement “${l.name}” on Handshake, where you agree on rules together.\n\nJoin here: ${url}\n\nThe link works once, for ${INVITE_DAYS} days. You’ll sign in with Google. If you weren’t expecting this, ignore this email.`,
          html: emailHtml({ heading: `${me.name} invited you to “${l.name}”`, intro: `${me.name} (${me.email}) invited you to join the agreement “${l.name}” on Handshake, where you agree on rules together.`,
            button: { href: url, label: `Join “${l.name}”` }, note: `The link works once, for ${INVITE_DAYS} days. You’ll sign in with Google. If you weren’t expecting this, you can ignore this email.` }) });
        if (!sent) return send(res, 502, { code: 'mail_failed', message: 'The invite email couldn’t be sent. Copy the link instead.' });
        return send(res, 201, { ok: true, to: email });
      }

      // A new entry: the author and time come from the session, and it needs every current member's agreement.
      if (req.method === 'POST' && parts[3] === 'entries' && parts.length === 4) {
        const body = await readBody(req);
        const { id, doc } = body;
        if (!ID_RE.test(String(id)) || !isPlainObject(doc)) return send(res, 400, { code: 'invalid_argument', message: 'Need an id and an entry.' });
        const l = q.ledger.get(lid);
        const existing = q.entry.get(id);
        if (existing) return existing.ledger_id === lid && existing.author_id === me.id ? send(res, 200, { ok: true })
          : send(res, 409, { code: 'invalid_argument', message: 'Entries cannot be changed once recorded.' });
        const clean = cleanDoc(doc, lid);
        if (clean.kind === 'rule' && !clean.text.trim()) return send(res, 400, { code: 'invalid_argument', message: 'The rule has no wording.' });
        if (clean.kind === 'repeal' && !clean.supersedes.length) return send(res, 400, { code: 'invalid_argument', message: 'Nothing to repeal.' });
        // Withdrawing: only the author of a rule not everyone has agreed to yet. It needs no one else, and no signature.
        if (clean.kind === 'withdraw') {
          const t = clean.supersedes.length === 1 && q.entry.get(clean.supersedes[0]);
          if (!t || t.author_id !== me.id || JSON.parse(t.doc).kind === 'withdraw') return send(res, 400, { code: 'invalid_argument', message: 'You can only withdraw a rule you wrote.' });
          if (isComplete(lid, clean.supersedes[0])) return send(res, 409, { code: 'complete', message: 'Everyone has already agreed to it. Repeal it instead.' });
        }
        // In a binding agreement, saving an entry is signing it (and, the first time, signing the agreement too).
        let signer = null;
        if (l.binding_since && clean.kind !== 'withdraw') {
          const block = bindingBlock(lid, me);
          if (block) return send(res, 403, block);
          signer = signatureFrom(body);
          if (!signer) return send(res, 400, { code: 'invalid_argument', message: 'Type your full name and confirm that you intend to be legally bound.' });
          const bad = checkCode(l, me, req, body.code);
          if (bad) return send(res, 403, bad);
        }
        const at = now(), required = clean.kind === 'withdraw' ? [me.id] : q.members.all(lid).map(m => m.id);
        tx(() => {
          if (signer) signLedgerOnce(l, me, signer, req);
          const e = { id, ledger_id: lid, author_id: me.id, created_at: at, required: JSON.stringify(required), doc: JSON.stringify(clean) };
          q.addEntry.run(e.id, e.ledger_id, e.author_id, e.created_at, e.required, e.doc);
          const hash = chainEntry(e);
          q.agree.run(id, me.id, at);
          if (signer) q.addEntrySig.run(id, me.id, at, signer, entryStatement(l, entryNumber(lid, id), hash, clean.effectiveOn), hash, me.email, clientIp(req), clientUa(req), methodOf(l), me.authAt || '');
        });
        notifyLedger(lid, me, id, false);
        announceIfComplete(lid, id);
        return send(res, 201, { ok: true });
      }

      if (req.method === 'POST' && parts[3] === 'entries' && parts[5] === 'agree' && parts.length === 6) {
        const e = q.entry.get(parts[4]);
        if (!e || e.ledger_id !== lid) return send(res, 404, { code: 'not_found', message: 'No such entry.' });
        if (!neededFor(lid, parts[4]).includes(me.id)) return send(res, 403, { code: 'forbidden', message: 'This entry doesn’t need your agreement on its own: it was already agreed when you joined, and agreeing to the whole agreement covers it.' });
        const l = q.ledger.get(lid);
        if (!l.binding_since) {
          if (q.agree.run(parts[4], me.id, now()).changes) { notifyLedger(lid, me, parts[4], true); announceIfComplete(lid, parts[4]); }
          return send(res, 200, { ok: true });
        }
        // Binding: a signature over the exact text the signer was shown.
        const block = bindingBlock(lid, me);
        if (block) return send(res, 403, block);
        const body = await readBody(req);
        const name = signatureFrom(body);
        if (!name) return send(res, 400, { code: 'invalid_argument', message: 'Type your full name and confirm that you intend to be legally bound.' });
        const h = q.entryHash.get(parts[4]);
        if (!h || body.entryHash !== h.hash) return send(res, 409, { code: 'stale', message: 'This isn’t the exact text that was recorded. Reload and read it again before signing.' });
        const bad = checkCode(l, me, req, body.code);
        if (bad) return send(res, 403, bad);
        const at = now();
        const added = tx(() => { signLedgerOnce(l, me, name, req); const c = q.agree.run(parts[4], me.id, at).changes; q.addEntrySig.run(parts[4], me.id, at, name, entryStatement(l, h.seq, h.hash, JSON.parse(e.doc).effectiveOn), h.hash, me.email, clientIp(req), clientUa(req), methodOf(l), me.authAt || ''); return c; });
        if (added) { notifyLedger(lid, me, parts[4], true); announceIfComplete(lid, parts[4]); }
        return send(res, 200, { ok: true });
      }
    }

    if (req.method === 'POST' && url.pathname === '/api/check') {
      const { prompt } = await readBody(req);
      if (typeof prompt !== 'string' || !prompt.trim()) return send(res, 400, { code: 'invalid_request', message: 'Empty prompt' });
      if (prompt.length > MAX_PROMPT) return send(res, 413, { code: 'invalid_request', message: 'The rule and agreement are too long to check in one go.' });
      // Checks spend the server's API credit: only for members of a ledger, and a few per minute each.
      if (!q.myLedgers.all(me.id).length) return send(res, 403, { code: 'forbidden', message: 'Join or create an agreement first.' });
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
  console.log(BASE.protocol === 'https:' || ['localhost', '127.0.0.1'].includes(BASE.hostname) ? 'Notifications: on (Web Push)' : 'Notifications: off until BASE_URL is https:// (browsers only allow push on secure sites).');
  console.log(MAIL_TRANSPORT === 'outbox' ? `Email: not configured; messages are saved to ${path.join(DATA_DIR, 'outbox')}` : `Email: ${MAIL_TRANSPORT}, from ${MAIL_FROM}`);
});
