# Handshake

Agreements between two or more people (partners, housemates, family, friends, business
partners), each a set of rules on one topic that everyone has agreed to. Every agreement is
kept as a ledger: rules are added and superseded, never edited or erased.

- Sign in with Google. Create an agreement for each topic and invite the others with a
  one-time link, or have Handshake email one to them. Only an agreement's members can see it.
- Write a rule and press **Check rule**: a fast model finds the rules in force it touches
  (the agreement narrows to them, with conflicting words marked) and suggests edge cases.
  Tick the edge cases you want in the rule, decide whether a conflicting rule is
  superseded, check again or save.
- A rule comes into effect once every member has agreed. The author agrees by saving;
  each rule lists every member with the date and time they agreed, or that they haven't
  yet. A rule that replaces another only does so once it is itself in effect.
- Entries are never edited or deleted; a new entry supersedes or repeals an older one.
  Click any rule's title to see every rule connected to it, earlier and later.
- Joining means agreeing to the whole agreement. Someone who joins after rules were agreed
  reviews them and agrees to all of them at once (recorded with the agreement's fingerprint),
  ticking off any rules still waiting for them in the same step, or first suggests a change or
  a repeal. Until then their line is dashed and everyone sees who hasn't agreed yet. Rules
  still waiting when someone joins need their agreement too.
- Anyone can **Suggest a change** to a rule that's still waiting: if everyone agrees to the new
  version, the original is closed as replaced.

## Legally binding agreements

Tick **Legally binding** when creating an agreement (it's off by default), or switch it on later
in the agreement's **Settings** (author only, and it can't be switched off again). Then:

1. Each member accepts, once per account, a notice about using electronic records and
   signatures.
2. Each member signs the agreement once: they read the rules in force, type their full legal
   name and press **Sign**, next to the statement that they intend to be legally bound (the
   press is the intent; there's no box to tick each time). The signature covers the
   agreement's history as they saw it (its current fingerprint) and every rule they sign
   afterwards. Members who join later do the same, and can sign the rules waiting for them in
   the same step: each still gets its own signature over its own fingerprint.
3. Every new rule is signed the same way, by its author on saving and by each member with
   **Agree and sign**. A signature names the fingerprint of the exact text signed; the
   server refuses it if that text isn't what was recorded.
4. A rule (or a repeal) can carry an **effective date**. It's part of the recorded text, so the
   fingerprint and every signature cover it. The rule takes effect on that day (from midnight
   UTC), or when the last member signs if that's later; until then it shows as signed but not
   yet in effect, and a rule it replaces stays in force. Past dates are allowed.

Every entry carries a SHA-256 fingerprint chained to the one before it, so changing,
removing or reordering anything breaks the chain; Settings and every certificate run the
check. Each consent and signature records the time, IP address, device and Google account.
Each rule and each agreement has a printable **certificate** (save it as a PDF from the
browser) with the text, fingerprints and the full audit trail. When everyone has signed
a rule, each of them is emailed its certificate; signing an agreement emails the signer a copy.

The agreement's author can also require that **every signature is confirmed with a six-digit
code** emailed to the signer's Google address (Settings › Confirming signatures). Codes
last ten minutes, work once, and stop working after five wrong tries. Each certificate
records how a signature was confirmed and when the signer last signed in with Google.

Members can **leave** an agreement from its Settings (the author can't). Rules then stop waiting
for them, new and pending alike; everything they signed or agreed to stays on record, and they're
still shown by name, with a grey line through the rules they agreed to.

This follows the usual requirements for electronic signatures (intent to sign, consent to
sign electronically, signatures tied to the exact record, tamper evidence, a copy for each
signer), but whether a given agreement is enforceable depends on what it says and where you
are. Have a lawyer review it before relying on it.

### Email

Set `RESEND_API_KEY` to send through [Resend](https://resend.com), or `SMTP_URL` to use any
mail server: `smtps://user:password@host:465` (TLS) or `smtp://user:password@host:587`
(upgraded with STARTTLS; a server that won't encrypt is refused, except on this machine).
`MAIL_FROM` sets the sender. With neither set, emails are written to `data/outbox/` instead,
which is fine for trying it out but means nobody receives codes or certificates. Every
email sent or failed is logged in the database. For Gmail, make an
[app password](https://myaccount.google.com/apppasswords) and use
`smtps://you%40gmail.com:apppassword@smtp.gmail.com:465` (the `@` in the address written as `%40`).

## Install it and get notifications

Handshake is an installable web app. In Chrome or Edge, use the install button in the
address bar; on Android, "Add to Home screen"; on iPhone and iPad, Share › Add to Home Screen.
Once you're signed in, each device asks whether Handshake may send notifications (Firefox
and Safari ask on your first click). Allow it to hear when a rule in one of your agreements is
added, agreed to, signed or repealed. Whoever does it isn't notified. To stop them, block
notifications for the site in the browser's settings. On iPhone and iPad this only works from
the Home Screen app (iOS 16.4 or later).

Notifications go through the browsers' own push services (Web Push), so they need no account
and cost nothing. The server makes its key pair on first run and keeps it in
`data/vapid.json`; keep that file with the database, since a new key means every device has
to turn notifications on again. Browsers only allow push on https sites and on localhost.

## Run it locally

Needs Node 22.13+ (it uses Node's built-in SQLite), a Google OAuth client for sign-in,
and a [Groq](https://console.groq.com) API key for rule checks. No `npm install`.
Put the settings in `.env`, then:

```bash
npm start
```

Open http://localhost:4317.

### Set up Google sign-in

1. In [Google Cloud Console](https://console.cloud.google.com/apis/credentials), create
   or pick a project.
2. Configure the **OAuth consent screen** (Google Auth Platform › Branding): app name
   "Handshake", your email as support and developer contact. The scopes it needs are the
   basic ones: `openid`, `email`, `profile`.
3. Under **Audience**, while the app is in *Testing*, add the Google accounts that should
   be able to sign in as test users, or publish the app so any Google account can (the
   basic scopes don't need Google's verification).
4. Under **Clients**, create an **OAuth client ID** of type *Web application* with the
   authorized redirect URI `http://localhost:4317/auth/google/callback`.
5. Put its ID and secret in `.env` as `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET`, and
   restart the server.

If you open Handshake at another address, set `BASE_URL` in `.env` to it and use
`<BASE_URL>/auth/google/callback` as the redirect URI. Google accepts plain `http` only
for `localhost`; anything else needs `https`.

### Notes

- Everything is stored in `data/handshake.db`, a SQLite file. To back it up while the
  server runs, take a consistent copy with
  `sqlite3 data/handshake.db ".backup handshake-backup.db"` (copying the file alone can miss
  the newest entries, which sit in `handshake.db-wal` until SQLite folds them in).
- Entries and agreements are append-only, and the database enforces it: SQLite itself
  refuses to change or delete them, whatever asks it to. Who wrote an entry, when, and
  whose agreement it needs are set by the server from the signed-in account.
- Entries from the single-ledger version stay in the database file, untouched, but
  aren't shown.
- Rule checks send the draft and the rules in force to Groq, which runs
  `openai/gpt-oss-20b`. A check takes a second or two and costs a fraction of a cent.
  Nothing is sent until you press Check. Any OpenAI-compatible endpoint works instead,
  including a local Ollama or LM Studio server: set `AI_URL` and `AI_MODEL`.
- The server only answers its own pages: it refuses requests from other websites,
  requests not sent as JSON, and requests addressed to other host names.

### Security

- Every query is a prepared statement; nothing a user sends is ever built into SQL.
  Everything shown on the page is escaped, and a Content Security Policy only lets the
  page's own scripts run.
- Sessions and invite tokens are stored only as SHA-256 hashes. Session cookies are
  HttpOnly and SameSite=Lax, and Secure when `BASE_URL` is https. Sessions renew whenever
  they're used, so you're only signed out after 400 days without a visit, or by Sign out.
- Push messages are encrypted for each device, so the push service can't read them, and the
  server only sends to the push services of Chrome, Firefox, Safari and Edge.
- Writes must come from the page itself as JSON; requests from other sites, or for other
  host names, are refused. The page can't be framed by another site.
- Opening an invite link only shows the invitation; joining takes a click.
- Each account is rate-limited (120 changes a minute, 20 rule checks per 10 minutes,
  30 invites an hour). Only agreement members can run checks, and prompts are capped.

### Deploying to a server

- Serve it over **https** (a reverse proxy such as Caddy or nginx in front, or Tailscale
  Serve), set `BASE_URL` to that https address, and add `<BASE_URL>/auth/google/callback`
  to the Google client's redirect URIs. With https, cookies are marked Secure and HSTS is on.
- Keep `HOST=127.0.0.1` when a proxy on the same machine forwards to it, and make the
  proxy pass the original `Host` header (Caddy and nginx's `proxy_set_header Host $host` do).
  Requests for any other host name are refused.
- Keep `.env` readable only by the user that runs the server (`chmod 600 .env`), and back
  up `data/handshake.db` with the `sqlite3 … ".backup …"` command above.
- Rate limits are kept in memory, so they reset when the server restarts.
- Behind a proxy, set `TRUST_PROXY=1` so signatures record the signer's real IP address
  (from `X-Forwarded-For`) instead of the proxy's. Only set it when a proxy is actually in
  front, since otherwise anyone could write that header.

Options (lines in `.env`, or environment variables): `GOOGLE_CLIENT_ID`,
`GOOGLE_CLIENT_SECRET`, `BASE_URL` (default `http://localhost:4317`), `GROQ_API_KEY`,
`AI_URL` (default Groq's chat endpoint), `AI_MODEL` (default `openai/gpt-oss-20b`),
`AI_API_KEY` (for a non-Groq endpoint), `PORT` (default 4317), `HOST` (default 127.0.0.1),
`DATA_DIR` (default `./data`), `TRUST_PROXY` (`1` behind a reverse proxy), `RESEND_API_KEY`,
`SMTP_URL`, `MAIL_FROM` (see Email), `VAPID_SUBJECT` (a `mailto:` or https contact for push
services; defaults to `BASE_URL` when it's https, else `MAIL_FROM`'s address).
