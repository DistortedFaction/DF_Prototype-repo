'use strict';
/*
  College Placement Tracker: backend
  ----------------------------------
  Run:   node server.js            then open http://localhost:3000
  Needs: Node.js 16 or newer. No npm install, no other dependencies.

  What it does
    - Serves new.html
    - Sign up / sign in / sign out with a secure session cookie
    - Saves every student's analysis history on the server (data/db.json)

  Environment variables (all optional)
    PORT         port to listen on (default 3000)
    HOST         address to bind to (default 127.0.0.1, only this computer).
                 Use HOST=0.0.0.0 to let other devices on your network reach it.
    DATA_DIR     folder for db.json (default ./data)
    TRUST_PROXY  set to 1 when running behind a reverse proxy that sets X-Forwarded-For / -Proto
*/

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || '127.0.0.1';
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');
const PAGE_FILE = path.join(__dirname, 'index.html');
const TRUST_PROXY = process.env.TRUST_PROXY === '1';

const SESSION_COOKIE = 'pt_session';
const SESSION_DAYS = 30;
const MAX_BODY_BYTES = 1000000;
const MAX_HISTORY_ENTRIES = 50;
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/* =====================================================================
   Tiny JSON database (one file, written atomically after every change)
   Shape: { users: {email: {...}}, sessions: {tokenHash: {...}}, history: {email: [entry]} }
   Plenty for a college-scale demo. For production, swap this for a real database.
   ===================================================================== */

let db = { users: {}, sessions: {}, history: {} };
const has = (object, key) => Object.prototype.hasOwnProperty.call(object, key);

function loadDb() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(DB_FILE)) return saveDb();
  try {
    const parsed = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    db = { users: parsed.users || {}, sessions: parsed.sessions || {}, history: parsed.history || {} };
  } catch (error) {
    // never overwrite a file we cannot read: keep a copy and stop, so no student data is lost
    const backup = DB_FILE + '.corrupt-' + Date.now();
    fs.copyFileSync(DB_FILE, backup);
    console.error('Could not read ' + DB_FILE + ' (' + error.message + '). A copy was saved to ' + backup + '.');
    console.error('Fix or delete db.json, then start the server again.');
    process.exit(1);
  }
  purgeExpiredSessions();
}

function saveDb() {
  const temporaryFile = DB_FILE + '.tmp';
  fs.writeFileSync(temporaryFile, JSON.stringify(db));
  fs.renameSync(temporaryFile, DB_FILE);
}

function purgeExpiredSessions() {
  const now = Date.now();
  let removed = false;
  for (const tokenHash of Object.keys(db.sessions)) {
    if (db.sessions[tokenHash].expires < now) { delete db.sessions[tokenHash]; removed = true; }
  }
  if (removed) saveDb();
}

/* =====================================================================
   Passwords and sessions
   ===================================================================== */

const sha256 = text => crypto.createHash('sha256').update(text).digest('hex');

const scrypt = (password, salt) => new Promise((resolve, reject) =>
  crypto.scrypt(password, salt, 64, (error, key) => (error ? reject(error) : resolve(key))));

async function makePasswordRecord(password) {
  const salt = crypto.randomBytes(16);
  const key = await scrypt(password, salt);
  return { salt: salt.toString('hex'), hash: key.toString('hex') };
}

const DUMMY_SALT = crypto.randomBytes(16);

async function passwordMatches(password, user) {
  // when the email is unknown we still do the same work, so timing does not reveal which emails exist
  const key = await scrypt(password, user ? Buffer.from(user.salt, 'hex') : DUMMY_SALT);
  if (!user) return false;
  const expected = Buffer.from(user.hash, 'hex');
  return expected.length === key.length && crypto.timingSafeEqual(expected, key);
}

function createSession(email) {
  const token = crypto.randomBytes(32).toString('hex');
  // only a hash of the token is stored, so a leaked db.json cannot be used to log in
  db.sessions[sha256(token)] = { email, expires: Date.now() + SESSION_DAYS * 86400000 };
  saveDb();
  return token;
}

function readCookie(req, name) {
  for (const part of (req.headers.cookie || '').split(';')) {
    const separator = part.indexOf('=');
    if (separator > 0 && part.slice(0, separator).trim() === name) return part.slice(separator + 1).trim();
  }
  return null;
}

function getSession(req) {
  const token = readCookie(req, SESSION_COOKIE);
  if (!token) return null;
  const tokenHash = sha256(token);
  const session = has(db.sessions, tokenHash) ? db.sessions[tokenHash] : null;
  if (!session || session.expires < Date.now() || !has(db.users, session.email)) return null;
  return { tokenHash, user: db.users[session.email] };
}

const isHttps = req => !!req.socket.encrypted || (TRUST_PROXY && req.headers['x-forwarded-proto'] === 'https');

function sessionCookie(req, token, maxAgeSeconds) {
  return SESSION_COOKIE + '=' + token + '; HttpOnly; SameSite=Lax; Path=/; Max-Age=' + maxAgeSeconds +
    (isHttps(req) ? '; Secure' : '');
}

/* =====================================================================
   Simple abuse limits (in memory)
   ===================================================================== */

const failedSignins = new Map();   // "ip|email" -> { count, resetAt }
const signupsByIp = new Map();     // ip -> { count, resetAt }

function clientIp(req) {
  if (TRUST_PROXY && req.headers['x-forwarded-for']) return String(req.headers['x-forwarded-for']).split(',')[0].trim();
  return req.socket.remoteAddress || 'unknown';
}

function isLimited(map, key, max) {
  const record = map.get(key);
  if (!record) return false;
  if (record.resetAt < Date.now()) { map.delete(key); return false; }
  return record.count >= max;
}

function addHit(map, key, windowMs) {
  const record = map.get(key);
  if (record && record.resetAt >= Date.now()) record.count++;
  else map.set(key, { count: 1, resetAt: Date.now() + windowMs });
}

/* =====================================================================
   HTTP helpers
   ===================================================================== */

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

function sendJson(res, status, body, extraHeaders) {
  const payload = JSON.stringify(body);
  res.writeHead(status, Object.assign({
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(payload),
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff'
  }, extraHeaders));
  res.end(payload);
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    if (!String(req.headers['content-type'] || '').startsWith('application/json')) {
      return reject(new HttpError(415, 'Send JSON with Content-Type: application/json.'));
    }
    const chunks = [];
    let size = 0;
    let tooLarge = false;
    req.on('data', chunk => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) tooLarge = true; else chunks.push(chunk);
    });
    req.on('end', () => {
      if (tooLarge) return reject(new HttpError(413, 'That request is too large.'));
      try {
        const parsed = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('not an object');
        resolve(parsed);
      } catch (error) {
        reject(new HttpError(400, 'The request body is not valid JSON.'));
      }
    });
    req.on('error', () => reject(new HttpError(400, 'The request could not be read.')));
  });
}

// block cross-site requests that change data (cookies are SameSite=Lax as well)
function checkOrigin(req) {
  const origin = req.headers.origin;
  if (!origin) return;
  let originHost;
  try { originHost = new URL(origin).host; } catch (error) { throw new HttpError(403, 'Request blocked.'); }
  if (originHost !== req.headers.host) throw new HttpError(403, 'Request blocked.');
}

/* =====================================================================
   Validation
   ===================================================================== */

const cleanText = (value, max) => (typeof value === 'string' ? value.trim().slice(0, max) : '');

function cleanSkillList(value) {
  if (!Array.isArray(value) || value.length > 100) throw new HttpError(400, 'Invalid skill list.');
  return value.map(skill => {
    if (typeof skill !== 'string' || skill.length > 30) throw new HttpError(400, 'Invalid skill list.');
    return skill;
  });
}

function cleanScore(value) {
  const number = Number(value);
  if (!Number.isFinite(number) || number < 0 || number > 100) throw new HttpError(400, 'Invalid score.');
  return Math.round(number);
}

function cleanNewEntry(input) {
  if (typeof input.id !== 'string' || !/^[a-z0-9]{6,32}$/.test(input.id)) throw new HttpError(400, 'Invalid entry id.');
  if (input.resumeText != null && (typeof input.resumeText !== 'string' || input.resumeText.length > 100000)) {
    throw new HttpError(400, 'The resume text is too long.');
  }
  let cgpa = null;
  if (input.cgpa != null) {
    cgpa = Number(input.cgpa);
    if (!Number.isFinite(cgpa) || cgpa < 0 || cgpa > 100) throw new HttpError(400, 'Invalid CGPA.');
  }
  return {
    id: input.id,
    createdAt: new Date().toISOString(),
    companyName: input.companyName == null ? null : cleanText(input.companyName, 80),
    roleKey: input.roleKey == null ? null : cleanText(input.roleKey, 30),
    jobDescText: cleanText(input.jobDescText, 20000),
    targetName: cleanText(input.targetName, 120) || 'Analysis',
    resumeText: input.resumeText || '',
    cgpa,
    foundSkills: cleanSkillList(input.foundSkills || []),
    learnedSkills: cleanSkillList(input.learnedSkills || []),
    missingSkills: cleanSkillList(input.missingSkills || []),
    startScore: cleanScore(input.startScore),
    score: cleanScore(input.score)
  };
}

/* =====================================================================
   API routes
   ===================================================================== */

const publicUser = user => ({ name: user.name, email: user.email });

async function handleApi(req, res, pathname) {
  const method = req.method;
  if (method !== 'GET') checkOrigin(req);

  /* ---- accounts ---- */

  if (pathname === '/api/signup' && method === 'POST') {
    const body = await readJsonBody(req);
    const name = cleanText(body.name, 80).replace(/\s+/g, ' ');
    const email = cleanText(body.email, 254).toLowerCase();
    const password = typeof body.password === 'string' ? body.password : '';
    const ip = clientIp(req);

    if (isLimited(signupsByIp, ip, 30)) throw new HttpError(429, 'Too many sign-ups from this network. Try again later.');
    if (name.length < 2) throw new HttpError(400, 'Enter your full name.');
    if (!EMAIL_PATTERN.test(email)) throw new HttpError(400, 'Enter a valid email address.');
    if (password.length < 8) throw new HttpError(400, 'Choose a password with at least 8 characters.');
    if (password.length > 200) throw new HttpError(400, 'That password is too long.');
    if (has(db.users, email)) throw new HttpError(409, 'An account with this email already exists. Sign in instead.');

    addHit(signupsByIp, ip, 3600000);
    const record = await makePasswordRecord(password);
    if (has(db.users, email)) throw new HttpError(409, 'An account with this email already exists. Sign in instead.');

    db.users[email] = { name, email, salt: record.salt, hash: record.hash, createdAt: new Date().toISOString() };
    db.history[email] = [];
    const token = createSession(email);
    return sendJson(res, 201, { user: publicUser(db.users[email]) },
      { 'Set-Cookie': sessionCookie(req, token, SESSION_DAYS * 86400) });
  }

  if (pathname === '/api/signin' && method === 'POST') {
    const body = await readJsonBody(req);
    const email = cleanText(body.email, 254).toLowerCase();
    const password = typeof body.password === 'string' ? body.password : '';
    const limitKey = clientIp(req) + '|' + email;

    if (isLimited(failedSignins, limitKey, 8)) {
      throw new HttpError(429, 'Too many failed attempts. Wait 15 minutes and try again.');
    }
    if (!email || !password || password.length > 200) throw new HttpError(400, 'Enter your email and password.');

    const user = has(db.users, email) ? db.users[email] : null;
    if (!(await passwordMatches(password, user))) {
      addHit(failedSignins, limitKey, 15 * 60000);
      throw new HttpError(401, 'Email or password is incorrect.');
    }
    failedSignins.delete(limitKey);
    purgeExpiredSessions();
    const token = createSession(email);
    return sendJson(res, 200, { user: publicUser(user) },
      { 'Set-Cookie': sessionCookie(req, token, SESSION_DAYS * 86400) });
  }

  if (pathname === '/api/signout' && method === 'POST') {
    const session = getSession(req);
    if (session) { delete db.sessions[session.tokenHash]; saveDb(); }
    return sendJson(res, 200, { ok: true }, { 'Set-Cookie': sessionCookie(req, '', 0) });
  }

  if (pathname === '/api/me' && method === 'GET') {
    const session = getSession(req);
    if (!session) throw new HttpError(401, 'Not signed in.');
    return sendJson(res, 200, { user: publicUser(session.user) });
  }

  /* ---- history (everything below needs a signed-in student) ---- */

  const historyMatch = pathname.match(/^\/api\/history(?:\/([a-z0-9]{1,32}))?$/);
  if (historyMatch) {
    const session = getSession(req);
    if (!session) throw new HttpError(401, 'Not signed in.');
    const email = session.user.email;
    if (!Array.isArray(db.history[email])) db.history[email] = [];
    const entries = db.history[email];
    const entryId = historyMatch[1];

    if (!entryId && method === 'GET') {
      return sendJson(res, 200, { entries });
    }

    if (!entryId && method === 'POST') {
      const entry = cleanNewEntry(await readJsonBody(req));
      if (entries.some(existing => existing.id === entry.id)) throw new HttpError(409, 'That entry already exists.');
      db.history[email] = [entry, ...entries].slice(0, MAX_HISTORY_ENTRIES);
      saveDb();
      return sendJson(res, 201, { entry });
    }

    if (!entryId && method === 'DELETE') {
      db.history[email] = [];
      saveDb();
      return sendJson(res, 200, { ok: true });
    }

    if (entryId && method === 'PUT') {
      const entry = entries.find(existing => existing.id === entryId);
      if (!entry) throw new HttpError(404, 'That history entry no longer exists.');
      const body = await readJsonBody(req);
      entry.learnedSkills = cleanSkillList(body.learnedSkills || []);
      entry.missingSkills = cleanSkillList(body.missingSkills || []);
      entry.score = cleanScore(body.score);
      saveDb();
      return sendJson(res, 200, { entry });
    }

    if (entryId && method === 'DELETE') {
      db.history[email] = entries.filter(existing => existing.id !== entryId);
      saveDb();
      return sendJson(res, 200, { ok: true });
    }
  }

  throw new HttpError(404, 'Not found.');
}

/* =====================================================================
   Server
   ===================================================================== */

const server = http.createServer(async (req, res) => {
  try {
    const pathname = new URL(req.url, 'http://localhost').pathname;

    if (pathname.startsWith('/api/')) return await handleApi(req, res, pathname);

    if (req.method === 'GET' && (pathname === '/' || pathname === '/new.html' || pathname === '/index.html')) {
      const page = fs.readFileSync(PAGE_FILE);
      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-cache',
        'X-Content-Type-Options': 'nosniff',
        'Referrer-Policy': 'same-origin'
      });
      return res.end(page);
    }

    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Not found');
  } catch (error) {
    if (res.headersSent) return res.end();
    if (error instanceof HttpError) {
      return sendJson(res, error.status, { error: error.message }, error.status === 413 ? { Connection: 'close' } : undefined);
    }
    console.error(error);
    sendJson(res, 500, { error: 'Something went wrong on the server.' });
  }
});

server.on('error', error => {
  if (error.code === 'EADDRINUSE') console.error('Port ' + PORT + ' is already in use. Try: PORT=3001 node server.js');
  else console.error(error);
  process.exit(1);
});

loadDb();
setInterval(purgeExpiredSessions, 3600000).unref();

server.listen(PORT, HOST, () => {
  console.log('Placement Tracker is running.');
  console.log('Open http://' + (HOST === '0.0.0.0' ? 'localhost' : HOST) + ':' + PORT + ' in your browser.');
  console.log('Student data is saved in ' + DB_FILE);
});
