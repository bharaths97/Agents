# Secure Coding Guide: JavaScript / Node.js

Language-specific security patterns for JavaScript and TypeScript applications, covering both browser-side and Node.js server-side contexts. Used by agents to assess JS/TS-specific security practices and generate remediation guidance.

---

## Input Validation

### Server-Side Validation (Node.js / Express)

**Unsafe:**
```javascript
app.post('/user', (req, res) => {
    const { username, age } = req.body;  // No validation; any value accepted
    db.createUser(username, age);
});
```

**Safe — using express-validator:**
```javascript
const { body, validationResult } = require('express-validator');

app.post('/user', [
    body('username')
        .isString()
        .trim()
        .isLength({ min: 3, max: 32 })
        .matches(/^[a-zA-Z0-9_]+$/),
    body('age')
        .isInt({ min: 0, max: 150 }),
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const { username, age } = req.body;
    db.createUser(username, parseInt(age, 10));
});
```

**Safe — using zod (TypeScript-first):**
```typescript
import { z } from 'zod';

const CreateUserSchema = z.object({
    username: z.string().min(3).max(32).regex(/^[a-zA-Z0-9_]+$/),
    age: z.number().int().min(0).max(150),
});

app.post('/user', (req, res) => {
    const result = CreateUserSchema.safeParse(req.body);
    if (!result.success) {
        return res.status(400).json({ errors: result.error.flatten() });
    }
    const { username, age } = result.data;
    db.createUser(username, age);
});
```

---

## SQL Injection

**Unsafe:**
```javascript
// String concatenation — SQL injection
const query = `SELECT * FROM users WHERE id = ${req.params.id}`;
db.query(query);

// Template literals with user data
const name = req.body.name;
connection.query(`SELECT * FROM users WHERE name = '${name}'`);
```

**Safe — node-postgres (pg):**
```javascript
// Parameterized queries with $1, $2, ... placeholders
const result = await client.query(
    'SELECT * FROM users WHERE id = $1',
    [req.params.id]
);

const result = await client.query(
    'SELECT * FROM users WHERE name = $1 AND active = $2',
    [name, true]
);
```

**Safe — MySQL2:**
```javascript
const [rows] = await connection.execute(
    'SELECT * FROM users WHERE id = ? AND active = ?',
    [userId, true]
);
```

**Safe — Sequelize ORM:**
```javascript
const user = await User.findOne({ where: { id: userId } });

// Safe raw query with replacements
const users = await sequelize.query(
    'SELECT * FROM users WHERE name = :name',
    { replacements: { name: req.body.name }, type: QueryTypes.SELECT }
);
```

**Safe — Knex query builder:**
```javascript
const users = await knex('users').where('id', userId).select('*');
```

---

## OS Command Injection

**Unsafe:**
```javascript
const { exec } = require('child_process');

// exec with string concatenation — shell injection
exec(`ls ${req.query.dir}`, (err, stdout) => res.send(stdout));
exec('convert ' + filename + ' output.jpg');

// Interpolation into shell string
exec(`git clone ${repoUrl}`);
```

**Safe — execFile (arguments separate from command):**
```javascript
const { execFile } = require('child_process');
const { promisify } = require('util');
const execFileAsync = promisify(execFile);

// execFile: command and args are always separate — no shell interpretation
const { stdout } = await execFileAsync('ls', ['-la', req.query.dir]);
const { stdout } = await execFileAsync('git', ['clone', repoUrl]);
```

**Safe — spawn for streaming output:**
```javascript
const { spawn } = require('child_process');
const child = spawn('ls', ['-la', directory]);
child.stdout.on('data', (data) => res.write(data));
child.on('close', () => res.end());
```

### Never use:
```javascript
exec(userInput);                          // Arbitrary command execution
eval(userInput);                          // JavaScript code execution
new Function(userInput)();                // Code execution
require(userInput);                       // Module loading from user path
```

---

## Path Traversal

**Unsafe:**
```javascript
const fs = require('fs');
const filename = req.query.file;
fs.readFile(`/uploads/${filename}`, 'utf8', (err, data) => res.send(data));
// Attack: file=../../etc/passwd
```

**Safe:**
```javascript
const path = require('path');
const fs = require('fs');

const BASE_DIR = path.resolve('/var/www/uploads');

function safePath(filename) {
    const resolved = path.resolve(BASE_DIR, filename);
    // Ensure resolved path stays within BASE_DIR
    if (!resolved.startsWith(BASE_DIR + path.sep)) {
        throw new Error('Path traversal detected');
    }
    return resolved;
}

app.get('/file', (req, res) => {
    try {
        const filePath = safePath(req.query.file);
        res.sendFile(filePath);
    } catch (e) {
        res.status(400).json({ error: 'Invalid file path' });
    }
});
```

---

## XSS Prevention

### Server-Side (Reflected / Stored XSS)

**Unsafe:**
```javascript
// Express: raw user input in response
app.get('/search', (req, res) => {
    res.send(`<h1>Results for ${req.query.q}</h1>`);  // XSS
});

// Template: unescaped variable (EJS)
// <h1>Hello <%= name %></h1>   ← escaped (safe)
// <h1>Hello <%- name %></h1>   ← unescaped (UNSAFE)
```

**Safe — HTML escaping:**
```javascript
const he = require('he');

app.get('/search', (req, res) => {
    const safeQuery = he.encode(req.query.q || '');
    res.send(`<h1>Results for ${safeQuery}</h1>`);
});
```

**Safe — use Content-Security-Policy header:**
```javascript
const helmet = require('helmet');
app.use(helmet.contentSecurityPolicy({
    directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        objectSrc: ["'none'"],
        upgradeInsecureRequests: [],
    },
}));
```

### Client-Side DOM XSS

**Unsafe:**
```javascript
// innerHTML with user-controlled data
document.getElementById('output').innerHTML = userInput;

// jQuery .html() with user data
$('#output').html(userInput);

// document.write
document.write(userInput);

// eval on URL fragment or query param
eval(location.hash.slice(1));
```

**Safe:**
```javascript
// textContent — no HTML parsing
document.getElementById('output').textContent = userInput;

// jQuery .text() — escapes HTML
$('#output').text(userInput);

// createElement for structured output
const div = document.createElement('div');
div.textContent = userInput;
container.appendChild(div);
```

**React (safe by default):**
```jsx
// Safe: React escapes JSX expressions
<div>{userInput}</div>

// UNSAFE: dangerouslySetInnerHTML bypasses escaping
<div dangerouslySetInnerHTML={{ __html: userInput }} />

// If HTML rendering is required, sanitize first:
import DOMPurify from 'dompurify';
<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userInput) }} />
```

---

## Authentication and JWT

**Unsafe:**
```javascript
const jwt = require('jsonwebtoken');

// No signature verification
const payload = jwt.decode(token);  // jwt.decode NEVER verifies signature

// Accepting algorithm from token header (alg confusion)
const header = JSON.parse(Buffer.from(token.split('.')[0], 'base64').toString());
const payload = jwt.verify(token, secret, { algorithms: [header.alg] });

// Accepting 'none' algorithm
const payload = jwt.verify(token, secret, { algorithms: ['HS256', 'none'] });
```

**Safe:**
```javascript
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET;

function verifyToken(token) {
    try {
        return jwt.verify(token, JWT_SECRET, {
            algorithms: ['HS256'],        // Explicitly allowlist one algorithm
            issuer: 'my-app',
            audience: 'my-app-users',
        });
    } catch (err) {
        throw new Error(`Invalid token: ${err.message}`);
    }
}

// Middleware
function authenticate(req, res, next) {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'No token' });
    try {
        req.user = verifyToken(token);
        next();
    } catch (e) {
        res.status(401).json({ error: 'Invalid token' });
    }
}
```

---

## Cryptography

### Password Hashing

**Unsafe:**
```javascript
const crypto = require('crypto');

// MD5 — broken
crypto.createHash('md5').update(password).digest('hex');

// SHA256 without salt — rainbow-table vulnerable
crypto.createHash('sha256').update(password).digest('hex');
```

**Safe:**
```javascript
const bcrypt = require('bcrypt');
const SALT_ROUNDS = 12;

// Hash
const hash = await bcrypt.hash(password, SALT_ROUNDS);

// Verify (timing-safe comparison built in)
const match = await bcrypt.compare(password, hash);
if (!match) throw new Error('Invalid password');
```

### Cryptographically Secure Random

**Unsafe:**
```javascript
Math.random()                           // Predictable PRNG — never use for security
Math.floor(Math.random() * 1000000)     // Predictable OTP — guessable
```

**Safe:**
```javascript
const crypto = require('crypto');

// Secure random token
const token = crypto.randomBytes(32).toString('hex');   // 256-bit hex string
const urlToken = crypto.randomBytes(32).toString('base64url');

// Secure random integer in range [0, max)
function secureRandInt(max) {
    return crypto.randomInt(max);
}
```

### Symmetric Encryption

**Unsafe:**
```javascript
const crypto = require('crypto');
// ECB mode — deterministic, reveals patterns
const cipher = crypto.createCipheriv('aes-128-ecb', key, null);
// Static IV
const IV = Buffer.alloc(16, 0);  // All-zero IV — never do this
```

**Safe — AES-256-GCM (authenticated encryption):**
```javascript
const crypto = require('crypto');

function encrypt(plaintext, key) {
    const iv = crypto.randomBytes(12);          // 96-bit random IV for GCM
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    const authTag = cipher.getAuthTag();        // Authentication tag (16 bytes)
    return Buffer.concat([iv, authTag, encrypted]);
}

function decrypt(ciphertext, key) {
    const iv = ciphertext.slice(0, 12);
    const authTag = ciphertext.slice(12, 28);
    const encrypted = ciphertext.slice(28);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);
    return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8');
}
```

---

## Hardcoded Credentials

**Unsafe:**
```javascript
const DB_PASSWORD = 'hunter2';
const API_KEY = 'sk-proj-abc123xyz';
const JWT_SECRET = 'mysecret';
```

**Safe:**
```javascript
require('dotenv').config();  // For local development only

const DB_PASSWORD = process.env.DB_PASSWORD;
const API_KEY = process.env.API_KEY;
const JWT_SECRET = process.env.JWT_SECRET;

// Validate at startup
const REQUIRED = ['DB_PASSWORD', 'API_KEY', 'JWT_SECRET'];
const missing = REQUIRED.filter(k => !process.env[k]);
if (missing.length) {
    throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
}
```

---

## HTTP Security Headers (Express)

**Unsafe — no security headers:**
```javascript
const express = require('express');
const app = express();
// Missing: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, etc.
```

**Safe — use helmet:**
```javascript
const helmet = require('helmet');

app.use(helmet());  // Sets a sensible default for all security headers

// Or configure explicitly:
app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true }));
app.use(helmet.contentSecurityPolicy({
    directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'nonce-{NONCE}'"],
        styleSrc: ["'self'"],
        imgSrc: ["'self'", 'data:', 'https:'],
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"],
        upgradeInsecureRequests: [],
    },
}));
app.use(helmet.noSniff());           // X-Content-Type-Options: nosniff
app.use(helmet.frameguard({ action: 'deny' }));  // X-Frame-Options: DENY
```

---

## Prototype Pollution Prevention

**Unsafe:**
```javascript
function merge(target, source) {
    for (const key in source) {
        target[key] = source[key];  // Pollutes Object.prototype if key is __proto__
    }
}

// Attack payload: {"__proto__": {"isAdmin": true}}
merge({}, JSON.parse(attackerInput));
```

**Safe:**
```javascript
// Use Object.assign with null-prototype objects for merging untrusted data
function safeMerge(target, source) {
    const safeSource = Object.create(null);
    for (const key of Object.keys(source)) {  // Only own keys, no __proto__
        if (key !== '__proto__' && key !== 'constructor' && key !== 'prototype') {
            safeSource[key] = source[key];
        }
    }
    return Object.assign(target, safeSource);
}

// Or use lodash.merge which has built-in prototype pollution protection
const _ = require('lodash');
_.merge(target, source);  // Safe in lodash >= 4.17.11
```

---

## Error Handling and Information Disclosure

**Unsafe:**
```javascript
app.use((err, req, res, next) => {
    res.status(500).json({ error: err.message, stack: err.stack });  // Leaks internals
});

// Returning full DB error to client
db.query(query).catch(err => res.status(500).json({ error: err.message }));
```

**Safe:**
```javascript
const logger = require('./logger');  // Structured logger (winston, pino)

app.use((err, req, res, next) => {
    logger.error({ err, req: { method: req.method, url: req.url } }, 'Unhandled error');
    res.status(500).json({ error: 'Internal server error' });  // Generic message to client
});

// Safe error handling for DB queries
try {
    const result = await db.query(query, params);
    res.json(result.rows);
} catch (err) {
    logger.error({ err }, 'Database query failed');
    res.status(500).json({ error: 'Database error' });
}
```

---

## CSRF Protection

**Unsafe — no CSRF token:**
```javascript
app.post('/transfer', authenticate, async (req, res) => {
    await transferFunds(req.user.id, req.body.to, req.body.amount);
    res.json({ ok: true });
});
```

**Safe — CSRF token validation:**
```javascript
const csrf = require('csurf');
const csrfProtection = csrf({ cookie: { httpOnly: true, secure: true } });

app.post('/transfer', authenticate, csrfProtection, async (req, res) => {
    await transferFunds(req.user.id, req.body.to, req.body.amount);
    res.json({ ok: true });
});

// For SPA/API: validate Origin/Referer header
function validateOrigin(req, res, next) {
    const origin = req.headers.origin || req.headers.referer || '';
    if (!origin.startsWith('https://app.example.com')) {
        return res.status(403).json({ error: 'CSRF validation failed' });
    }
    next();
}
```

---

## Dependency Security

**Package audit:**
```bash
npm audit                    # Check for known vulnerabilities
npm audit fix                # Auto-fix where possible
npx snyk test                # Snyk deep analysis with fix suggestions
```

**Lock file hygiene:**
```bash
# Always commit package-lock.json or yarn.lock
# Regenerate if corrupted:
rm package-lock.json && npm install

# Verify package integrity
npm ci                       # Installs exactly what's in lock file
```

**Avoid dangerous packages:**
```javascript
// Never use in production:
eval(code)                   // Code execution
new Function(code)()         // Code execution
require('vm').runInThisContext(code)  // Sandbox escape risk
```
