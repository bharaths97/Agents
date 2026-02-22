# OWASP Top 10 2021

Reference for web application security risk classification. Used by agents to map findings to OWASP categories, assess domain risk, and recommend mitigations.

---

## A01:2021 — Broken Access Control

### Description
Access control enforces that users cannot act outside their intended permissions. Failures lead to unauthorized information disclosure, modification, or destruction of data, or performing business functions outside the user's limits.

### Common Manifestations
- Horizontal privilege escalation: accessing another user's resources by modifying a URL or parameter (e.g., `/user/123` → `/user/124`)
- Vertical privilege escalation: accessing admin functions without admin role
- CORS misconfiguration allowing unauthorized API access
- Missing authentication on API endpoints
- Force browsing to authenticated pages without session
- JWT token manipulation (altering payload without signature verification)

### Detection Patterns

**Python (Unsafe — BOLA):**
```python
@app.route('/user/<user_id>')
def get_user(user_id):
    user = db.query(User).filter_by(id=user_id).first()
    return user.to_dict()  # No check: is current_user.id == user_id?
```

**Python (Safe):**
```python
from flask_login import current_user
from flask import abort

@app.route('/user/<user_id>')
def get_user(user_id):
    if str(current_user.id) != str(user_id) and not current_user.is_admin:
        abort(403)
    user = db.query(User).filter_by(id=user_id).first()
    return user.to_dict()
```

**JavaScript (Unsafe):**
```javascript
app.get('/api/order/:id', async (req, res) => {
    const order = await Order.findById(req.params.id);
    res.json(order);  // No ownership check
});
```

**JavaScript (Safe):**
```javascript
app.get('/api/order/:id', async (req, res) => {
    const order = await Order.findById(req.params.id);
    if (!order || order.userId.toString() !== req.user.id) {
        return res.status(403).json({ error: 'Forbidden' });
    }
    res.json(order);
});
```

### CWE Mappings
- CWE-284: Improper Access Control
- CWE-285: Improper Authorization
- CWE-639: Authorization Bypass Through User-Controlled Key
- CWE-862: Missing Authorization

### Prevention Checklist
- Deny by default; allowlist access explicitly
- Log access control failures and alert on high rates
- Rate-limit API endpoints to limit automated enumeration
- Invalidate server-side sessions on logout
- Enforce object-level authorization on every request

---

## A02:2021 — Cryptographic Failures

### Description
Failures related to cryptography that often lead to sensitive data exposure. Includes using weak algorithms, hardcoded secrets, transmitting sensitive data in cleartext, or improper key management.

### Common Manifestations
- Passwords stored as MD5 or SHA1 hashes (reversible via rainbow tables)
- Sensitive data transmitted over HTTP (not HTTPS)
- Hardcoded API keys, passwords, or secrets in source code
- Weak random number generation for security tokens
- Static IVs in symmetric encryption
- ECB mode encryption (deterministic, reveals patterns)

### Detection Patterns

**Python (Unsafe — weak hashing):**
```python
import hashlib
password_hash = hashlib.md5(password.encode()).hexdigest()  # MD5 is broken
```

**Python (Safe):**
```python
import bcrypt
password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
# Or: use argon2-cffi
from argon2 import PasswordHasher
ph = PasswordHasher()
hash = ph.hash(password)
```

**Python (Unsafe — hardcoded secret):**
```python
SECRET_KEY = "mysecretkey123"  # Hardcoded
JWT_SECRET = "hardcoded-jwt-secret"
```

**Python (Safe):**
```python
import os
SECRET_KEY = os.environ['SECRET_KEY']  # From environment
```

**Python (Unsafe — ECB mode):**
```python
from Crypto.Cipher import AES
cipher = AES.new(key, AES.MODE_ECB)  # ECB is deterministic
```

**Python (Safe):**
```python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
iv = get_random_bytes(16)
cipher = AES.new(key, AES.MODE_CBC, iv)  # CBC with random IV
```

### CWE Mappings
- CWE-327: Use of a Broken or Risky Cryptographic Algorithm
- CWE-319: Cleartext Transmission of Sensitive Information
- CWE-798: Use of Hard-coded Credentials
- CWE-330: Use of Insufficiently Random Values

### Prevention Checklist
- Classify data processed, stored, transmitted; apply controls per sensitivity
- Don't store sensitive data unnecessarily
- Encrypt all sensitive data at rest and in transit (TLS 1.2+)
- Use Argon2, scrypt, or bcrypt for passwords — never MD5/SHA1
- Use authenticated encryption (AES-GCM) for symmetric encryption
- Store secrets in environment variables or vaults, never source code

---

## A03:2021 — Injection

### Description
User-supplied data is sent to an interpreter as part of a command or query. Includes SQL, NoSQL, OS command, LDAP, expression language injection, and more.

### Common Manifestations
- SQL queries built with string concatenation from user input
- OS commands assembled from user-controlled data
- Template injection in server-side rendering engines
- LDAP queries with unsanitized distinguished names
- XML/XPath injection

### Detection Patterns

**Python (Unsafe — SQL injection):**
```python
user_id = request.args.get('id')
query = f"SELECT * FROM users WHERE id = {user_id}"
conn.execute(query)
```

**Python (Safe):**
```python
user_id = request.args.get('id')
conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
```

**Python (Unsafe — OS command injection):**
```python
import os
filename = request.args.get('file')
os.system(f"cat {filename}")  # Allows ; rm -rf /
```

**Python (Safe):**
```python
import subprocess
from pathlib import Path
filename = request.args.get('file')
safe_path = (Path('/uploads') / filename).resolve()
if not str(safe_path).startswith('/uploads'):
    raise ValueError("Path traversal")
subprocess.run(['cat', str(safe_path)], shell=False, capture_output=True)
```

**JavaScript (Unsafe — SQL):**
```javascript
const query = `SELECT * FROM users WHERE id = ${req.params.id}`;
db.query(query);
```

**JavaScript (Safe):**
```javascript
db.query('SELECT * FROM users WHERE id = $1', [req.params.id]);
```

### CWE Mappings
- CWE-89: SQL Injection
- CWE-77: Command Injection
- CWE-78: OS Command Injection
- CWE-94: Code Injection
- CWE-79: XSS (related injection category)

### Prevention Checklist
- Use parameterized queries / prepared statements — never string concatenation
- Use ORM with safe query builders
- Validate and allowlist input where possible
- Use `shell=False` for subprocess calls; never pass user input to `shell=True`

---

## A04:2021 — Insecure Design

### Description
Risks related to missing or ineffective control design. Distinct from implementation bugs — insecure design means a secure implementation cannot defend against certain attacks because the design itself lacks necessary controls.

### Common Manifestations
- No rate limiting on credential brute-force endpoints
- Password reset via predictable token or security question only
- Business logic flaws: negative quantities in e-commerce, free item exploit
- Sensitive operations with no confirmation step or audit trail
- Missing multi-factor authentication for privileged actions

### Detection Patterns

```python
# Unsafe: no rate limiting on login
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    user = authenticate(username, password)
    ...

# Safe: rate limit applied
from flask_limiter import Limiter
limiter = Limiter(app, key_func=get_remote_address)

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    ...
```

### CWE Mappings
- CWE-770: Allocation of Resources Without Limits or Throttling
- CWE-306: Missing Authentication for Critical Function
- CWE-841: Improper Enforcement of Behavioral Workflow

### Prevention Checklist
- Threat model during design phase
- Implement rate limiting on all authentication and sensitive endpoints
- Require step-up authentication (MFA) for sensitive actions
- Segregate layers to limit blast radius of compromise
- Write security user stories and misuse cases

---

## A05:2021 — Security Misconfiguration

### Description
The most commonly seen issue. Results from insecure default configurations, incomplete or ad hoc configurations, open cloud storage, misconfigured HTTP headers, or verbose error messages exposing internal information.

### Common Manifestations
- Default admin credentials not changed
- Unnecessary features enabled (ports, services, pages, accounts, privileges)
- Stack traces and internal paths exposed in error responses
- Missing security headers (CSP, HSTS, X-Frame-Options)
- Cloud storage buckets publicly readable/writable
- Directory listing enabled on web server

### Detection Patterns

**Python (Unsafe — debug mode in production):**
```python
app.run(debug=True)  # Exposes interactive debugger to users
```

**Python (Unsafe — verbose error response):**
```python
@app.errorhandler(Exception)
def handle_error(e):
    return str(e), 500  # Leaks stack trace and internal paths
```

**Python (Safe):**
```python
@app.errorhandler(Exception)
def handle_error(e):
    app.logger.error(f"Unhandled error: {e}", exc_info=True)
    return {"error": "Internal server error"}, 500
```

**Missing security headers (Express.js):**
```javascript
// Unsafe: no security headers
const app = express();

// Safe: use helmet
const helmet = require('helmet');
app.use(helmet());
```

### CWE Mappings
- CWE-16: Configuration
- CWE-209: Information Exposure Through Error Message
- CWE-732: Incorrect Permission Assignment for Critical Resource

### Prevention Checklist
- Automated configuration verification in CI/CD
- Minimal platform — disable unnecessary features, services
- Review and update configurations as part of patch management
- Segment application architecture
- Send security directives to clients (CSP, HSTS, X-Frame-Options, etc.)

---

## A06:2021 — Vulnerable and Outdated Components

### Description
Components (libraries, frameworks, other software modules) run with the same privileges as the application. If a vulnerable component is exploited, it can facilitate serious data loss or server takeover.

### Common Manifestations
- Using known-vulnerable library versions (e.g., Log4Shell in log4j 2.x)
- No process to scan for vulnerabilities in dependencies
- Upgrading underlying platforms (OS, server software) infrequently
- Not testing compatibility of updated libraries before deployment

### Detection Patterns

```text
# Unsafe: pinned to outdated version
Django==3.1.0   # Has known CVEs — upgrade to 3.2.x or 4.x

# Safe: specify minimum secure version
Django>=4.2.0
```

### CWE Mappings
- CWE-1104: Use of Unmaintained Third Party Components
- CWE-937: Using Components with Known Vulnerabilities

### Prevention Checklist
- Inventory all components and versions on both client and server side
- Monitor CVE databases (NVD, OSV, GitHub Advisory) continuously
- Use `pip-audit`, `npm audit`, `trivy` in CI/CD pipeline
- Only obtain components from official sources over secure channels
- Remove unused dependencies, features, files, documentation

---

## A07:2021 — Identification and Authentication Failures

### Description
Confirmation of the user's identity, authentication, and session management is critical. Failures allow attackers to compromise passwords, keys, or session tokens, or exploit implementation flaws to assume other users' identities.

### Common Manifestations
- Permits brute force or credential stuffing attacks
- Permits weak passwords (e.g., "password123")
- Weak credential recovery questions
- Plain text or weakly hashed passwords in storage
- Missing or ineffective MFA
- Session tokens exposed in URL
- Session not invalidated after logout

### Detection Patterns

**Unsafe — session not invalidated:**
```python
@app.route('/logout')
def logout():
    session.pop('user_id', None)  # Client-side only; server-side session still valid
    return redirect('/')

# Safe: invalidate server-side session
@app.route('/logout')
def logout():
    session.clear()
    session.modified = True
    return redirect('/')
```

**Unsafe — weak session secret:**
```python
app.secret_key = 'dev'  # Too weak; predictable
```

### CWE Mappings
- CWE-287: Improper Authentication
- CWE-306: Missing Authentication for Critical Function
- CWE-384: Session Fixation
- CWE-521: Weak Password Requirements

### Prevention Checklist
- Implement MFA where possible
- Do not ship or deploy with default credentials
- Implement weak-password checks against known-bad-password lists
- Use secure, server-side session manager generating high-entropy session IDs
- Invalidate session IDs after logout and after idle timeout

---

## A08:2021 — Software and Data Integrity Failures

### Description
Failures related to code and infrastructure that does not protect against integrity violations. Includes insecure deserialization, unsigned software updates, and CI/CD pipeline integrity issues.

### Common Manifestations
- Deserializing untrusted data with pickle, YAML.load, Java ObjectInputStream
- Auto-update functionality that fetches and executes unsigned/unverified content
- Relying on CDN-hosted libraries without Subresource Integrity (SRI) hashes
- Insecure CI/CD pipelines allowing code injection

### Detection Patterns

**Python (Unsafe — pickle deserialization):**
```python
import pickle
data = pickle.loads(request.get_data())  # Arbitrary code execution
```

**Python (Safe):**
```python
import json
data = json.loads(request.get_data())  # Safe structured format
```

**Python (Unsafe — yaml.load):**
```python
import yaml
config = yaml.load(user_input)  # Executes arbitrary Python via !!python/object
```

**Python (Safe):**
```python
import yaml
config = yaml.safe_load(user_input)  # Restricted loader
```

### CWE Mappings
- CWE-502: Deserialization of Untrusted Data
- CWE-494: Download of Code Without Integrity Check
- CWE-829: Inclusion of Functionality from Untrusted Control Sphere

### Prevention Checklist
- Never deserialize untrusted data with pickle, Java ObjectInputStream, PHP unserialize
- Use JSON or protobuf for data serialization across trust boundaries
- Verify digital signatures or checksums on software updates
- Use SRI hashes for externally hosted JavaScript and CSS
- Audit CI/CD pipeline access and configuration changes

---

## A09:2021 — Security Logging and Monitoring Failures

### Description
Without logging and monitoring, breaches cannot be detected. Insufficient logging and monitoring, combined with missing or ineffective integration with incident response, allows attackers to persist, pivot, and tamper.

### Common Manifestations
- Auditable events (logins, failed logins, access control failures) not logged
- Warnings and errors generating no log messages
- Logs not monitored for suspicious activity
- Logs stored locally only (destroyed if server compromised)
- Log injection possible via unsanitized user input in log lines

### Detection Patterns

**Python (Unsafe — no logging of auth failure):**
```python
@app.route('/login', methods=['POST'])
def login():
    user = authenticate(username, password)
    if not user:
        return "Invalid credentials", 401  # Silent failure, no log
```

**Python (Safe):**
```python
import logging
logger = logging.getLogger(__name__)

@app.route('/login', methods=['POST'])
def login():
    user = authenticate(username, password)
    if not user:
        logger.warning("Failed login attempt for user: %s from IP: %s",
                       username, request.remote_addr)
        return "Invalid credentials", 401
```

**Log injection (Unsafe):**
```python
logger.info(f"User searched for: {user_query}")  # Query can contain newlines
```

**Log injection (Safe):**
```python
safe_query = user_query.replace('\n', '\\n').replace('\r', '\\r')
logger.info("User searched for: %s", safe_query)
```

### CWE Mappings
- CWE-532: Insertion of Sensitive Information into Log File
- CWE-778: Insufficient Logging
- CWE-117: Improper Output Neutralization for Logs

### Prevention Checklist
- Log all authentication events (success and failure) with timestamp and IP
- Log access control failures; alert on threshold breaches
- Store logs in tamper-evident, append-only store (SIEM or remote aggregator)
- Never log passwords, session tokens, or full PAN/SSN
- Sanitize user-controlled data before inclusion in log lines

---

## A10:2021 — Server-Side Request Forgery (SSRF)

### Description
SSRF flaws occur when a web application fetches a remote resource based on user-supplied input without validating the URL. Allows attackers to coerce the server to make requests to internal services, metadata endpoints, or arbitrary external URLs.

### Common Manifestations
- URL-fetch functionality with unconstrained user-supplied URL (fetch, wget, curl wrappers)
- Import-from-URL features (import document, fetch avatar by URL)
- Webhook registration with no URL allowlist
- PDF/screenshot generation from URL using headless browser
- AWS metadata endpoint access via `http://169.254.169.254/`

### Detection Patterns

**Python (Unsafe):**
```python
import requests
url = request.args.get('url')
resp = requests.get(url)  # Attacker can fetch http://169.254.169.254/latest/meta-data/
return resp.text
```

**Python (Safe — allowlist approach):**
```python
from urllib.parse import urlparse
ALLOWED_HOSTS = {'api.example.com', 'cdn.example.com'}

def safe_fetch(url):
    parsed = urlparse(url)
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError(f"Host not allowed: {parsed.hostname}")
    if parsed.scheme not in ('http', 'https'):
        raise ValueError("Only HTTP/HTTPS allowed")
    return requests.get(url, timeout=5)
```

**JavaScript (Unsafe):**
```javascript
app.get('/fetch', async (req, res) => {
    const response = await axios.get(req.query.url);  // SSRF
    res.send(response.data);
});
```

### CWE Mappings
- CWE-918: Server-Side Request Forgery (SSRF)

### Prevention Checklist
- Enforce allowlist of allowed schemes, hosts, and ports
- Disable HTTP redirections to prevent redirect-chaining to internal hosts
- Block private/reserved IP ranges (RFC 1918, loopback, link-local)
- Reject raw IP address URLs; resolve hostnames and re-validate
- Do not send raw responses from internal services to clients
