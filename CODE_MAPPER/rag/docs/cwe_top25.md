# CWE Top 25 Most Dangerous Software Weaknesses (2023)

Comprehensive reference for the most critical software weaknesses. Each entry includes description, detection patterns, code examples, and mitigations. Used by agents to classify findings, assess severity, and generate remediation guidance.

---

## CWE-787: Out-of-bounds Write
**Rank:** #1 | **Severity:** CRITICAL

### Description
Writing data past the end, or before the beginning, of an intended buffer. Commonly leads to memory corruption, crashes, or code execution in C/C++ programs.

### Detection Patterns
```c
// Unsafe
char buf[8];
strcpy(buf, user_input);  // No bounds check; overflows if input > 7 chars

// Safe
char buf[8];
strncpy(buf, user_input, sizeof(buf) - 1);
buf[sizeof(buf) - 1] = '\0';
```

### Mitigations
- Use safe string functions (`strncpy`, `strncat`, `snprintf`)
- Use memory-safe languages (Python, Go, Rust) when possible
- Enable compiler stack protection (`-fstack-protector-all`)
- Use address sanitizer (ASan) during testing

---

## CWE-79: Cross-site Scripting (XSS)
**Rank:** #2 | **Severity:** HIGH–CRITICAL

### Description
User-supplied input is incorporated into HTML output without proper escaping, allowing injection of malicious scripts into pages served to other users.

### Subtypes
- **Reflected XSS:** Input immediately reflected in response
- **Stored XSS:** Input stored (database, file) and later served to users
- **DOM-based XSS:** Client-side script writes attacker-controlled data to DOM

### Detection Patterns

**Python Flask (Unsafe):**
```python
from flask import request
@app.route('/search')
def search():
    q = request.args.get('q', '')
    return f"<h1>Results for {q}</h1>"  # Reflected XSS
```

**Python Flask (Safe):**
```python
from markupsafe import escape
@app.route('/search')
def search():
    q = escape(request.args.get('q', ''))
    return f"<h1>Results for {q}</h1>"
```

**JavaScript React (Unsafe):**
```jsx
<div dangerouslySetInnerHTML={{ __html: userInput }} />
```

**JavaScript React (Safe):**
```jsx
<div>{userInput}</div>  {/* React escapes by default */}
```

**Django template (Unsafe):**
```html
{{ user_input|safe }}  <!-- Disables autoescaping -->
```

**Django template (Safe):**
```html
{{ user_input }}  <!-- Autoescaped by default -->
```

### Mitigations
- Use templating engines with autoescaping enabled by default
- Apply context-aware encoding (HTML, URL, JS, CSS contexts differ)
- Implement Content Security Policy (CSP) headers
- Use `HttpOnly` and `Secure` cookie flags

---

## CWE-89: SQL Injection
**Rank:** #3 | **Severity:** CRITICAL

### Description
SQL query constructed using unsanitized user input, allowing attackers to modify query logic, extract data, bypass authentication, or execute admin operations.

### Detection Patterns

**Python (Unsafe):**
```python
user_id = request.args.get('id')
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
# Attack: id=1 OR 1=1 — dumps all users
# Attack: id=1; DROP TABLE users --
```

**Python (Safe — parameterized):**
```python
user_id = request.args.get('id')
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

**Python (Safe — SQLAlchemy ORM):**
```python
user = session.query(User).filter(User.id == user_id).first()
```

**JavaScript (Unsafe):**
```javascript
const query = `SELECT * FROM users WHERE name = '${req.body.name}'`;
db.query(query);
```

**JavaScript (Safe — node-postgres):**
```javascript
db.query('SELECT * FROM users WHERE name = $1', [req.body.name]);
```

**Java (Unsafe):**
```java
String query = "SELECT * FROM users WHERE id = " + userId;
stmt.executeQuery(query);
```

**Java (Safe — PreparedStatement):**
```java
PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
stmt.setInt(1, userId);
stmt.executeQuery();
```

### Mitigations
- Always use parameterized queries or prepared statements
- Use ORM with safe query builders
- Apply principle of least privilege on DB accounts
- Validate and sanitize all inputs (type check, range check)

---

## CWE-22: Path Traversal
**Rank:** #4 | **Severity:** HIGH

### Description
User-controlled input used to construct a file path, allowing access to files outside the intended directory via `../` sequences or absolute paths.

### Detection Patterns

**Python (Unsafe):**
```python
filename = request.args.get('file')
with open(f"/var/www/uploads/{filename}") as f:
    return f.read()
# Attack: file=../../../../etc/passwd
```

**Python (Safe):**
```python
from pathlib import Path
base = Path('/var/www/uploads').resolve()
filename = request.args.get('file', '')
target = (base / filename).resolve()
if not str(target).startswith(str(base)):
    abort(400)
with open(target) as f:
    return f.read()
```

### Mitigations
- Resolve path to absolute and verify it starts with the base directory
- Allowlist file extensions and reject others
- Use `os.path.realpath()` or `Path.resolve()` before comparison
- Never use `os.path.join()` alone — it does not prevent `..` traversal

---

## CWE-20: Improper Input Validation
**Rank:** #5 | **Severity:** HIGH

### Description
Software does not validate, or incorrectly validates, input that can affect control flow or data integrity. Broad root cause for many downstream vulnerabilities.

### Detection Patterns

**Python (Unsafe):**
```python
age = int(request.args.get('age'))  # No bounds check; crashes on non-integer input
```

**Python (Safe):**
```python
try:
    age = int(request.args.get('age', ''))
    if not (0 <= age <= 150):
        raise ValueError("Age out of range")
except ValueError:
    abort(400)
```

### Mitigations
- Validate type, format, length, range, and allowed values
- Prefer allowlisting over denylisting
- Fail closed: reject invalid input rather than silently accepting it

---

## CWE-125: Out-of-bounds Read
**Rank:** #6 | **Severity:** HIGH

### Description
Reading data past the end of an intended buffer. Can lead to information disclosure or crashes.

### Detection Patterns
```c
int arr[10];
int val = arr[user_index];  // No bounds check; reads past array end if index >= 10
```

### Mitigations
- Always validate array indices before access
- Use bounds-checked containers (C++ `std::vector::at()`, Rust slices)

---

## CWE-78: OS Command Injection
**Rank:** #7 | **Severity:** CRITICAL

### Description
User input incorporated into an OS command string, allowing execution of arbitrary commands on the host system.

### Detection Patterns

**Python (Unsafe):**
```python
import os
filename = request.args.get('file')
os.system(f"cat {filename}")  # Attack: file=x; rm -rf /
```

**Python (Unsafe — subprocess with shell=True):**
```python
import subprocess
subprocess.call(f"ping {host}", shell=True)  # Shell injection via host
```

**Python (Safe):**
```python
import subprocess
subprocess.run(['ping', '-c', '1', host], shell=False, capture_output=True)
```

**JavaScript (Unsafe):**
```javascript
const { exec } = require('child_process');
exec(`ls ${req.query.dir}`);  // Command injection
```

**JavaScript (Safe):**
```javascript
const { execFile } = require('child_process');
execFile('ls', [req.query.dir]);  // Arguments passed separately
```

### Mitigations
- Never pass user input to shell commands directly
- Use `shell=False` with argument lists in subprocess
- Use `execFile` instead of `exec` in Node.js
- Allowlist acceptable values where possible

---

## CWE-416: Use After Free
**Rank:** #8 | **Severity:** HIGH

### Description
Memory is referenced after it has been freed, leading to undefined behavior, data corruption, or exploitable memory corruption.

### Detection Patterns
```c
char *buf = malloc(64);
free(buf);
strcpy(buf, data);  // Use after free
```

### Mitigations
- Set pointers to NULL after freeing
- Use smart pointers in C++ (`unique_ptr`, `shared_ptr`)
- Use memory-safe languages for new development
- Enable AddressSanitizer during testing

---

## CWE-476: NULL Pointer Dereference
**Rank:** #9 | **Severity:** MEDIUM–HIGH

### Description
Dereferencing a pointer that is NULL or uninitialized leads to crashes and potentially exploitable conditions.

### Detection Patterns
```c
char *ptr = get_value();
printf("%s", ptr->name);  // Crash if ptr is NULL
```

```python
user = db.query(User).filter_by(id=user_id).first()
return user.name  # AttributeError if user is None
```

### Mitigations
- Always check return values for NULL before dereferencing
- In Python: check for None before attribute access
- Use optional types / null-safe operators in typed languages

---

## CWE-787: (See rank #1 above)

---

## CWE-502: Deserialization of Untrusted Data
**Rank:** #12 | **Severity:** CRITICAL

### Description
Deserializing data from untrusted sources using unsafe formats (pickle, Java ObjectInputStream, PHP unserialize) allows attackers to achieve arbitrary code execution or object injection.

### Detection Patterns

**Python (Unsafe):**
```python
import pickle
data = pickle.loads(request.get_data())  # Arbitrary code execution
```

**Python (Unsafe):**
```python
import yaml
config = yaml.load(user_input)  # !!python/object tag executes code
```

**Python (Safe):**
```python
import json
data = json.loads(request.get_data())

import yaml
config = yaml.safe_load(user_input)
```

**Java (Unsafe):**
```java
ObjectInputStream ois = new ObjectInputStream(inputStream);
Object obj = ois.readObject();  // Gadget chain exploitation
```

### Mitigations
- Never deserialize untrusted data with pickle, Java ObjectInputStream, PHP unserialize
- Use JSON, protobuf, or MessagePack for cross-trust-boundary serialization
- Implement deserialization allowlisting (Java: `ObjectInputFilter`)
- Sign serialized data and validate signature before deserialization

---

## CWE-287: Improper Authentication
**Rank:** #13 | **Severity:** CRITICAL

### Description
Authentication mechanism is missing, bypassed, or incorrectly implemented, allowing attackers to assume other users' identities or skip authentication entirely.

### Detection Patterns

**Python (Unsafe — JWT not verified):**
```python
import jwt
token = request.headers.get('Authorization', '').replace('Bearer ', '')
payload = jwt.decode(token, options={"verify_signature": False})  # No verification!
```

**Python (Safe):**
```python
payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
```

**Python (Unsafe — missing auth check):**
```python
@app.route('/admin/delete_user', methods=['POST'])
def delete_user():
    user_id = request.form.get('user_id')
    db.delete(User, user_id)  # No authentication check
```

### Mitigations
- Always verify JWTs with the correct secret/key and algorithm
- Apply authentication decorators/middleware to all protected routes
- Implement MFA for sensitive operations
- Use established auth libraries rather than custom implementations

---

## CWE-798: Use of Hard-coded Credentials
**Rank:** #18 | **Severity:** HIGH

### Description
Credentials (passwords, API keys, encryption keys, tokens) embedded directly in source code. Discoverable via source code access, binary analysis, or public repositories.

### Detection Patterns

**Unsafe:**
```python
DATABASE_URL = "postgresql://admin:secretpassword@db:5432/prod"
API_KEY = "sk-proj-abc123xyz789"
SECRET_KEY = "hardcoded-flask-secret"
```

**Safe:**
```python
import os
DATABASE_URL = os.environ['DATABASE_URL']
API_KEY = os.environ['API_KEY']
SECRET_KEY = os.environ['SECRET_KEY']
```

### Mitigations
- Store all secrets in environment variables or secret managers (AWS Secrets Manager, HashiCorp Vault)
- Use `.env` files for local development; add `.env` to `.gitignore`
- Scan repositories for secrets using `trufflehog`, `gitleaks`, `detect-secrets`
- Rotate any credential that has been committed to a repository

---

## CWE-862: Missing Authorization
**Rank:** #11 | **Severity:** HIGH

### Description
Performing an operation on a resource without verifying that the requester has permission to do so. Differs from missing authentication (who are you?) — this is missing authorization (are you allowed?).

### Detection Patterns

**Python (Unsafe):**
```python
@app.route('/post/<int:post_id>/delete', methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get(post_id)
    db.session.delete(post)  # No ownership check — any logged-in user can delete any post
```

**Python (Safe):**
```python
@app.route('/post/<int:post_id>/delete', methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author_id != current_user.id and not current_user.is_admin:
        abort(403)
    db.session.delete(post)
```

### Mitigations
- Enforce object-level authorization on every request
- Centralize authorization logic in a reusable function or middleware
- Test authorization with multiple user roles in integration tests

---

## CWE-306: Missing Authentication for Critical Function
**Rank:** #36 (included for relevance) | **Severity:** CRITICAL

### Description
Critical functionality accessible without any authentication. Common in admin interfaces, internal APIs, or development endpoints left exposed in production.

### Detection Patterns

```python
# Unsafe: admin endpoint with no auth
@app.route('/admin/reset_all_passwords', methods=['POST'])
def reset_all_passwords():
    for user in User.query.all():
        user.password = generate_temp_password()
    db.session.commit()

# Safe: protected with admin role check
@app.route('/admin/reset_all_passwords', methods=['POST'])
@login_required
@require_role('admin')
def reset_all_passwords():
    ...
```

### Mitigations
- Apply authentication to all non-public endpoints
- Audit all routes for missing authentication decorators
- Use default-deny middleware that requires explicit opt-out for public routes

---

## CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
**Rank:** #20 | **Severity:** MEDIUM–HIGH

### Description
Sensitive information (credentials, PII, internal paths, stack traces, business logic) is exposed to unauthorized actors through error messages, logs, API responses, or comments.

### Detection Patterns

**Python (Unsafe — stack trace in response):**
```python
@app.errorhandler(Exception)
def handle_error(e):
    return str(e), 500  # Leaks internal paths, library versions, SQL queries
```

**Python (Unsafe — sensitive data in response):**
```python
return jsonify(user.__dict__)  # May include password_hash, internal fields
```

**Python (Safe):**
```python
return jsonify({
    'id': user.id,
    'email': user.email,
    'name': user.name
    # Explicitly allowlist response fields
})
```

### Mitigations
- Return generic error messages to clients; log details server-side
- Explicitly allowlist fields included in API responses
- Redact sensitive fields in logs (passwords, tokens, full card numbers)
- Disable debug mode in production

---

## CWE-352: Cross-Site Request Forgery (CSRF)
**Rank:** #9 (in web context) | **Severity:** HIGH

### Description
An attacker tricks an authenticated user's browser into making an unintended request to a web application, executing actions with the victim's privileges.

### Detection Patterns

**Unsafe — no CSRF protection:**
```python
@app.route('/transfer', methods=['POST'])
@login_required
def transfer():
    amount = request.form.get('amount')
    to_account = request.form.get('to')
    transfer_funds(current_user.id, to_account, amount)
```

**Safe — CSRF token validation (Flask-WTF):**
```python
from flask_wtf.csrf import CSRFProtect
csrf = CSRFProtect(app)

# In template:
# <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
```

### Mitigations
- Use CSRF tokens on all state-changing requests (POST, PUT, DELETE, PATCH)
- Use `SameSite=Strict` or `SameSite=Lax` cookie attribute
- Validate `Origin` and `Referer` headers on sensitive operations
- Use framework-provided CSRF protection (Django CSRF middleware, Flask-WTF)

---

## CWE-918: Server-Side Request Forgery (SSRF)
**Rank:** #19 | **Severity:** HIGH–CRITICAL

### Description
Application fetches a remote resource based on user-supplied URL without restricting schemes, hosts, or ports. Allows attackers to scan internal networks or access cloud metadata endpoints.

### Detection Patterns

**Python (Unsafe):**
```python
url = request.args.get('url')
response = requests.get(url)  # Can reach http://169.254.169.254/latest/meta-data/
```

**Python (Safe):**
```python
from urllib.parse import urlparse
ALLOWED_HOSTS = {'api.example.com'}
parsed = urlparse(url)
if parsed.hostname not in ALLOWED_HOSTS or parsed.scheme not in ('http', 'https'):
    abort(400)
response = requests.get(url, timeout=5, allow_redirects=False)
```

### Mitigations
- Allowlist permitted URL schemes and destination hostnames
- Disable redirects or re-validate after redirect
- Block private IP ranges (10.x, 172.16.x, 192.168.x, 127.x, 169.254.x)

---

## CWE-532: Insertion of Sensitive Information into Log File
**Rank:** #35 (included for relevance) | **Severity:** MEDIUM

### Description
Sensitive data written to log files that may be accessible to unauthorized parties, retained longer than intended, or visible in log aggregation systems.

### Detection Patterns

**Unsafe:**
```python
logger.info(f"Login attempt: user={username}, password={password}")
logger.debug(f"Request headers: {request.headers}")  # May contain Authorization header
```

**Safe:**
```python
logger.info("Login attempt: user=%s", username)  # No password
logger.debug("Request path: %s method: %s", request.path, request.method)
```

### Mitigations
- Never log passwords, tokens, full credit card numbers, or SSNs
- Mask or hash sensitive identifiers before logging
- Apply log redaction middleware in production environments

---

## CWE-770: Allocation of Resources Without Limits or Throttling
**Rank:** #37 (included for relevance) | **Severity:** MEDIUM

### Description
Software does not properly limit resource consumption, enabling attackers to cause denial of service by exhausting memory, CPU, disk, or network resources.

### Detection Patterns

**Python (Unsafe — unbounded file upload):**
```python
data = request.get_data()  # No size limit — can exhaust server memory
```

**Python (Safe):**
```python
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH
```

**Python (Unsafe — no rate limit):**
```python
@app.route('/login', methods=['POST'])
def login():
    ...  # Brute-forceable without rate limiting
```

### Mitigations
- Set maximum request body size limits
- Apply rate limiting on authentication, search, and expensive endpoints
- Use timeouts on external calls and database queries
- Implement circuit breakers for dependent services
