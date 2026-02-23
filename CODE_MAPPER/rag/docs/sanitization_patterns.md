# Sanitization & Validation Patterns

Per-sink reference for safe and unsafe patterns across languages. Used by agents to assess whether a taint path is adequately sanitized and to recommend specific remediation for each sink type.

---

## SQL Injection Prevention

### Safe Patterns

**Python — sqlite3:**
```python
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
cursor.execute("SELECT * FROM users WHERE name = ? AND active = ?", (name, True))
```

**Python — psycopg2 (PostgreSQL):**
```python
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
cursor.executemany("INSERT INTO items (name, val) VALUES (%s, %s)", rows)
```

**Python — SQLAlchemy ORM:**
```python
# Safe: ORM builds parameterized query
user = session.query(User).filter(User.id == user_id).first()
# Safe: text() with bound parameters
from sqlalchemy import text
result = session.execute(text("SELECT * FROM users WHERE id = :id"), {"id": user_id})
```

**Python — Django ORM:**
```python
User.objects.filter(id=user_id)  # Safe ORM query
User.objects.raw("SELECT * FROM users WHERE id = %s", [user_id])  # Safe raw with params
```

**JavaScript — node-postgres (pg):**
```javascript
const result = await client.query('SELECT * FROM users WHERE id = $1', [userId]);
```

**JavaScript — MySQL2:**
```javascript
const [rows] = await connection.execute('SELECT * FROM users WHERE id = ?', [userId]);
```

**JavaScript — Sequelize ORM:**
```javascript
const user = await User.findOne({ where: { id: userId } });
// Safe raw query with replacements:
const users = await sequelize.query('SELECT * FROM users WHERE id = :id',
    { replacements: { id: userId }, type: QueryTypes.SELECT });
```

**Java — PreparedStatement (JDBC):**
```java
PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
stmt.setInt(1, userId);
ResultSet rs = stmt.executeQuery();
```

**Java — JPA/Hibernate:**
```java
TypedQuery<User> query = em.createQuery("SELECT u FROM User u WHERE u.id = :id", User.class);
query.setParameter("id", userId);
User user = query.getSingleResult();
```

### Unsafe Patterns (Never Use)

```python
# String concatenation
query = f"SELECT * FROM users WHERE id = {user_id}"
query = "SELECT * FROM users WHERE id = " + user_id

# String formatting
query = "SELECT * FROM users WHERE id = {}".format(user_id)
query = "SELECT * FROM users WHERE id = %s" % user_id  # Note: % formatting IS unsafe

# Even with escaping — escaping is NOT sufficient
query = f"SELECT * FROM users WHERE name = '{escape(name)}'"  # Still injectable in some DBs
```

### Why Escaping Is Not Enough
Character encoding tricks, multi-byte characters, and context-specific injection can bypass manual escaping in many databases. Parameterized queries are the **only** fully safe approach.

---

## OS Command Injection Prevention

### Safe Patterns

**Python — subprocess with argument list:**
```python
import subprocess

# Safe: arguments passed as list, no shell interpretation
subprocess.run(['ping', '-c', '1', host], shell=False, capture_output=True, timeout=10)
subprocess.run(['convert', input_file, '-resize', '800x', output_file], shell=False)

# Safe: check=True raises on non-zero exit
result = subprocess.run(['ls', directory], shell=False, capture_output=True, check=True)
```

**Python — when shell=True is unavoidable (last resort):**
```python
import shlex
# shlex.quote wraps value in single quotes and escapes internals
safe_host = shlex.quote(host)
subprocess.run(f"ping -c 1 {safe_host}", shell=True)
# Still prefer argument lists over this approach
```

**JavaScript — child_process.execFile:**
```javascript
const { execFile } = require('child_process');
execFile('ls', ['-la', directory], (error, stdout) => {
    if (error) throw error;
    console.log(stdout);
});
```

**JavaScript — promisified execFile:**
```javascript
const { execFile } = require('child_process');
const { promisify } = require('util');
const execFileAsync = promisify(execFile);
const { stdout } = await execFileAsync('convert', [inputFile, '-resize', '800x', outputFile]);
```

### Unsafe Patterns

```python
import os
os.system(f"ping {host}")                              # Shell injection via host
os.popen(f"cat {filename}")                            # Same issue
subprocess.call(f"ls {directory}", shell=True)         # shell=True with user data
subprocess.Popen(user_command, shell=True)             # Arbitrary command execution
```

```javascript
const { exec } = require('child_process');
exec(`ls ${req.query.dir}`);                           // Shell injection
exec('convert ' + inputFile + ' output.jpg');          // Concatenation = injection
```

---

## Path Traversal Prevention

### Safe Patterns

**Python — resolve and prefix check:**
```python
from pathlib import Path

BASE_DIR = Path('/var/www/uploads').resolve()

def safe_open(filename: str) -> Path:
    target = (BASE_DIR / filename).resolve()
    if not str(target).startswith(str(BASE_DIR) + '/'):
        raise ValueError(f"Path traversal detected: {filename}")
    return target

with open(safe_open(user_filename)) as f:
    content = f.read()
```

**Python — allowlist extension check:**
```python
ALLOWED_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.pdf'}

def validate_filename(filename: str) -> str:
    path = Path(filename)
    if path.suffix.lower() not in ALLOWED_EXTENSIONS:
        raise ValueError(f"Extension not allowed: {path.suffix}")
    # Strip directory components
    return path.name  # Returns only the filename, no path components
```

**JavaScript — path.resolve + startsWith:**
```javascript
const path = require('path');
const BASE_DIR = '/var/www/uploads';

function safePath(filename) {
    const resolved = path.resolve(BASE_DIR, filename);
    if (!resolved.startsWith(BASE_DIR + path.sep)) {
        throw new Error('Path traversal detected');
    }
    return resolved;
}
```

### Unsafe Patterns

```python
# os.path.join does NOT prevent traversal
open(os.path.join('/uploads', user_filename))     # '../../../etc/passwd' still works

# Simple prefix check without resolve is bypassable
if not user_filename.startswith('/uploads'):       # Bypassable with symlinks
    raise ValueError()

# String replacement is insufficient
filename = user_filename.replace('../', '')        # '....//....//etc/passwd' bypasses
```

---

## XSS Prevention

### Safe Patterns

**Python — Jinja2/Flask (autoescaping on by default for HTML templates):**
```python
# In render_template, variables are autoescaped in .html files
return render_template('page.html', name=user_name)

# Template:
# <h1>Hello, {{ name }}</h1>   ← autoescaped
```

**Python — explicit escaping (when autoescaping is off):**
```python
from markupsafe import escape
safe_name = escape(user_name)
return f"<h1>Hello, {safe_name}</h1>"
```

**Python — Django (autoescaping on by default):**
```django
{{ user_input }}        {# Autoescaped #}
{{ user_input|safe }}   {# UNSAFE — disables escaping #}
```

**JavaScript — React (escapes JSX expressions by default):**
```jsx
// Safe: React escapes text content automatically
<div>{userInput}</div>

// Safe: textContent in vanilla JS
element.textContent = userInput;
```

**JavaScript — vanilla DOM (safe methods):**
```javascript
element.textContent = userInput;           // Safe — no HTML parsing
element.setAttribute('data-value', val);   // Safe for attribute values
```

**Content Security Policy header:**
```
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';
```

### Unsafe Patterns

```python
return f"<h1>Hello, {user_name}</h1>"        # Raw f-string in response — reflected XSS
return render_template_string(user_template)  # Template injection if user controls template
```

```javascript
element.innerHTML = userInput;               // XSS — parses HTML
document.write(userInput);                   // XSS — writes to document
eval(userInput);                             // Code execution
```

```jsx
<div dangerouslySetInnerHTML={{ __html: userInput }} />  // XSS in React
```

---

## Deserialization Prevention

### Safe Patterns

**Python — use JSON for cross-boundary data:**
```python
import json
data = json.loads(request.get_data(as_text=True))  # Safe structured format
```

**Python — YAML safe loading:**
```python
import yaml
config = yaml.safe_load(config_string)  # Restricts to basic types only
```

**Python — if pickle is required internally (never on untrusted data):**
```python
import pickle
import hmac, hashlib

SECRET = os.environ['PICKLE_SECRET']

def safe_pickle_loads(data: bytes) -> object:
    payload, sig = data[:-32], data[-32:]
    expected = hmac.new(SECRET.encode(), payload, hashlib.sha256).digest()
    if not hmac.compare_digest(sig, expected):
        raise ValueError("Pickle signature invalid")
    return pickle.loads(payload)
```

**JavaScript — JSON.parse is always safe:**
```javascript
const data = JSON.parse(req.body);  // Safe — only parses JSON, no code execution
```

### Unsafe Patterns

```python
pickle.loads(user_data)              # Arbitrary Python code execution
yaml.load(config, Loader=yaml.Loader)  # !!python/object executes code
```

```php
unserialize($userData);              // Object injection, possibly RCE
```

```java
ObjectInputStream ois = new ObjectInputStream(inputStream);
Object obj = ois.readObject();       // Gadget chain exploitation without allowlisting
```

---

## Authentication Token Validation

### Safe Patterns

**Python — JWT with full verification:**
```python
import jwt

def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=['HS256'],     # Allowlist algorithms explicitly
            options={'require': ['exp', 'iat', 'sub']}  # Require standard claims
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise AuthError("Token expired")
    except jwt.InvalidTokenError as e:
        raise AuthError(f"Invalid token: {e}")
```

**Python — verify expiry explicitly:**
```python
if payload.get('exp', 0) < time.time():
    raise AuthError("Token expired")
```

### Unsafe Patterns

```python
# Skipping signature verification
payload = jwt.decode(token, options={"verify_signature": False})

# Accepting 'none' algorithm
payload = jwt.decode(token, algorithms=['HS256', 'none'])  # 'none' = no verification

# Trusting algorithm from token header (alg confusion attack)
header = jwt.get_unverified_header(token)
payload = jwt.decode(token, key, algorithms=[header['alg']])  # Attacker controls alg
```

---

## Cryptography Patterns

### Password Hashing

**Safe:**
```python
import bcrypt
# Hash
hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12))
# Verify
bcrypt.checkpw(password.encode('utf-8'), hashed)

# Or argon2 (preferred for new systems)
from argon2 import PasswordHasher
ph = PasswordHasher(time_cost=2, memory_cost=65536, parallelism=2)
hash = ph.hash(password)
ph.verify(hash, password)
```

**Unsafe:**
```python
hashlib.md5(password.encode()).hexdigest()    # Broken — rainbow table reversible
hashlib.sha1(password.encode()).hexdigest()   # Broken
hashlib.sha256(password.encode()).hexdigest() # Without salt — still vulnerable to rainbow tables
```

### Symmetric Encryption

**Safe:**
```python
from cryptography.fernet import Fernet
# Fernet = AES-128-CBC + HMAC-SHA256; handles IV generation automatically
key = Fernet.generate_key()
f = Fernet(key)
token = f.encrypt(data)
data = f.decrypt(token)

# Or AES-GCM for custom implementations
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
key = AESGCM.generate_key(bit_length=256)
aead = AESGCM(key)
nonce = os.urandom(12)
ciphertext = aead.encrypt(nonce, data, associated_data)
```

**Unsafe:**
```python
from Crypto.Cipher import AES
cipher = AES.new(key, AES.MODE_ECB)   # ECB: deterministic, reveals patterns
iv = b'\x00' * 16
cipher = AES.new(key, AES.MODE_CBC, iv)  # Static IV: breaks CBC security
```

---

## Input Length and Type Validation

### Safe Patterns

**Python — Pydantic for structured validation:**
```python
from pydantic import BaseModel, constr, confloat

class CreateUserRequest(BaseModel):
    username: constr(min_length=3, max_length=32, pattern=r'^[a-zA-Z0-9_]+$')
    age: int
    email: str

    class Config:
        # Reject extra fields not in schema
        extra = 'forbid'
```

**Python — manual validation:**
```python
def validate_username(username: str) -> str:
    if not isinstance(username, str):
        raise ValueError("Username must be a string")
    if not (3 <= len(username) <= 32):
        raise ValueError("Username must be 3–32 characters")
    if not re.fullmatch(r'[a-zA-Z0-9_]+', username):
        raise ValueError("Username may only contain letters, digits, and underscores")
    return username
```

**JavaScript — input validation:**
```javascript
function validateUsername(username) {
    if (typeof username !== 'string') throw new Error('Must be a string');
    if (username.length < 3 || username.length > 32) throw new Error('Length 3-32');
    if (!/^[a-zA-Z0-9_]+$/.test(username)) throw new Error('Invalid characters');
    return username;
}
```

### Unsafe Patterns

```python
# No validation — type coercion issues
age = int(request.args.get('age'))           # Crashes on non-integer; no range check
username = request.args.get('username', '')  # Accepted as-is; no length/format check
```

---

## Redirect Validation

### Safe Patterns

**Python — allowlist redirect targets:**
```python
ALLOWED_REDIRECT_HOSTS = {'example.com', 'app.example.com'}

def safe_redirect(url: str) -> str:
    from urllib.parse import urlparse
    parsed = urlparse(url)
    # Reject absolute URLs to external hosts
    if parsed.netloc and parsed.netloc not in ALLOWED_REDIRECT_HOSTS:
        return '/'  # Fall back to home page
    # Only allow relative paths or known-safe hosts
    return url

return redirect(safe_redirect(request.args.get('next', '/')))
```

### Unsafe Patterns

```python
next_url = request.args.get('next')
return redirect(next_url)  # Open redirect — attacker controls destination

# Partial checks are bypassable:
if next_url.startswith('/'):
    return redirect(next_url)  # '//evil.com' is still absolute URL
```
