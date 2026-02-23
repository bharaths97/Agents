# Secure Coding Guide: Python

Language-specific security patterns for Python applications. Covers common vulnerability classes with unsafe and safe code examples. Used by agents to assess Python-specific security practices and generate remediation guidance.

---

## Input Validation

### Type and Range Validation

**Unsafe:**
```python
age = int(request.args.get('age'))              # Crashes on non-integer; no range check
user_id = request.args.get('user_id')           # Accepted as-is; may be None or wrong type
quantity = float(request.form.get('quantity'))  # No bounds check
```

**Safe:**
```python
from pydantic import BaseModel, conint, validator

class OrderRequest(BaseModel):
    quantity: conint(ge=1, le=1000)
    user_id: int

    @validator('user_id')
    def user_id_positive(cls, v):
        if v <= 0:
            raise ValueError('user_id must be positive')
        return v

# Or manual validation
def get_validated_age(raw: str) -> int:
    try:
        age = int(raw)
    except (ValueError, TypeError):
        raise ValueError("Age must be an integer")
    if not (0 <= age <= 150):
        raise ValueError("Age out of range")
    return age
```

### String Pattern Validation

**Unsafe:**
```python
username = request.args.get('username', '')  # No format validation
```

**Safe:**
```python
import re

USERNAME_RE = re.compile(r'^[a-zA-Z0-9_]{3,32}$')

def validate_username(username: str) -> str:
    if not USERNAME_RE.fullmatch(username):
        raise ValueError("Invalid username format")
    return username
```

---

## SQL Injection

See also: `sanitization_patterns.md` for full per-driver coverage.

**Unsafe — any form of string interpolation into SQL:**
```python
# f-string
query = f"SELECT * FROM users WHERE email = '{email}'"
# .format()
query = "SELECT * FROM users WHERE id = {}".format(user_id)
# % operator
query = "SELECT * FROM users WHERE name = '%s'" % name  # % formatting IS unsafe
```

**Safe — parameterized queries:**
```python
# sqlite3
cursor.execute("SELECT * FROM users WHERE email = ?", (email,))

# psycopg2
cursor.execute("SELECT * FROM users WHERE email = %s", (email,))

# SQLAlchemy ORM
user = session.query(User).filter(User.email == email).first()

# SQLAlchemy raw with named params
from sqlalchemy import text
result = session.execute(text("SELECT * FROM users WHERE email = :email"), {"email": email})

# Django ORM
User.objects.filter(email=email).first()
```

---

## OS Command Injection

**Unsafe:**
```python
import os, subprocess

# os.system with user input
os.system(f"convert {filename} output.jpg")

# subprocess with shell=True and string concatenation
subprocess.run(f"git clone {repo_url}", shell=True)
subprocess.call("rm " + filepath, shell=True)

# os.popen
os.popen(f"cat {filename}").read()
```

**Safe:**
```python
import subprocess
from pathlib import Path

# Always use argument lists; never shell=True with user data
subprocess.run(['convert', filename, 'output.jpg'], shell=False, check=True)

# If shell is unavoidable, use shlex.quote
import shlex
safe_url = shlex.quote(repo_url)
subprocess.run(f"git clone {safe_url}", shell=True)

# Validate inputs before use in any system call
ALLOWED_COMMANDS = {'ls', 'cat', 'head'}
if cmd not in ALLOWED_COMMANDS:
    raise ValueError(f"Command not allowed: {cmd}")
```

---

## Path Traversal

**Unsafe:**
```python
# Naive join — allows ../../../etc/passwd
with open(os.path.join('/uploads', user_filename)) as f:
    return f.read()

# String replace is bypassable
clean = user_filename.replace('../', '')  # '....//....//etc/passwd' bypasses this
```

**Safe:**
```python
from pathlib import Path

BASE = Path('/var/www/uploads').resolve()

def safe_path(filename: str) -> Path:
    target = (BASE / filename).resolve()
    # resolve() follows symlinks; check strict prefix with separator
    if not str(target).startswith(str(BASE) + '/'):
        raise PermissionError(f"Path traversal blocked: {filename}")
    return target

with open(safe_path(user_filename)) as f:
    return f.read()
```

---

## Deserialization

**Unsafe:**
```python
import pickle

# pickle.loads on untrusted data = arbitrary code execution
obj = pickle.loads(request.get_data())

# yaml.load without Loader
import yaml
config = yaml.load(config_string)  # !!python/object executes arbitrary code

# eval / exec on user input
result = eval(user_expression)
exec(user_code)
```

**Safe:**
```python
import json, yaml

# JSON: safe structured format
data = json.loads(request.get_data(as_text=True))

# YAML: use safe_load — restricts to basic types (str, int, float, list, dict)
config = yaml.safe_load(config_string)

# If pickle is required for internal data only, sign it
import hmac, hashlib, os
SECRET = os.environ['PICKLE_HMAC_SECRET'].encode()

def sign_pickle(obj: object) -> bytes:
    payload = pickle.dumps(obj)
    sig = hmac.new(SECRET, payload, hashlib.sha256).digest()
    return payload + sig

def verified_unpickle(data: bytes) -> object:
    payload, sig = data[:-32], data[-32:]
    expected = hmac.new(SECRET, payload, hashlib.sha256).digest()
    if not hmac.compare_digest(sig, expected):
        raise ValueError("Invalid pickle signature")
    return pickle.loads(payload)
```

---

## Cryptography

### Password Hashing

**Unsafe:**
```python
import hashlib

# MD5 — broken, rainbow-table reversible
hashlib.md5(password.encode()).hexdigest()

# SHA1 — broken for passwords
hashlib.sha1(password.encode()).hexdigest()

# SHA256 without salt — still vulnerable to precomputed attacks
hashlib.sha256(password.encode()).hexdigest()
```

**Safe:**
```python
# bcrypt — industry standard; adaptive cost factor
import bcrypt
hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12))
# Verify
bcrypt.checkpw(password.encode('utf-8'), hashed)

# argon2 — OWASP recommended for new systems
from argon2 import PasswordHasher
ph = PasswordHasher(time_cost=2, memory_cost=65536, parallelism=2)
hash_val = ph.hash(password)
ph.verify(hash_val, password)  # Raises VerifyMismatchError on failure
```

### Symmetric Encryption

**Unsafe:**
```python
from Crypto.Cipher import AES
# ECB mode — deterministic, reveals data patterns
cipher = AES.new(key, AES.MODE_ECB)
# Static IV — breaks CBC confidentiality
cipher = AES.new(key, AES.MODE_CBC, b'\x00' * 16)
```

**Safe:**
```python
from cryptography.fernet import Fernet
# Fernet = AES-128-CBC + HMAC-SHA256; handles IV/nonce automatically
key = Fernet.generate_key()  # Store securely
f = Fernet(key)
ciphertext = f.encrypt(plaintext.encode())
plaintext = f.decrypt(ciphertext).decode()

# Or AES-256-GCM for custom needs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
key = AESGCM.generate_key(bit_length=256)
aead = AESGCM(key)
nonce = os.urandom(12)  # 96-bit random nonce
ciphertext = aead.encrypt(nonce, data, associated_data=None)
```

### Secrets and Random Numbers

**Unsafe:**
```python
import random
token = random.randint(100000, 999999)    # Predictable PRNG — not cryptographic
session_id = str(random.getrandbits(128)) # Still not suitable for security tokens
```

**Safe:**
```python
import secrets

token = secrets.token_hex(32)            # 256-bit cryptographically secure token
session_id = secrets.token_urlsafe(32)   # URL-safe base64 token
otp = secrets.randbelow(1000000)         # Cryptographically random int in range
```

---

## Hardcoded Credentials

**Unsafe:**
```python
DATABASE_URL = "postgresql://admin:hunter2@localhost/prod"
API_KEY = "sk-proj-abc123"
SECRET_KEY = "my-secret-flask-key"
SMTP_PASSWORD = "emailpassword"
```

**Safe:**
```python
import os
from dotenv import load_dotenv

load_dotenv()  # Load from .env for local development

DATABASE_URL = os.environ['DATABASE_URL']         # Raises KeyError if not set
API_KEY = os.environ.get('API_KEY')               # Returns None if not set
SECRET_KEY = os.environ['SECRET_KEY']

# Validate required secrets are present at startup
REQUIRED_ENV = ['DATABASE_URL', 'SECRET_KEY', 'API_KEY']
missing = [k for k in REQUIRED_ENV if not os.environ.get(k)]
if missing:
    raise RuntimeError(f"Missing required environment variables: {missing}")
```

---

## Authentication and Session Management

**Unsafe:**
```python
# JWT: skipping signature verification
import jwt
payload = jwt.decode(token, options={"verify_signature": False})

# JWT: accepting 'none' algorithm
payload = jwt.decode(token, algorithms=['HS256', 'none'])

# Session: not invalidating on logout
@app.route('/logout')
def logout():
    session.pop('user_id', None)  # Session still valid server-side
```

**Safe:**
```python
import jwt

SECRET_KEY = os.environ['JWT_SECRET']
ALGORITHM = 'HS256'

def verify_jwt(token: str) -> dict:
    try:
        return jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],           # Allowlist — never include 'none'
            options={'require': ['exp', 'iat', 'sub']}
        )
    except jwt.ExpiredSignatureError:
        raise AuthError("Token expired")
    except jwt.InvalidTokenError as e:
        raise AuthError(str(e))

# Session: full invalidation on logout
from flask import session
@app.route('/logout')
@login_required
def logout():
    session.clear()
    session.modified = True
    return redirect('/')
```

---

## Logging Security

**Unsafe:**
```python
# Logging passwords or tokens
logger.info(f"Login: user={username}, password={password}")
logger.debug(f"Auth header: {request.headers.get('Authorization')}")

# Log injection via unsanitized user input
logger.info(f"Search query: {user_query}")  # query can contain \n to fake log entries
```

**Safe:**
```python
import logging
logger = logging.getLogger(__name__)

# Log username but never password
logger.info("Login attempt: user=%s from %s", username, request.remote_addr)

# Sanitize user-controlled data before logging
def sanitize_for_log(value: str) -> str:
    return value.replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')

logger.info("Search query: %s", sanitize_for_log(user_query))

# Never log these:
# - passwords or password hashes
# - session tokens or JWTs
# - full credit card numbers
# - SSNs or government ID numbers
# - OAuth tokens or API keys
```

---

## File Upload Security

**Unsafe:**
```python
@app.route('/upload', methods=['POST'])
def upload():
    f = request.files['file']
    f.save(f'/uploads/{f.filename}')  # No validation; allows ../../../etc/cron.d/shell
```

**Safe:**
```python
import os, uuid
from pathlib import Path
from werkzeug.utils import secure_filename

UPLOAD_DIR = Path('/var/www/uploads').resolve()
ALLOWED_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.pdf'}
MAX_FILE_SIZE = 16 * 1024 * 1024  # 16 MB

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    if 'file' not in request.files:
        abort(400)
    f = request.files['file']
    if f.filename == '':
        abort(400)

    # Validate extension
    ext = Path(f.filename).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        abort(400, "File type not allowed")

    # Generate safe filename — never use user-provided filename directly
    safe_name = f"{uuid.uuid4().hex}{ext}"
    dest = UPLOAD_DIR / safe_name

    # Enforce size limit (also set app.config['MAX_CONTENT_LENGTH'])
    f.seek(0, 2)
    size = f.tell()
    f.seek(0)
    if size > MAX_FILE_SIZE:
        abort(413)

    f.save(dest)
    return {'filename': safe_name}, 201
```

---

## SSRF Prevention

**Unsafe:**
```python
import requests
url = request.args.get('url')
resp = requests.get(url)  # Fetches any URL including internal services
```

**Safe:**
```python
import requests
from urllib.parse import urlparse
import ipaddress

ALLOWED_SCHEMES = {'http', 'https'}
ALLOWED_HOSTS = {'api.example.com', 'cdn.example.com'}

PRIVATE_RANGES = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),  # AWS metadata
]

def is_private_ip(hostname: str) -> bool:
    try:
        ip = ipaddress.ip_address(hostname)
        return any(ip in net for net in PRIVATE_RANGES)
    except ValueError:
        return False  # Not an IP address; hostname validation handles it

def safe_fetch(url: str) -> requests.Response:
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise ValueError("Scheme not allowed")
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("Host not allowed")
    if is_private_ip(parsed.hostname):
        raise ValueError("Private IP not allowed")
    return requests.get(url, timeout=5, allow_redirects=False)
```

---

## XML External Entity (XXE) Prevention

**Unsafe:**
```python
import xml.etree.ElementTree as ET
tree = ET.parse(user_uploaded_xml)  # Vulnerable to XXE in older Python versions

from lxml import etree
parser = etree.XMLParser()  # Default lxml parser allows external entities
tree = etree.parse(user_xml, parser)
```

**Safe:**
```python
# xml.etree.ElementTree in Python 3.8+ is safe by default for file parsing,
# but use defusedxml for untrusted input
import defusedxml.ElementTree as ET
tree = ET.parse(user_uploaded_xml)  # Blocks XXE, DTD, entity expansion

# lxml with explicit safe parser
from lxml import etree
parser = etree.XMLParser(
    resolve_entities=False,
    no_network=True,
    dtd_validation=False,
    load_dtd=False,
)
tree = etree.parse(user_xml, parser)
```

---

## Error Handling and Information Disclosure

**Unsafe:**
```python
@app.errorhandler(Exception)
def handle_error(e):
    return str(e), 500             # Leaks stack trace, internal paths, SQL queries

@app.route('/user/<id>')
def get_user(id):
    user = db.get(id)
    return jsonify(user.__dict__)  # May expose password_hash, internal fields
```

**Safe:**
```python
import logging
logger = logging.getLogger(__name__)

@app.errorhandler(Exception)
def handle_error(e):
    logger.exception("Unhandled error")     # Full details go to server logs only
    return {"error": "Internal server error"}, 500

@app.route('/user/<int:user_id>')
@login_required
def get_user(user_id):
    user = User.query.get_or_404(user_id)
    # Explicitly allowlist returned fields
    return jsonify({
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'created_at': user.created_at.isoformat(),
        # Never include: password_hash, internal_notes, admin_flags
    })
```
