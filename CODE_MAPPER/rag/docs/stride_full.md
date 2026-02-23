# STRIDE Threat Modeling Reference

Full STRIDE reference for threat identification, analysis, and mitigation. Used by agents to classify threats, build threat models, and map security controls to threat categories.

---

## Overview

STRIDE is a threat classification model developed at Microsoft. Each letter represents a threat category:

| Letter | Threat | Violated Property | Description |
|--------|--------|-------------------|-------------|
| **S** | Spoofing | Authentication | Impersonating something or someone else |
| **T** | Tampering | Integrity | Modifying data or code |
| **R** | Repudiation | Non-repudiation | Claiming not to have performed an action |
| **I** | Information Disclosure | Confidentiality | Exposing information to unauthorized actors |
| **D** | Denial of Service | Availability | Denying or degrading service to legitimate users |
| **E** | Elevation of Privilege | Authorization | Gaining capabilities without authorization |

---

## S — Spoofing

### Definition
An attacker impersonates a legitimate user, system, or component to gain unauthorized access or trust.

### Common Attack Scenarios

**User Identity Spoofing:**
- Credential theft (phishing, brute force, credential stuffing)
- Session token theft (XSS, network interception)
- Cookie manipulation (missing HttpOnly/Secure flags)
- JWT forgery (weak secret, algorithm confusion, 'none' algorithm)

**Service-to-Service Spoofing:**
- Missing mutual TLS between internal services
- Hardcoded or shared API keys for service authentication
- DNS spoofing leading to traffic redirection
- SSRF leveraged to make requests appear from internal services

**System-Level Spoofing:**
- BGP hijacking (network level)
- ARP spoofing on local networks
- Subdomain takeover (DNS record pointing to deregistered resource)

### Mitigations

| Control | Implementation |
|---------|---------------|
| Strong authentication | MFA, hardware tokens for privileged access |
| Signed tokens | JWT with RS256 (asymmetric) for service-to-service |
| mTLS | Certificate-based mutual authentication between services |
| Short-lived credentials | Tokens expire in minutes/hours, not days |
| Secure cookies | `HttpOnly`, `Secure`, `SameSite=Strict` |
| Session management | Server-side invalidation on logout; rotate IDs after login |
| Secret rotation | Rotate API keys and service credentials periodically |

### Trust Boundary Spoofing Risks
- **Internet → Edge:** Unauthenticated users claiming to be authenticated; spoofed headers (X-Forwarded-For)
- **Edge → Internal:** Services not validating internal caller identity
- **Service → Database:** DB connections without strong authentication
- **Client → API:** JWT manipulation or replay attacks

---

## T — Tampering

### Definition
An attacker modifies data, code, or configuration without authorization, violating integrity.

### Common Attack Scenarios

**Data Tampering:**
- SQL injection modifying database records
- Mass assignment (overposting) updating protected fields
- Parameter manipulation (changing `price=100` to `price=1`)
- Insecure direct object reference allowing unauthorized modification

**Code Tampering:**
- Dependency confusion / supply chain attack
- Insecure deserialization executing attacker-controlled code
- CI/CD pipeline injection (poisoned pull request, compromised dependency)
- Server-side template injection (SSTI)

**Configuration Tampering:**
- Unauthorized modification of application config via admin APIs
- Insecure feature flags controllable by users
- Race condition on config reload

### Mitigations

| Control | Implementation |
|---------|---------------|
| Input validation | Validate all inputs; reject unexpected fields |
| Parameterized queries | Prevent SQL injection from modifying data |
| HMAC / digital signatures | Sign sensitive data; verify on receipt |
| RBAC on mutations | Authorize every write operation at the object level |
| Immutable audit log | Append-only log of all data changes |
| Code signing | Sign artifacts; verify in deployment pipeline |
| Dependency pinning | Lock dependency versions; verify checksums |
| CSP | Prevent script injection modifying DOM |

### Trust Boundary Tampering Risks
- **User → API:** Modifying request parameters to alter other users' data
- **API → Database:** SQL injection through ORM raw queries or concatenated SQL
- **Build → Deploy:** Compromised packages in supply chain
- **Browser → Server:** CSRF causing state-changing requests from attacker-controlled page

---

## R — Repudiation

### Definition
A user or system denies performing an action, and there is insufficient evidence to prove otherwise.

### Common Attack Scenarios

**Missing Audit Trails:**
- Administrative actions (user deletion, config change) with no log
- Financial transactions with no audit record
- Data access without logging who accessed what and when
- Account creation/deletion without timestamps

**Log Tampering:**
- Attacker deletes or modifies logs after compromise
- Logs stored locally on compromised host
- No integrity protection (HMAC) on log entries

**Weak Non-Repudiation:**
- Shared credentials (multiple users sharing one account)
- Actions authenticated by session only (no MFA for sensitive operations)
- Weak or absent digital signature on documents/transactions

### Mitigations

| Control | Implementation |
|---------|---------------|
| Comprehensive audit logging | Log: actor, action, target, timestamp, IP, outcome |
| Tamper-evident logs | Forward logs to append-only SIEM or external system |
| Log integrity | HMAC or hash-chain on log entries |
| Individual accountability | No shared accounts; each action tied to a specific identity |
| MFA for sensitive actions | Step-up authentication for admin operations |
| Digital signatures | Sign transactions with user's private key for legal non-repudiation |
| Retention policy | Retain logs per regulatory requirement (90 days minimum; 1 year for compliance) |

### What to Log

```
For every state-changing operation:
  - WHO: authenticated user ID (not just username — IDs are stable)
  - WHAT: action taken (create_user, delete_post, update_price, login)
  - TARGET: resource affected (user:123, post:456, product:789)
  - WHEN: UTC timestamp with millisecond precision
  - FROM: source IP address and User-Agent
  - OUTCOME: success / failure / partial
  - CONTEXT: relevant parameters (e.g., new value for update operations)
```

---

## I — Information Disclosure

### Definition
Sensitive information is exposed to actors who are not authorized to access it.

### Common Attack Scenarios

**Verbose Error Messages:**
- Stack traces returned to users revealing internal paths, library versions, SQL queries
- Error messages revealing whether a username exists (username enumeration)

**Insecure Data Exposure:**
- API returning all fields including password_hash, internal notes, admin flags
- Sensitive data in URL query parameters (passwords, tokens — appear in server logs)
- PII or secrets committed to public repositories

**Transport and Storage:**
- HTTP (not HTTPS) transmission of sensitive data
- Cleartext passwords in database (should be hashed)
- Unencrypted backup files containing sensitive data
- Caching sensitive responses without Cache-Control: no-store

**Side Channels:**
- Timing attacks on authentication (different response time for valid vs invalid username)
- Error message distinguishing invalid username from invalid password
- Log files containing session tokens or PII

### Mitigations

| Control | Implementation |
|---------|---------------|
| Generic error responses | Return "Internal server error" to clients; log details server-side |
| Response allowlisting | Explicitly list fields returned in API responses |
| TLS everywhere | HTTPS for all traffic; HSTS header to prevent downgrade |
| Secret scanning | Scan repos with trufflehog/gitleaks; rotate any exposed secrets |
| Cache-Control headers | `no-store` for sensitive responses; `private` for user-specific |
| Constant-time comparison | Use `hmac.compare_digest()` (Python) or `crypto.timingSafeEqual()` (Node) |
| Data minimization | Only collect, process, and return data that is necessary |
| Log redaction | Never log passwords, tokens, full card numbers, SSNs |

### Trust Boundary Information Risks
- **API → User:** Returning more data than the user is authorized to see
- **Service → Logs:** Sensitive values appearing in structured or unstructured logs
- **Database → Backup:** Unencrypted backup files accessible to unauthorized parties
- **Browser → Server:** Sensitive data in URL (visible in browser history, server logs, referrer headers)

---

## D — Denial of Service

### Common Attack Scenarios

**Resource Exhaustion:**
- Unbounded file upload (no size limit) exhausting disk space or memory
- No rate limiting on expensive endpoints (search, login, export)
- Regular expressions with catastrophic backtracking (ReDoS)
- Uncontrolled recursion or deeply nested JSON parsing

**Application-Level DoS:**
- Algorithmic complexity attacks (O(n²) or worse operations on user-controlled input)
- Slowloris (keeping many partial connections open)
- Large HTTP request bodies with no size limit
- Infinite pagination (requesting page 999999)

**Dependency DoS:**
- Dependent service unavailable causing cascading failure (no circuit breaker)
- Database connection pool exhaustion
- DNS resolution failure with no fallback

### Mitigations

| Control | Implementation |
|---------|---------------|
| Rate limiting | Apply per-IP and per-user limits on all endpoints |
| Request size limits | Set `MAX_CONTENT_LENGTH`; reject oversized bodies early |
| Timeouts | Set timeouts on all external calls, DB queries, background jobs |
| Pagination limits | Cap page size; validate page number is within reasonable range |
| Circuit breakers | Fail fast when downstream services are unavailable |
| Connection pooling | Pool DB connections; cap max pool size |
| ReDoS prevention | Use linear-time regex libraries; test patterns with `redos` tool |
| Caching | Cache expensive computations; use ETag/Last-Modified for CDN caching |
| Autoscaling + load balancing | Horizontal scaling for traffic spikes |

### Rate Limiting Patterns

**Python (Flask-Limiter):**
```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(app, key_func=get_remote_address,
                  default_limits=["200 per day", "50 per hour"])

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login(): ...
```

**Node.js (express-rate-limit):**
```javascript
const rateLimit = require('express-rate-limit');
const loginLimiter = rateLimit({ windowMs: 60 * 1000, max: 5 });
app.post('/login', loginLimiter, loginHandler);
```

---

## E — Elevation of Privilege

### Definition
An attacker gains more permissions or capabilities than they are authorized to have, either by exploiting a vulnerability or bypassing authorization controls.

### Common Attack Scenarios

**Horizontal Privilege Escalation:**
- Accessing another user's resources by modifying an ID (BOLA/IDOR)
- API endpoints that rely on user-supplied account_id without validating ownership

**Vertical Privilege Escalation:**
- Accessing admin functions without admin role
- JWT with tampered role claim (if secret is weak or algorithm is 'none')
- Mass assignment updating `is_admin = true` via API

**Privilege Inheritance:**
- SSRF reaching internal admin APIs that trust internal callers without auth
- Insecure subprocess calls executing with elevated OS privileges

**Second-Order Attacks:**
- Stored XSS in admin panel allowing script execution in admin context
- SQL injection on admin search granting unauthorized DB access

### Mitigations

| Control | Implementation |
|---------|---------------|
| Deny by default | All routes require authentication; explicitly opt out for public routes |
| RBAC | Role-based access control enforced on every operation |
| Object-level authorization | Verify ownership on every resource access, not just role |
| Least privilege | Service accounts have minimum necessary permissions |
| Privilege separation | Admin and user functions run in separate contexts |
| Input allowlisting | Never trust client-supplied role, is_admin, or permission fields |
| Audit all privilege use | Log when elevated roles are used |

### Authorization Patterns

**Python — centralized authorization check:**
```python
def require_ownership(resource, user):
    if resource.owner_id != user.id and not user.has_role('admin'):
        raise PermissionError("Access denied")

@app.route('/document/<int:doc_id>', methods=['DELETE'])
@login_required
def delete_document(doc_id):
    doc = Document.query.get_or_404(doc_id)
    require_ownership(doc, current_user)
    db.session.delete(doc)
    db.session.commit()
```

**Node.js — middleware-based authorization:**
```javascript
function requireOwnership(model) {
    return async (req, res, next) => {
        const resource = await model.findById(req.params.id);
        if (!resource || (resource.userId.toString() !== req.user.id && !req.user.isAdmin)) {
            return res.status(403).json({ error: 'Forbidden' });
        }
        req.resource = resource;
        next();
    };
}

app.delete('/post/:id', authenticate, requireOwnership(Post), async (req, res) => {
    await req.resource.deleteOne();
    res.json({ ok: true });
});
```

---

## Trust Boundary Analysis

### Boundary Types

| Boundary | Description | Key STRIDE Risks |
|----------|-------------|-----------------|
| Internet → Edge | Unauthenticated internet traffic hits public endpoint | S (user spoofing), D (DDoS), I (information exposure) |
| Edge → Application | Load balancer or API gateway to app server | T (header tampering), I (sensitive forwarded headers) |
| Application → Database | App server queries DB | T (SQL injection), I (over-fetching data), E (DB account privilege) |
| Application → External API | Outbound calls to third parties | S (API key exposure), I (data shared with third party), D (third-party unavailability) |
| Service → Service | Internal microservice communication | S (missing mTLS), T (request tampering), E (implicit trust between services) |
| Browser → Application | Client-side to server-side | S (CSRF), T (parameter tampering), I (sensitive data in URLs) |
| Admin → System | Administrative access | E (privilege escalation), R (missing audit trail), S (credential theft) |
| Runtime → OS | Application executing system calls | E (command injection granting OS access), T (file system tampering) |

### Per-Component Threat Table Template

For each component in the system, assess:

```
Component: [name]
Interactions: [what it receives from / sends to]

Spoofing threats:
  - [ ] Does the component verify the identity of its callers?
  - [ ] Are credentials stored and transmitted securely?

Tampering threats:
  - [ ] Is all input validated before processing?
  - [ ] Are all writes authorized at the object level?

Repudiation threats:
  - [ ] Are all significant actions logged with actor identity?
  - [ ] Are logs forwarded to tamper-evident storage?

Information disclosure threats:
  - [ ] Are responses limited to only what the caller is authorized to see?
  - [ ] Is sensitive data encrypted at rest and in transit?

Denial of service threats:
  - [ ] Are resource limits (size, rate, time) enforced?
  - [ ] Does the component fail gracefully under load?

Elevation of privilege threats:
  - [ ] Does the component run with minimum necessary privileges?
  - [ ] Are all privileged operations explicitly authorized?
```

---

## STRIDE ↔ OWASP Top 10 Mapping

| STRIDE Category | OWASP 2021 Categories |
|-----------------|----------------------|
| Spoofing | A07 (Identification & Authentication Failures) |
| Tampering | A03 (Injection), A08 (Software/Data Integrity Failures) |
| Repudiation | A09 (Security Logging & Monitoring Failures) |
| Information Disclosure | A02 (Cryptographic Failures), A05 (Security Misconfiguration) |
| Denial of Service | A04 (Insecure Design) |
| Elevation of Privilege | A01 (Broken Access Control), A04 (Insecure Design) |

---

## STRIDE ↔ CWE Mapping

| STRIDE | Key CWEs |
|--------|----------|
| Spoofing | CWE-287 (Improper Authentication), CWE-384 (Session Fixation), CWE-798 (Hard-coded Credentials) |
| Tampering | CWE-89 (SQL Injection), CWE-78 (OS Command Injection), CWE-502 (Insecure Deserialization) |
| Repudiation | CWE-778 (Insufficient Logging), CWE-532 (Sensitive Info in Log) |
| Information Disclosure | CWE-200 (Info Exposure), CWE-209 (Error Message Info Exposure), CWE-319 (Cleartext Transmission) |
| Denial of Service | CWE-770 (Resource Allocation Without Limits), CWE-400 (Uncontrolled Resource Consumption) |
| Elevation of Privilege | CWE-284 (Improper Access Control), CWE-862 (Missing Authorization), CWE-639 (BOLA) |
