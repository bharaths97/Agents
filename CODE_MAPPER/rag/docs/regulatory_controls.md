# Regulatory Security Controls Reference

Technical security controls required by major compliance frameworks. Used by agents to assess regulatory context, map findings to compliance requirements, escalate severity for regulated domains, and generate compliance-aware remediation guidance.

---

## HIPAA — Health Insurance Portability and Accountability Act

### Applicability
Applies to: **Covered Entities** (healthcare providers, health plans, healthcare clearinghouses) and their **Business Associates** (vendors, contractors, SaaS providers that process PHI on behalf of covered entities).

**Protected Health Information (PHI):** Any individually identifiable health information — including names, dates, geographic data, phone numbers, emails, SSNs, medical record numbers, account numbers, diagnoses, treatment information, payment information — in any medium (electronic, paper, oral).

---

### HIPAA Security Rule — Technical Safeguards (45 CFR § 164.312)

#### Access Control (§ 164.312(a))
- **Unique user identification (Required):** Assign unique identifiers to each user; no shared accounts
- **Emergency access procedure (Required):** Documented procedure for accessing ePHI during emergencies
- **Automatic logoff (Addressable):** Terminate sessions after period of inactivity
- **Encryption and decryption (Addressable):** Encrypt ePHI at rest and in transit

**Technical implementation:**
```
✅ Unique user accounts for every staff member — no shared credentials
✅ Role-based access control (RBAC) — users access only PHI needed for their role
✅ Session timeout after 15 minutes of inactivity (NIST recommendation)
✅ AES-256 encryption for ePHI at rest
✅ TLS 1.2+ for ePHI in transit
✅ Audit logs linked to individual user IDs
```

#### Audit Controls (§ 164.312(b))
- **Required:** Hardware, software, and procedural mechanisms to record and examine activity in systems that contain ePHI

**What must be logged:**
```
- All logins and logouts (success and failure)
- All access to ePHI records (who viewed/modified which record, when)
- All administrative actions (account creation/deletion, permission changes)
- All failed access attempts
- System startup and shutdown
```

**Minimum log retention:** 6 years (HIPAA minimum); many states require longer.

#### Integrity Controls (§ 164.312(c))
- **Addressable:** Implement security measures to ensure ePHI is not improperly altered or destroyed
- **Electronic mechanisms:** Checksums, digital signatures, or hashing to verify integrity

#### Transmission Security (§ 164.312(e))
- **Addressable — Encryption:** Encrypt ePHI in transit
- **Required:** Guard against unauthorized access to ePHI during transmission

**Implementation:**
```
✅ TLS 1.2+ for all ePHI transmission
✅ Reject connections over TLS 1.0/1.1
✅ Encrypt email containing ePHI (S/MIME or equivalent)
✅ VPN for remote access to systems containing ePHI
```

---

### HIPAA Risk Assessment Requirements (§ 164.308(a)(1))

Organizations must conduct a **risk analysis** covering:
1. Identify where ePHI is stored, received, maintained, transmitted
2. Identify reasonably anticipated threats to ePHI
3. Identify reasonably anticipated vulnerabilities
4. Assess current security measures
5. Determine likelihood and impact of threat occurrence
6. Assign risk level to each identified threat/vulnerability
7. Document risk analysis and implement mitigation

---

### Common HIPAA Technical Violations

| Violation | Example | Severity |
|-----------|---------|----------|
| Unencrypted ePHI at rest | Patient records in plaintext SQLite DB | CRITICAL |
| Unencrypted ePHI in transit | Sending patient data over HTTP | CRITICAL |
| Missing access controls | Any authenticated user can view any patient record | CRITICAL |
| Shared accounts | Multiple staff sharing one login | HIGH |
| Missing audit logging | No log of who accessed which patient record | HIGH |
| Hardcoded credentials | DB password in source code | HIGH |
| No session timeout | Session never expires | MEDIUM |
| Excessive data collection | Storing PHI that is not needed for the function | MEDIUM |

---

### HIPAA Minimum Necessary Standard

Only access, use, and disclose the minimum PHI necessary to accomplish the intended purpose.

**API design implication:** Return only PHI fields required for the specific use case. Do not return full patient records when only a name and appointment date are needed.

---

## PCI-DSS — Payment Card Industry Data Security Standard

### Applicability
Any organization that **stores, processes, or transmits** cardholder data (primary account number / PAN, cardholder name, expiration date, service code, CVV, PIN).

**Current version:** PCI DSS v4.0 (effective March 2024)

**Cardholder Data (CHD) vs Sensitive Authentication Data (SAD):**
- CHD (may store with protection): PAN, cardholder name, expiration date, service code
- SAD (NEVER store after authorization): Full magnetic stripe, CVV/CVC, PIN/PIN block

---

### PCI-DSS Requirements Summary (Technical Focus)

#### Requirement 1–2: Network Security
```
✅ Install and maintain network security controls (firewalls/NSGs)
✅ Apply secure configurations to all system components
✅ No vendor-supplied default passwords or security settings
✅ Segment cardholder data environment (CDE) from other networks
```

#### Requirement 3: Protect Stored Account Data
```
✅ NEVER store SAD after authorization (CVV, full mag stripe, PIN)
✅ Minimize PAN storage — store only what is needed
✅ Mask PAN when displayed — show only first 6 / last 4 digits
✅ Render PAN unreadable anywhere it is stored:
   - Strong one-way hashes (SHA-256 with key) of PAN
   - Truncation
   - Index tokens with secured token pads
   - Strong cryptography (AES-256)
✅ Cryptographic key management procedures documented
```

**Code implications:**
```python
# NEVER do this:
log.info(f"Processing card: {card_number}")    # PAN in logs — PCI violation

# NEVER store:
session['cvv'] = request.form['cvv']           # SAD storage — PCI violation
db.save(cvv=request.form['cvv'])               # SAD storage — PCI violation

# Safe — masked PAN in response:
def mask_pan(pan: str) -> str:
    if len(pan) < 10:
        return '*' * len(pan)
    return pan[:6] + '*' * (len(pan) - 10) + pan[-4:]

# Safe — never log PAN:
log.info("Payment processed for card ending %s", pan[-4:])
```

#### Requirement 4: Protect Cardholder Data in Transit
```
✅ Use strong cryptography and security protocols (TLS 1.2+) for transmitting CHD
✅ Never send unprotected PAN by end-user messaging (email, chat, SMS)
✅ Disable weak protocols (SSL, TLS 1.0, TLS 1.1, early TLS)
```

#### Requirement 6: Develop and Maintain Secure Systems
```
✅ Security patch management — critical patches within one month
✅ Secure development lifecycle (SSDLC)
✅ Code review or automated scanning for vulnerabilities
✅ Protection against OWASP Top 10 web vulnerabilities
✅ Separate development and production environments
✅ No live PAN in non-production environments
```

**Development controls:**
```
✅ Input validation on all user input
✅ Parameterized queries for all database access
✅ Authentication required for all access to cardholder data
✅ HTTPS enforced for all pages
✅ No custom authentication — use vetted, tested mechanisms
✅ Code reviewed for injection flaws, XSS, broken auth before deployment
```

#### Requirement 7–8: Restrict Access
```
✅ Restrict access to cardholder data by business need-to-know
✅ Identify and authenticate all users with unique IDs
✅ Strong password requirements: ≥ 12 characters, complexity, 90-day rotation
✅ MFA required for remote network access to CDE
✅ MFA required for all non-console admin access
✅ Disable accounts after 90 days of inactivity
✅ Account lockout after maximum 10 failed attempts; lockout duration ≥ 30 min
```

#### Requirement 10: Log and Monitor
```
✅ Implement audit logs for all access to network resources and CHD
✅ Capture: user, event type, date/time, success/failure, origin, affected component
✅ Synchronize all clocks (NTP)
✅ Protect audit logs from modification
✅ Retain audit logs for at least 12 months (3 months immediately available)
✅ Review logs and security events daily
```

#### Requirement 11: Test Security
```
✅ Quarterly internal and external vulnerability scans (ASV for external)
✅ Annual (or after significant change) penetration testing
✅ Intrusion detection/prevention systems on CDE perimeter and internal networks
✅ File integrity monitoring (FIM) on critical files
```

---

### Common PCI-DSS Violations

| Violation | Example | Requirement |
|-----------|---------|-------------|
| SAD storage | Storing CVV in database | Req 3 |
| PAN in logs | Logging full card number | Req 3 |
| Unencrypted PAN at rest | Plaintext card number in DB | Req 3 |
| HTTP transmission | Sending card data over HTTP | Req 4 |
| Shared accounts | Multiple users sharing one login | Req 8 |
| Missing MFA for remote access | Admin SSH without MFA | Req 8 |
| No vulnerability scanning | No regular security scans | Req 11 |
| SQL injection | Unparameterized query touching CHD | Req 6 |

---

## SOC 2 — Service Organization Control 2

### Applicability
US standard for service organizations (SaaS, cloud providers, data processors). Voluntary but increasingly required by enterprise customers.

### Trust Service Criteria (TSC)

#### Security (CC — Common Criteria) — Required for all SOC 2 reports

**Access Controls:**
```
✅ Logical access controls — role-based, least privilege
✅ MFA for all administrative access
✅ Periodic access reviews (quarterly recommended)
✅ Deprovisioning within 24 hours of employee termination
```

**System Operations:**
```
✅ Vulnerability management — scan and remediate on defined SLA
✅ Patch management — critical patches within 30 days
✅ Security incident management — defined process with RTO/RPO
✅ Change management — all changes reviewed and approved
```

**Monitoring:**
```
✅ Continuous security monitoring
✅ Log retention ≥ 12 months
✅ Alerting on anomalous events
✅ Annual penetration testing
```

#### Availability
```
✅ SLA commitments documented
✅ Redundancy and failover
✅ Disaster recovery testing
✅ Capacity planning
```

#### Confidentiality
```
✅ Encrypt confidential data at rest (AES-256) and in transit (TLS 1.2+)
✅ Data classification and handling procedures
✅ NDA / DPA agreements with sub-processors
✅ Data retention and disposal procedures
```

#### Privacy
```
✅ Privacy notice and consent
✅ Data subject rights (access, correction, deletion)
✅ Data minimization — collect only what is needed
✅ Cross-border transfer controls (SCCs for EU data)
```

---

## GDPR — General Data Protection Regulation (EU)

### Applicability
Any organization processing **personal data** of EU/EEA residents, regardless of where the organization is located.

**Personal data:** Any information relating to an identified or identifiable natural person (name, email, IP address, cookie ID, location data, health data, etc.).

### Key Technical Requirements

#### Article 25 — Data Protection by Design and by Default
```
✅ Build privacy controls into systems from the start
✅ Default to most privacy-preserving settings
✅ Collect only minimum necessary personal data (data minimization)
✅ Pseudonymize data where possible
```

#### Article 32 — Security of Processing
Implement "appropriate technical and organizational measures" including as appropriate:
```
✅ Pseudonymization and encryption of personal data
✅ Ability to ensure ongoing confidentiality, integrity, availability of processing systems
✅ Ability to restore data in timely manner after incident
✅ Regular testing and evaluation of security measures
```

Specific technical controls:
```
✅ Encryption at rest (AES-256 minimum for sensitive categories)
✅ Encryption in transit (TLS 1.2+)
✅ Access controls and authentication (MFA for sensitive data)
✅ Audit logging of personal data access
✅ Vulnerability management and patching
✅ Breach detection and response capability
```

#### Article 33–34 — Breach Notification
```
✅ Notify supervisory authority within 72 hours of discovering breach
✅ Notify affected individuals without undue delay if high risk to their rights
✅ Document all breaches (even those not meeting notification threshold)
```

#### Data Subject Rights (Articles 15–22)
Technical systems must support:
```
✅ Right of access — export all personal data for a given individual
✅ Right to rectification — ability to correct inaccurate data
✅ Right to erasure ("right to be forgotten") — delete individual's data on request
✅ Right to data portability — export data in machine-readable format
✅ Right to restrict processing — flag records for restricted use
```

**Code implication:** Applications storing personal data must implement data export and deletion capabilities, including cascading deletes across all tables/services storing that user's data.

---

## Regulatory Severity Amplification for Agents

When a domain is identified as regulated, severity of findings should be amplified:

| Finding Type | Standard Domain | HIPAA Domain | PCI-DSS Domain | GDPR Domain |
|---|---|---|---|---|
| Unencrypted sensitive data at rest | HIGH | CRITICAL | CRITICAL | CRITICAL |
| SQL injection touching regulated data | HIGH | CRITICAL | CRITICAL | HIGH |
| Missing access control on regulated data | HIGH | CRITICAL | CRITICAL | HIGH |
| Sensitive data in logs | MEDIUM | HIGH | HIGH | HIGH |
| Hardcoded credentials | HIGH | CRITICAL | CRITICAL | HIGH |
| Missing audit logging | MEDIUM | HIGH | HIGH | MEDIUM |
| Session fixation / weak auth | HIGH | CRITICAL | HIGH | HIGH |
| PAN stored in cleartext | N/A | N/A | CRITICAL | N/A |
| CVV/SAD stored after auth | N/A | N/A | CRITICAL | N/A |

---

## Cross-Framework Control Mapping

| Control | HIPAA | PCI-DSS | SOC 2 | GDPR |
|---------|-------|---------|-------|------|
| Encryption at rest | Addressable (§164.312(a)) | Req 3 | CC6.1 | Art 32 |
| Encryption in transit | Addressable (§164.312(e)) | Req 4 | CC6.7 | Art 32 |
| Access control / RBAC | Required (§164.312(a)) | Req 7 | CC6.1 | Art 25, 32 |
| Unique user IDs / no sharing | Required (§164.312(a)) | Req 8 | CC6.2 | Art 32 |
| MFA | Addressable | Req 8 | CC6.1 | Art 32 |
| Audit logging | Required (§164.312(b)) | Req 10 | CC7.2 | Art 32 |
| Vulnerability management | Required (§164.308(a)(1)) | Req 11 | CC7.1 | Art 32 |
| Breach notification | Required (§164.408) | Req 12 | CC7.3 | Art 33–34 |
| Data minimization | Minimum Necessary | Req 3 | P3.2 | Art 5, 25 |
| Log retention | 6 years | 12 months | 12 months | Per purpose |
