# Lab 2 Submission - Threat Modeling with Threagile

**Author:** Ahmed Baha Eddine Alimi 
**Branch:** `feature/lab2`

---

## Task 1: Threagile Baseline Model (6 pts)

### 1.1 Generate Baseline Threat Model

Successfully generated baseline threat model for OWASP Juice Shop v19.0.0 using Threagile.

**Command executed:**
```bash
docker run --rm -v "${PWD}:/app/work" threagile/threagile -model /app/work/labs/lab2/threagile-model.yaml -output /app/work/labs/lab2/baseline -generate-risks-excel=false -generate-tags-excel=false
```

**Architecture Modeled:**
- **User Browser** (external entity) - End-user web client accessing the application
- **Reverse Proxy** (optional) - Nginx for TLS termination and security headers
- **Juice Shop Application** (web-server) - Node.js/Express v19.0.0 in Docker container
- **Persistent Storage** (datastore) - Host-mounted volume for SQLite database, uploads, and logs
- **Webhook Endpoint** (external entity) - Optional third-party integration for challenge notifications

**Trust Boundaries:**
- **Internet** (untrusted) - Contains User Browser and Webhook Endpoint
- **Host** (local machine) - Contains Reverse Proxy and Persistent Storage
- **Container Network** (isolated) - Contains Juice Shop Application

**Data Assets:**
- User Accounts (confidential) - Credentials, profile data
- Orders (confidential) - Transaction history, addresses
- Product Catalog (public) - Product information
- Tokens & Sessions (confidential) - JWTs, session identifiers
- Logs (internal) - Application and access logs

### 1.2 Verify Generated Outputs

All expected files generated successfully in `labs/lab2/baseline/`:

✅ `report.pdf` - Complete threat analysis report (80+ pages)  
✅ `risks.json` - Machine-readable risk catalog  
✅ `stats.json` - Risk statistics and metrics  
✅ `technical-assets.json` - Technical asset inventory  
✅ `data-flow-diagram.png` - Visual data flow representation  
✅ `data-asset-diagram.png` - Data asset relationships  

**Total Risks Identified:** 23 risks across 15 categories

**Risk Distribution:**
- Elevated severity: 4 risks (17%)
- Medium severity: 14 risks (61%)
- Low severity: 5 risks (22%)

### 1.3 Risk Analysis and Documentation
<img src="lab2/baseline/data-flow-diagram.png" alt="Baseline Data Flow" width="600" height="600">
<img src="lab2/secure/data-flow-diagram.png" alt="Secure Data Flow" width="600" height="600">

#### Risk Ranking Methodology

**Composite Score Formula:**
```
Composite Score = (Severity × 100) + (Likelihood × 10) + Impact
```

**Scoring Weights:**

| Factor | Weight | Values |
|--------|--------|--------|
| **Severity** | ×100 | critical=5, elevated=4, high=3, medium=2, low=1 |
| **Likelihood** | ×10 | very-likely=4, likely=3, possible=2, unlikely=1 |
| **Impact** | ×1 | high=3, medium=2, low=1 |

**Rationale:**
- **Severity** weighted highest (×100) as it represents inherent vulnerability criticality and exploitability
- **Likelihood** weighted moderately (×10) to prioritize realistic attack scenarios over theoretical risks
- **Impact** serves as tiebreaker for risks with similar severity/likelihood combinations
- Score range: 111 (low/unlikely/low) to 543 (critical/very-likely/high)

**Example Calculations:**
- Elevated (4) + Likely (3) + High (3) = **433**
- Elevated (4) + Likely (3) + Medium (2) = **432**
- Medium (2) + Very-Likely (4) + Low (1) = **241**

#### Top 5 Risks by Composite Score

| Rank | Risk Title | Severity | Category | Asset | Likelihood | Impact | Score |
|------|-----------|----------|----------|-------|------------|--------|-------|
| 1 | Unencrypted Communication named Direct to App (no proxy) between User Browser and Juice Shop Application transferring authentication data | elevated | unencrypted-communication | user-browser | likely | high | 433 |
| 2 | Cross-Site Scripting (XSS) risk at Juice Shop Application | elevated | cross-site-scripting | juice-shop | likely | medium | 432 |
| 3 | Unencrypted Communication named To App between Reverse Proxy and Juice Shop Application | elevated | unencrypted-communication | reverse-proxy | likely | medium | 432 |
| 4 | Missing Authentication covering communication link To App from Reverse Proxy to Juice Shop Application | elevated | missing-authentication | juice-shop | likely | medium | 432 |
| 5 | Cross-Site Request Forgery (CSRF) risk at Juice Shop Application via Direct to App (no proxy) from User Browser | medium | cross-site-request-forgery | juice-shop | very-likely | low | 241 |

#### Critical Security Concerns Analysis

**Risk #1: Unencrypted Communication - Direct Browser to App (Score: 433)**

- **Threat:** Man-in-the-middle (MITM) attacks on authentication data and session tokens transmitted in cleartext
- **Vulnerability:** HTTP protocol used for direct browser access on port 3000, exposing credentials, session tokens, and PII
- **Impact:** Passive network monitoring can capture all authentication data; active MITM can modify requests/responses in real-time
- **Attack Scenario:** Attacker on same network (public WiFi, compromised router) uses Wireshark to capture HTTP traffic, extracting credentials during login or hijacking active sessions by stealing session tokens
- **Why Critical:** Authentication data over unencrypted channels enables trivial credential theft without sophisticated attacks. Any network observer can compromise accounts.

**Risk #2: Cross-Site Scripting (XSS) at Juice Shop Application (Score: 432)**

- **Threat:** Attackers inject malicious JavaScript that executes in victim browsers
- **Vulnerability:** Insufficient input validation and output encoding in Node.js application
- **Impact:** Session hijacking, credential theft, defacement, malicious redirects, arbitrary actions on behalf of users
- **Attack Scenario:** Attacker submits `<script>` tags through product review form. When users view product details, script executes, stealing session cookies via `document.cookie` and sending to attacker-controlled server
- **Why Critical:** XSS bypasses client-side security controls and can compromise all users who interact with poisoned content

**Risk #3: Unencrypted Communication - Proxy to App (Score: 432)**

- **Threat:** Internal network traffic interception within host environment
- **Vulnerability:** HTTPS terminated at proxy, then downgraded to HTTP between proxy and application
- **Impact:** Exposes sensitive data within host network boundary, enabling lateral movement attacks
- **Attack Scenario:** Container escape or host compromise allows attacker to use `tcpdump` to sniff cleartext traffic between proxy and application
- **Why Critical:** Creates weak link in security chain. HTTPS protection at edge completely negated by cleartext internal transmission

**Risk #4: Missing Authentication - Proxy to App (Score: 432)**

- **Threat:** Direct backend access bypassing all security controls if internal network compromised
- **Vulnerability:** No authentication required for proxy→application communication
- **Impact:** Attacker with internal network access can bypass proxy-level security controls (rate limiting, WAF, authentication)
- **Attack Scenario:** Container escape allows direct HTTP requests to application port, circumventing all reverse proxy protections
- **Why Critical:** Relies solely on network perimeter defense, violating zero-trust principles

**Risk #5: Cross-Site Request Forgery (CSRF) (Score: 241)**

- **Threat:** Attackers trick authenticated users into performing unwanted actions
- **Vulnerability:** Missing or inadequate CSRF tokens on state-changing operations
- **Impact:** Unauthorized actions using victim's session (password changes, orders, profile modifications)
- **Attack Scenario:** Malicious website with hidden form submits POST request to Juice Shop. Browser automatically includes session cookies, executing password change without user knowledge
- **Why Critical:** Despite medium severity, rated "very-likely" due to ease of exploitation. Defending requires proper CSRF token implementation

#### Key Security Findings

**Primary Attack Vectors:**
1. Unencrypted communication paths (HTTP) exposing credentials and sensitive data
2. Missing authentication on internal services (trust based on network location)
3. Application-layer vulnerabilities (XSS, CSRF, SSRF) from insufficient input validation
4. No encryption at rest for sensitive database and log files
5. Optional security controls allow bypassing protections entirely

**Architecture Vulnerabilities:**
- **Dual access paths:** Direct HTTP (port 3000) bypasses ALL reverse proxy security, creating inconsistent security posture
- **HTTP downgrade pattern:** HTTPS at edge terminated at proxy, downgraded to HTTP internally (common anti-pattern)
- **Single-layer defense:** Network isolation is primary control; network compromise exposes everything
- **Unencrypted storage:** Database, logs, uploads contain sensitive data without encryption

**Risk Category Summary:**

| Category | Count |
|----------|-------|
| missing-authentication-second-factor | 2 |
| cross-site-request-forgery | 2 |
| missing-hardening | 2 |
| unencrypted-asset | 2 |
| unencrypted-communication | 2 |
| unnecessary-data-transfer | 2 |
| server-side-request-forgery | 2 |
| unnecessary-technical-asset | 2 |
| cross-site-scripting | 1 |
| missing-build-infrastructure | 1 |
| missing-vault | 1 |
| container-baseimage-backdooring | 1 |
| missing-waf | 1 |
| missing-authentication | 1 |
| missing-identity-store | 1 |

#### Generated Diagrams Analysis

**Data Flow Diagram Observations:**

- Three trust boundaries clearly visualized: Internet → Host → Container Network
- HTTP connections shown between User Browser→Juice Shop (direct path) and Reverse Proxy→Juice Shop (internal path)
- HTTPS connection only between User Browser→Reverse Proxy
- Multiple access paths to application visible (direct vs proxy), highlighting architectural inconsistency
- Database access contained within Container Network boundary but lacks encryption indicator
- Outbound webhook crosses trust boundary from container to external internet

**Data Asset Diagram Observations:**

- User credentials and session tokens flow through multiple components
- Persistent Storage contains ALL sensitive data assets (credentials, orders, logs, product catalog)
- Product Catalog has lowest confidentiality (public) but integrity remains important
- No encryption indicators on storage assets
- Clear data lineage: user input → application processing → persistent storage
- Technical assets color-coded: Juice Shop (orange), Persistent Storage (orange), Reverse Proxy (orange)

**Trust Boundary Insights:**

- Container Network provides process isolation but insufficient for sensitive data protection
- Host boundary shared by reverse-proxy and persistent-storage creates lateral movement surface
- Internet boundary properly identified but inconsistently protected (HTTP bypass available)

---

## Task 2: HTTPS Variant & Risk Comparison (4 pts)

### 2.1 Create Secure Model Variant

Created `labs/lab2/threagile-model.secure.yaml` with the following specific changes:

#### Change 1: Enable HTTPS for Direct Browser Access

**Location:** `User Browser` → `communication_links` → `Direct to App (no proxy)`

**Modification:**
```yaml
# BEFORE:
protocol: http

# AFTER:
protocol: https
```

**Rationale:** Eliminates cleartext transmission of authentication data over the direct access path. Provides confidentiality through TLS encryption and integrity through HMAC, preventing passive network monitoring and active man-in-the-middle attacks.

**Security Impact:** Directly mitigates the #1 highest-priority risk (score 433). Ensures consistent security posture regardless of which access path users choose.

#### Change 2: Enable HTTPS Between Reverse Proxy and Application

**Location:** `Reverse Proxy` → `communication_links` → `To App`

**Modification:**
```yaml
# BEFORE:
protocol: http

# AFTER:
protocol: https
```

**Rationale:** Eliminates HTTP downgrade between proxy and application. Provides end-to-end encryption from client through proxy to application backend, protecting against internal network eavesdropping and lateral movement scenarios.

**Security Impact:** Directly mitigates risk #3 (score 432). Implements defense-in-depth by not trusting the internal network. Protects against container escape and host network compromise.

#### Change 3: Enable Database Encryption at Rest

**Location:** `Persistent Storage` → `technical_assets`

**Modification:**
```yaml
# BEFORE:
encryption: none

# AFTER:
encryption: transparent
```

**Rationale:** Protects sensitive data (SQLite database, logs, uploaded files) if storage volume is compromised or accessed offline. Transparent encryption operates at filesystem/volume level with no application code changes required.

**Security Impact:** Mitigates unencrypted-asset risks. Protects against volume snapshot theft, physical storage access, backup compromise, and forensic data extraction scenarios.

### 2.2 Generate Secure Variant Analysis

**Command executed:**
```bash
docker run --rm -v "${PWD}:/app/work" threagile/threagile -model /app/work/labs/lab2/threagile-model.secure.yaml -output /app/work/labs/lab2/secure -generate-risks-excel=false -generate-tags-excel=false

```

**Results:**
- Generated complete secure variant report in `labs/lab2/secure/`
- All artifacts successfully created (report.pdf, risks.json, diagrams)
- **Total Risks: 20** (down from 23 baseline)

### 2.3 Generate Risk Comparison

**Primary Analysis Method - jq Command (as required by lab):**

Executed the provided jq command for standardized risk comparison:

```bash
jq -n \
  --slurpfile b labs/lab2/baseline/risks.json \
  --slurpfile s labs/lab2/secure/risks.json '
def tally(x):
(x | group_by(.category) | map({ (.[0].category): length }) | add) // {};
(tally($b[0])) as $B |
(tally($s[0])) as $S |
(($B + $S) | keys | sort) as $cats |
[
"| Category | Baseline | Secure | Δ |",
"|---|---:|---:|---:|"
] + (
$cats | map(
"| " + . + " | " +
(($B[.] // 0) | tostring) + " | " +
(($S[.] // 0) | tostring) + " | " +
(((($S[.] // 0) - ($B[.] // 0))) | tostring) + " |"
)
) | .[]' | sed 's/"//g' > labs/lab2/jq-comparison.txt
```

**How this works:**
1. `--slurpfile` loads both JSON files into variables `$b` and `$s`
2. `tally()` function groups risks by category and counts occurrences
3. Calculates deltas: `$S[category] - $B[category]`
4. Generates formatted Markdown table with Category | Baseline | Secure | Δ columns
5. Output saved to `labs/lab2/jq-comparison.txt`

**Additional Analysis - PowerShell Scripts:**

Also developed PowerShell scripts for detailed risk analysis:

```powershell
# Composite risk scoring with severity/likelihood/impact weights
powershell -ExecutionPolicy Bypass -File labs/lab2/analyze-risks.ps1

# Automated baseline vs secure comparison with summary statistics
powershell -ExecutionPolicy Bypass -File labs/lab2/compare-risks.ps1
```

**Scripts provide:**
- `analyze-risks.ps1` - Calculates composite scores, ranks risks, generates detailed analysis
- `compare-risks.ps1` - Produces risk category deltas with percentage changes and formatted output
- Results saved to: `baseline-analysis.txt`, `secure-analysis.txt`, `comparison.txt`

**Verification:** Both jq and PowerShell methods produced identical results (23→20 risks, -13% reduction), confirming analysis accuracy.

#### Risk Category Delta Table

| Category | Baseline | Secure | Δ |
|----------|----------|--------|-------|
| container-baseimage-backdooring | 1 | 1 | 0 |
| cross-site-request-forgery | 2 | 2 | 0 |
| cross-site-scripting | 1 | 1 | 0 |
| missing-authentication | 1 | 1 | 0 |
| missing-authentication-second-factor | 2 | 2 | 0 |
| missing-build-infrastructure | 1 | 1 | 0 |
| missing-hardening | 2 | 2 | 0 |
| missing-identity-store | 1 | 1 | 0 |
| missing-vault | 1 | 1 | 0 |
| missing-waf | 1 | 1 | 0 |
| server-side-request-forgery | 2 | 2 | 0 |
| unencrypted-asset | 2 | 1 | -1 |
| unencrypted-communication | 2 | 0 | -2 |
| unnecessary-data-transfer | 2 | 2 | 0 |
| unnecessary-technical-asset | 2 | 2 | 0 |

**Summary:**
- **Total Baseline:** 23 risks
- **Total Secure:** 20 risks  
- **Delta:** -3 risks (-13.0% reduction)

### 2.4 Delta Analysis

#### Overall Impact

The three security changes resulted in:
- **3 risks eliminated** (13% reduction)
- **1 risk category fully eliminated:** unencrypted-communication (2 → 0)
- **1 risk category partially reduced:** unencrypted-asset (2 → 1)
- **13 risk categories unchanged** (require application-level or infrastructure changes)

#### Risks Eliminated

**1. Unencrypted Communication - Direct to App** ✅ **ELIMINATED**

- **Before:** HTTP protocol exposed credentials and session tokens to network eavesdropping (score: 433)
- **After:** HTTPS with TLS 1.2+ provides encryption, preventing cleartext data transmission
- **Technical Mitigation:**
  - AES-256 symmetric encryption for confidentiality
  - HMAC for message integrity
  - Certificate validation prevents MITM attacks
  - Perfect Forward Secrecy protects past sessions

**2. Unencrypted Communication - Proxy to App** ✅ **ELIMINATED**

- **Before:** Internal HTTP created vulnerability within host network (score: 432)
- **After:** End-to-end HTTPS eliminates cleartext internal traffic
- **Technical Mitigation:**
  - Could implement mTLS (mutual TLS) for additional authentication
  - Protects against lateral movement in compromised networks
  - Maintains encryption even if network perimeter breached

**3. Unencrypted Asset - Persistent Storage** ✅ **PARTIALLY MITIGATED**

- **Before:** Database files, logs, and uploads stored in cleartext (2 risks)
- **After:** Transparent storage encryption protects data at rest (1 risk remains)
- **Technical Mitigation:**
  - Filesystem-level encryption with separate key management
  - Data encrypted before writing to disk
  - No application code changes required
  - Protects against offline attacks (stolen drives, snapshots)

#### Why These Changes Were Effective

**HTTPS Implementation:**

- **Confidentiality:** TLS provides strong encryption (AES-256-GCM)
- **Integrity:** HMAC prevents data tampering in transit
- **Authentication:** X.509 certificate validation ensures connection to legitimate server
- **Forward Secrecy:** DHE/ECDHE key exchange protects past sessions if long-term keys compromised
- **Complete Category Elimination:** Both unencrypted-communication risks (100%) removed

**Transparent Storage Encryption:**

- **Automatic Protection:** All disk writes encrypted without application awareness
- **Key Separation:** Encryption keys managed separately from encrypted data
- **Compliance:** Meets data protection regulations (GDPR, HIPAA, PCI-DSS)
- **Defense in Depth:** Protects against physical access, backup theft, snapshot compromise
- **Partial Category Mitigation:** Reduced unencrypted-asset from 2 to 1 (50%)

#### Risks That Remained Unchanged (20 total)

**Application Logic Vulnerabilities (3 risks - require code changes):**

- Cross-Site Scripting (XSS) - Now #1 risk in secure variant (score: 432)
- Cross-Site Request Forgery (CSRF) - 2 instances
- Server-Side Request Forgery (SSRF) - 2 instances

**Why Unchanged:** Encryption doesn't fix input validation, output encoding, or token validation issues

**Required Mitigation:**
- Implement Content Security Policy (CSP) headers
- Add CSRF tokens to all state-changing operations
- Validate and sanitize all server-side requests
- Use framework-provided XSS/CSRF protections

**Authentication/Authorization Gaps (4 risks - require architectural changes):**

- Missing Authentication (proxy to app) - Still elevated severity (score: 432)
- Missing Authentication Second Factor - 2 instances
- Missing Identity Store integration
- Missing Vault for secrets management

**Why Unchanged:** Transport encryption doesn't add authentication layers

**Required Mitigation:**
- Implement mTLS for service-to-service authentication
- Deploy MFA (TOTP/WebAuthn)
- Integrate OAuth2/OIDC identity provider
- Deploy HashiCorp Vault or AWS Secrets Manager

**Infrastructure Hardening (6 risks - require additional tooling):**

- Missing WAF, Missing Build Infrastructure security, Missing Hardening (2), Container Baseimage Backdooring, Unnecessary assets/transfers

**Why Unchanged:** Require security tooling and process improvements beyond encryption

**Required Mitigation:**
- Deploy ModSecurity WAF with OWASP Core Rule Set
- Implement secure CI/CD pipeline
- Harden OS and containers (CIS benchmarks)
- Use minimal base images, vulnerability scanning

#### Diagram Comparison

**Baseline Data Flow Diagram:**
- HTTP connections (insecure) visible:
  - User Browser → Juice Shop (direct): **http**
  - Reverse Proxy → Juice Shop (internal): **http**
- HTTPS only between User Browser → Reverse Proxy
- Clear visual indication of security gaps (mixed protocols)

**Secure Data Flow Diagram:**
- All connections show **https**:
  - User Browser → Juice Shop (direct): **https** ✅
  - Reverse Proxy → Juice Shop (internal): **https** ✅
  - User Browser → Reverse Proxy: **https** ✅
- Consistent security posture across all trust boundary crossings
- No cleartext communication paths remain

**Data Asset Diagram Changes:**
- Baseline: Persistent Storage without encryption indicator
- Secure: Persistent Storage with encryption protection (transparent)
- Note: Minimal visual changes as diagram focuses on data relationships, not transport security

---

## Conclusion

### Key Findings

1. **Baseline Security Posture:**
   - 23 risks identified across 15 distinct categories
   - Primary concerns: unencrypted communications (#1 and #3 risks) and application vulnerabilities
   - Architecture allows complete bypass of security controls via direct HTTP access
   - 4 elevated-severity risks requiring immediate attention

2. **Impact of Security Controls:**
   - HTTPS and database encryption eliminated 3 risks (13% reduction)
   - Fully eliminated unencrypted-communication category (critical security improvement)
   - Simple configuration changes (no code modifications) yielded measurable improvement
   - Demonstrates high ROI for implementing fundamental security controls

3. **Remaining Security Gaps:**
   - 20 risks persist (87% of original findings)
   - Application logic vulnerabilities (XSS, CSRF, SSRF) now represent primary attack surface
   - Authentication/authorization gaps require architectural changes
   - Infrastructure hardening needs additional security tooling

4. **Threat Modeling Value:**
   - Automated analysis identified risks that could be missed in manual review
   - Clear risk scoring enabled data-driven prioritization
   - Visual diagrams made architecture vulnerabilities immediately obvious
   - Code-based models support continuous security assessment in CI/CD

### Lessons Learned

1. **Encryption is Foundational but Not Sufficient:**
   - Transport (HTTPS) and storage encryption are baseline requirements, not optional
   - Must be applied consistently with no fallback to insecure protocols
   - However, encryption alone doesn't address application logic vulnerabilities
   - Defense-in-depth requires multiple complementary security controls

2. **Architecture Creates or Destroys Security:**
   - Optional security paths create confusion and exploit opportunities
   - Inconsistent security posture is worse than consistently lower security
   - Internal networks should not be implicitly trusted (zero-trust principles)
   - Security controls should be mandatory and enforced, not bypassable

3. **Automation Enables Continuous Security:**
   - Manual threat modeling doesn't scale with architecture changes
   - Automated tools like Threagile integrate naturally into CI/CD
   - Code-based models enable version control and team collaboration
   - Continuous threat modeling catches security regressions before deployment

4. **Prioritization is Essential:**
   - Not all risks are equally important - composite scoring focuses resources
   - Addressing 3 high-impact risks provided meaningful security improvement
   - Complete risk elimination is unrealistic - focus on highest severity/likelihood
   - Residual risk acceptance is necessary for practical security management

### Recommendations

**Immediate Actions:**
1. ✅ Implement HTTPS for all deployments (completed)
2. ✅ Enable database encryption at rest (completed)
3. Remove HTTP direct access path - force all traffic through HTTPS reverse proxy
4. Deploy TLS certificates with automated renewal (Let's Encrypt)

**Short-term Actions (1-3 months):**
1. Deploy Web Application Firewall (ModSecurity with OWASP CRS)
2. Implement rate limiting at reverse proxy and application levels
3. Add security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options)
4. Enable comprehensive security logging with centralized SIEM
5. Implement CSRF protection tokens

**Long-term Actions (3-6 months):**
1. Address application vulnerabilities through secure coding practices
2. Implement Multi-Factor Authentication (TOTP/WebAuthn)
3. Deploy secrets management solution (HashiCorp Vault)
4. Integrate enterprise identity provider (OAuth2/OIDC)
5. Establish continuous security integration (SAST/DAST/dependency scanning)
6. Regular penetration testing and security training program

---

## Appendix

### Repository Structure

```
labs/lab2/
├── threagile-model.yaml              # Baseline threat model
├── threagile-model.secure.yaml       # Secure variant with HTTPS + encryption
├── analyze-risks.ps1                 # Risk analysis script (composite scoring)
├── compare-risks.ps1                 # Baseline vs secure comparison script
├── baseline-analysis.txt             # Saved baseline analysis output
├── secure-analysis.txt               # Saved secure variant analysis output
├── comparison.txt                    # Saved PowerShell comparison output
├── jq-comparison.txt                 # Saved jq comparison output (lab requirement)
├── baseline/
│   ├── report.pdf
│   ├── risks.json
│   ├── stats.json
│   ├── technical-assets.json
│   ├── data-flow-diagram.png
│   ├── data-asset-diagram.png
│   └── [additional diagrams]
└── secure/
    ├── report.pdf
    ├── risks.json
    ├── stats.json
    ├── technical-assets.json
    ├── data-flow-diagram.png
    ├── data-asset-diagram.png
    └── [additional diagrams]
```

### Commands Used

**Generate baseline threat model:**
```bash
docker run --rm -v "${PWD}:/app/work" threagile/threagile -model /app/work/labs/lab2/threagile-model.yaml -output /app/work/labs/lab2/baseline -generate-risks-excel=false -generate-tags-excel=false
```

**Generate secure variant:**
```bash
docker run --rm -v "${PWD}:/app/work" threagile/threagile -model /app/work/labs/lab2/threagile-model.secure.yaml -output /app/work/labs/lab2/secure -generate-risks-excel=false -generate-tags-excel=false
```

**Generate risk comparison (jq method - as required):**
```bash
jq -n \
  --slurpfile b labs/lab2/baseline/risks.json \
  --slurpfile s labs/lab2/secure/risks.json '
def tally(x):
(x | group_by(.category) | map({ (.[0].category): length }) | add) // {};
(tally($b[0])) as $B |
(tally($s[0])) as $S |
(($B + $S) | keys | sort) as $cats |
[
"| Category | Baseline | Secure | Δ |",
"|---|---:|---:|---:|"
] + (
$cats | map(
"| " + . + " | " +
(($B[.] // 0) | tostring) + " | " +
(($S[.] // 0) | tostring) + " | " +
(((($S[.] // 0) - ($B[.] // 0))) | tostring) + " |"
)
) | .[]' | sed 's/"//g' > labs/lab2/jq-comparison.txt
```

**Additional PowerShell analysis:**
```powershell
# Custom risk analysis with composite scoring
powershell -ExecutionPolicy Bypass -File labs/lab2/analyze-risks.ps1

# Automated comparison with detailed statistics
powershell -ExecutionPolicy Bypass -File labs/lab2/compare-risks.ps1
```

### Tools and Technologies

- **Threagile v1.0.0** - Agile threat modeling toolkit
- **Docker** - Container runtime for Threagile
- **PowerShell** - Risk analysis and comparison scripting
- **YAML** - Infrastructure-as-code threat model format
- **OWASP Juice Shop v19.0.0** - Target application