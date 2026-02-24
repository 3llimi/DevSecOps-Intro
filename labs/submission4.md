# Lab 4 — SBOM Generation & Software Composition Analysis

**Branch:** `feature/lab4`  
**Target Image:** `bkimminich/juice-shop:v19.0.0`

---

## Task 1 — SBOM Generation with Syft and Trivy

### 1.1 Environment Setup

```powershell
New-Item -ItemType Directory -Force -Path labs/lab4/syft, labs/lab4/trivy, labs/lab4/comparison, labs/lab4/analysis
docker pull anchore/syft:latest
docker pull aquasec/trivy:latest
docker pull anchore/grype:latest
```

All three images pulled successfully:
- `anchore/syft:latest` — digest `sha256:392b65f...`
- `aquasec/trivy:latest` — digest `sha256:1c78ed1...`
- `anchore/grype:latest` — digest `sha256:fc348b3...`

### 1.2 SBOM Generation with Syft

**Commands executed:**

```powershell
# Syft native JSON (most detailed)
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock `
  -v "${PWD}:/tmp" anchore/syft:latest `
  bkimminich/juice-shop:v19.0.0 -o "syft-json=/tmp/labs/lab4/syft/juice-shop-syft-native.json"

# Human-readable table
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock `
  -v "${PWD}:/tmp" anchore/syft:latest `
  bkimminich/juice-shop:v19.0.0 -o "table=/tmp/labs/lab4/syft/juice-shop-syft-table.txt"
```

Syft produced a 3.6 MB native JSON SBOM by performing deep layer-by-layer inspection of the image, cataloguing all packages with full metadata including file paths, layer origins, licenses, and CPE identifiers.

**Package Type Distribution (Syft):**

| Package Type | Count | Description                          |
|--------------|------:|--------------------------------------|
| `npm`        |   990 | Node.js application dependencies     |
| `deb`        |    10 | Debian system packages (OS layer)    |
| `binary`     |     1 | Node.js runtime binary               |
| **Total**    | **1,001** | All catalogued software components |

**Notable Syft behaviors:**
- Captured full Debian version strings including patch suffixes (e.g. `libc6@2.36-9+deb12u10`)
- Detected test/dummy npm packages (`baz`, `false_main`, `invalid_main`, `@my-scope/package-a/b`) by recursively scanning all `node_modules/` entries
- Recorded the `node@22.18.0` binary as a separate component
- Generated 32 unique license types across all components

### 1.3 SBOM Generation with Trivy

**Commands executed:**

```powershell
# Detailed JSON with all packages
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock `
  -v "${PWD}:/tmp" aquasec/trivy:latest image `
  --format json --output /tmp/labs/lab4/trivy/juice-shop-trivy-detailed.json `
  --list-all-pkgs bkimminich/juice-shop:v19.0.0

# Human-readable table
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock `
  -v "${PWD}:/tmp" aquasec/trivy:latest image `
  --format table --output /tmp/labs/lab4/trivy/juice-shop-trivy-table.txt `
  --list-all-pkgs bkimminich/juice-shop:v19.0.0
```

Trivy first downloaded its vulnerability database (86 MB) before scanning. It detected Debian 12.11 as the OS and organized results into structured targets.

**Package Type Distribution (Trivy):**

| Target | Type | Packages |
|--------|------|--------:|
| `bkimminich/juice-shop:v19.0.0 (debian 12.11)` | `debian` | 10 |
| `Node.js` | `node-pkg` | 1,125 |
| `/juice-shop/build/lib/insecurity.js` | secrets | 0 |
| `/juice-shop/lib/insecurity.ts` | secrets | 0 |
| **Total** | | **1,135** |

### 1.4 Package Detection Analysis

**Quantitative comparison:**

| Metric | Value |
|--------|------:|
| Syft total unique packages | 1,001 |
| Trivy total unique packages | 997 |
| Packages detected by both | 988 |
| Syft-only packages | 13 |
| Trivy-only packages | 9 |

**Syft-only packages (13):**

| Package | Version | Reason |
|---------|---------|--------|
| `baz`, `false_main`, `invalid_main`, `hashids-esm`, `browser_field` | UNKNOWN | Test/dummy npm entries detected by deep node_modules scan |
| `gcc-12-base`, `libc6`, `libgcc-s1`, `libgomp1`, `libssl3`, `libstdc++6`, `tzdata` | Full Debian versions (e.g. `2.36-9+deb12u10`) | Full patch-level version strings |
| `node` | `22.18.0` | Node.js runtime detected as binary component |

**Trivy-only packages (9):**

| Package | Version | Reason |
|---------|---------|--------|
| `gcc-12-base`, `libc6`, `libgcc-s1`, `libgomp1`, `libssl3`, `libstdc++6`, `tzdata` | Trimmed versions (e.g. `2.36`) | Strips Debian epoch/patch suffixes |
| `portscanner` | `2.2.0` | Detected via different npm manifest parsing |
| `toposort-class` | `1.0.1` | Detected via different npm manifest parsing |

**Key finding:** The "unique" packages are mostly the same components with different version formatting. Syft preserves full Debian version strings (`2.36-9+deb12u10`) while Trivy trims them (`2.36`), causing false divergence in automated comparisons. This is an important consideration when using SBOMs for vulnerability matching — version string normalization directly affects CVE matching accuracy.

### 1.5 License Discovery Analysis

**License comparison:**

| Metric | Syft | Trivy |
|--------|-----:|------:|
| Unique license types found | 32 | 28 |
| MIT packages | 890 | 878 |
| ISC packages | 143 | 143 |
| LGPL packages | 19 | 19 |

**Top licenses (Syft):**

| License | Count | Risk Level |
|---------|------:|------------|
| MIT | 890 | ✅ Permissive |
| ISC | 143 | ✅ Permissive |
| LGPL-3.0 | 19 | ⚠️ Weak copyleft |
| BSD-3-Clause | 16 | ✅ Permissive |
| Apache-2.0 | 15 | ✅ Permissive |
| BSD-2-Clause | 12 | ✅ Permissive |
| GPL-2 / GPL-3 / GPL | 15 | ⚠️ Strong copyleft |
| Artistic | 5 | ⚠️ Review required |
| BlueOak-1.0.0 | 5 | ✅ Permissive |
| WTFPL | 2 | ⚠️ Legally unclear |

Syft found 4 more unique license types than Trivy (32 vs 28), capturing more granular GPL variants (GPL-2, GPL-3, GPL as separate entries) and additional edge cases. Trivy normalized these into fewer categories.

---

## Task 2 — Software Composition Analysis with Grype and Trivy

### 2.1 SCA with Grype

**Commands executed:**

```powershell
docker run --rm -v "${PWD}:/tmp" anchore/grype:latest `
  "sbom:/tmp/labs/lab4/syft/juice-shop-syft-native.json" `
  -o json > labs/lab4/syft/grype-vuln-results.json

docker run --rm -v "${PWD}:/tmp" anchore/grype:latest `
  "sbom:/tmp/labs/lab4/syft/juice-shop-syft-native.json" `
  -o table > labs/lab4/syft/grype-vuln-table.txt
```

Grype scanned the Syft-generated SBOM directly, matching all 1,001 components against the Anchore vulnerability database (which aggregates NVD, GitHub Advisory Database, and OS-specific advisories).

**Grype vulnerability severity distribution:**

| Severity | Count |
|----------|------:|
| Critical | 11 |
| High | 60 |
| Medium | 31 |
| Low | 3 |
| Negligible | 12 |
| **Total** | **117** |

### 2.2 SCA with Trivy

**Commands executed:**

```powershell
# Full vulnerability scan
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock `
  -v "${PWD}:/tmp" aquasec/trivy:latest image `
  --format json --output /tmp/labs/lab4/trivy/juice-shop-trivy-detailed.json `
  bkimminich/juice-shop:v19.0.0

# Secrets scan
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock `
  -v "${PWD}:/tmp" aquasec/trivy:latest image `
  --scanners secret --format table `
  --output /tmp/labs/lab4/trivy/trivy-secrets.txt `
  bkimminich/juice-shop:v19.0.0

# License scan
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock `
  -v "${PWD}:/tmp" aquasec/trivy:latest image `
  --scanners license --format json `
  --output /tmp/labs/lab4/trivy/trivy-licenses.json `
  bkimminich/juice-shop:v19.0.0
```

**Trivy vulnerability severity distribution:**

| Severity | Count |
|----------|------:|
| Critical | 10 |
| High | 55 |
| Medium | 33 |
| Low | 18 |
| **Total** | **116** |

### 2.3 Critical Vulnerabilities Analysis — Top 5

The following critical findings appeared across both tools, confirming their validity:

**1. vm2 Sandbox Escape (Multiple CVEs) — `vm2@3.9.17`**

| Field | Detail |
|-------|--------|
| IDs | CVE-2023-32314, CVE-2023-37466, CVE-2023-37903, CVE-2026-22709, GHSA-whpj-8f3w-67p5, GHSA-99p7-6v5w-7xg8, GHSA-cchq-frgv-rjh5, GHSA-g644-9gfx-q4q4 |
| Severity | Critical |
| Description | Multiple sandbox escape vulnerabilities allow attackers to execute arbitrary code outside the sandboxed environment via Promise handler bypass and custom inspect functions |
| Impact | Full host system compromise from within the Juice Shop application |
| Remediation | vm2 is **unmaintained and deprecated** — replace with `isolated-vm`. Remove usage entirely if possible |

**2. OpenSSL Remote Code Execution — `libssl3@3.0.17-1~deb12u2`**

| Field | Detail |
|-------|--------|
| ID | CVE-2025-15467 |
| Severity | Critical |
| Description | Remote code execution or Denial of Service via oversized Initialization Vector in CMS parsing |
| Impact | OS-level RCE possible if the application processes attacker-controlled CMS data |
| Remediation | Rebuild Docker image from an updated Debian 12 base to pull patched `libssl3` |

**3. crypto-js Weak PBKDF2 — `crypto-js@3.3.0`**

| Field | Detail |
|-------|--------|
| IDs | CVE-2023-46233 / GHSA-xwcq-pm8m-c4vf |
| Severity | Critical |
| Description | PBKDF2 implementation is 1,000× weaker than the 1993 standard and 1.3 million× weaker than current standards due to incorrect default iteration count |
| Impact | Password hashes generated by this library are trivially brute-forceable |
| Remediation | Upgrade to `crypto-js@4.2.0+` or migrate to Node.js native `crypto` module |

**4. jsonwebtoken Algorithm Confusion — `jsonwebtoken@0.1.0` and `@0.4.0`**

| Field | Detail |
|-------|--------|
| IDs | CVE-2015-9235 / GHSA-c7hr-j4mj-j2w6 |
| Severity | Critical |
| Description | JWT verification can be bypassed by changing the algorithm to `none`, allowing forged tokens without a valid signature |
| Impact | Authentication bypass — attackers can forge admin tokens and gain full application access |
| Remediation | Upgrade to `jsonwebtoken@9.0.0+`; explicitly reject the `none` algorithm in verification options |

**5. marsdb Command Injection — `marsdb@0.6.11`**

| Field | Detail |
|-------|--------|
| ID | GHSA-5mrr-rgp6-x4gr |
| Severity | Critical |
| Description | Command injection vulnerability allows arbitrary code execution via unsanitized input to database query functions |
| Impact | Remote code execution through the application's database layer |
| Remediation | `marsdb` is unmaintained — migrate to a maintained MongoDB-compatible library |

### 2.4 Secrets Scanning Results

Trivy's secrets scanner found **2 secrets** baked into the Docker image:

**Finding 1 — JWT Token in Test File**

| Field | Detail |
|-------|--------|
| File | `/juice-shop/frontend/src/app/last-login-ip/last-login-ip.component.spec.ts:61` |
| Type | JWT token hardcoded in test |
| Severity | Medium |
| Layer | Added by `COPY --chown=65532:0 /juice-shop` |
| Risk | Test tokens committed to source reveal JWT structure and signing patterns |

**Finding 2 — RSA Private Key**

| Field | Detail |
|-------|--------|
| File | `/juice-shop/lib/insecurity.ts:23` |
| Type | `AsymmetricPrivateKey` — RSA Private Key |
| Severity | HIGH |
| Layer | Added by `COPY --chown=65532:0 /juice-shop` |
| Risk | This is Juice Shop's **JWT signing private key** hardcoded in source. Any attacker with image access can extract it and forge arbitrary JWT tokens for any user including admin |

This finding directly correlates with the jsonwebtoken critical vulnerability — together they form a trivially exploitable authentication bypass chain: extract the private key from the image, forge a JWT with admin claims, bypass all authentication.

### 2.5 License Compliance Assessment

**Potentially risky licenses identified:**

| License | Count | Risk | Concern |
|---------|------:|------|---------|
| GPL-2 / GPL-3 / GPL | 15 | ⚠️ High | Strong copyleft — commercial distribution would require disclosing all source code |
| LGPL-3.0 | 19 | ⚠️ Medium | Weak copyleft — modifications to LGPL components must be shared |
| WTFPL | 2 | ⚠️ Low | Legally untested, not OSI-approved |
| Artistic | 5 | ⚠️ Low | Older Perl-era license with ambiguous terms |

**Compliance recommendation:** For a production application, the 15 GPL-licensed packages would require legal review before commercial distribution. Since Juice Shop is itself open source (MIT licensed), GPL dependencies are currently acceptable. In a proprietary product, these would require replacement with permissively-licensed alternatives.

---

## Task 3 — Toolchain Comparison: Syft+Grype vs Trivy All-in-One

### 3.1 Accuracy and Coverage Analysis

**Package detection:**

| Metric | Syft | Trivy |
|--------|-----:|------:|
| Total unique packages | 1,001 | 997 |
| Packages in common | 988 | 988 |
| Tool-exclusive packages | 13 | 9 |
| Version string format | Full Debian patches | Trimmed/normalized |

**Vulnerability detection:**

| Metric | Grype | Trivy |
|--------|------:|------:|
| Total vulnerabilities | 117 | 116 |
| Unique CVE/advisory IDs | 90 | 88 |
| CVEs in common | 26 | 26 |
| Tool-exclusive findings | 64 | 62 |
| Critical | 11 | 10 |
| High | 60 | 55 |
| Medium | 31 | 33 |
| Low | 3 | 18 |
| Negligible | 12 | — |

**The most striking finding is that only 26 out of ~152 total unique CVE/advisory IDs were detected by both tools** — roughly a 17% overlap. This is not because one tool is more accurate, but because they draw from fundamentally different advisory databases. Neither is strictly better — they are complementary.

### 3.2 Vulnerability Database Differences

**Grype-exclusive findings (64):** Predominantly GHSA-format advisories — these are GitHub Advisory Database entries for npm packages that either have no CVE assignment or whose CVE mappings Trivy doesn't include. Grype also caught newer CVEs (`CVE-2025-55130/55131/55132`) for the Node.js runtime itself.

**Trivy-exclusive findings (62):** Predominantly traditional CVE-format IDs from NVD — older, well-known npm vulnerabilities that Grype either de-duplicates into GHSA entries or omits. Also includes `NSWG-ECO-*` Node Security Working Group advisories not in Grype's database.

### 3.3 Tool Strengths and Weaknesses

**Syft strengths:**
- Richer package metadata: file paths, layer origins, CPEs, full version strings
- Catches test/dummy npm packages and binary components others miss
- Full Debian version strings enable more precise CVE matching
- 32 unique license types vs Trivy's 28
- SBOM suitable for sharing with external parties or feeding into Dependency-Track

**Syft weaknesses:**
- SBOM-only — requires Grype for vulnerability scanning (two-step workflow)
- Runs silently on Windows with no progress output

**Grype strengths:**
- Best npm ecosystem GHSA advisory coverage (64 unique findings)
- Scans offline from Syft SBOM — decouples generation from analysis
- Detects `Negligible` severity class that Trivy omits
- 117 total findings vs Trivy's 116

**Grype weaknesses:**
- Misses 62 CVEs that Trivy finds (traditional NVD entries)
- No secrets scanning, license scanning, or misconfiguration detection
- Requires Syft as a prerequisite

**Trivy strengths:**
- All-in-one: vulnerability + secrets + license + misconfiguration scanning in a single tool
- Found 2 hardcoded secrets (RSA private key + JWT token) that Grype missed entirely
- Better NVD and OS vendor advisory coverage
- Built-in license compliance scanning
- Simpler CI/CD integration — one tool, one command

**Trivy weaknesses:**
- Misses 64 GHSA advisories that Grype finds
- Trims Debian version strings, reducing CVE match precision
- Slower initial run due to 86 MB vulnerability DB download
- Fewer unique license types detected (28 vs 32)

### 3.4 Use Case Recommendations

**Choose Syft + Grype when:**
- You need rich SBOMs for compliance or supply chain documentation (NTIA, CISA requirements)
- Your application is npm/Node.js-heavy and GHSA coverage matters
- You need to share SBOMs with external parties or feed them into Dependency-Track
- You operate in air-gapped environments where SBOM generation and scanning are separate steps
- Precise Debian patch-level version matching is required

**Choose Trivy when:**
- You want a single tool covering vulnerabilities, secrets, licenses, and misconfigurations
- Secrets scanning is a requirement (Trivy found 2 secrets; Grype found none)
- You scan diverse targets (containers, filesystems, git repos, IaC) with one tool
- CI/CD simplicity is a priority

**Best practice — run both:** Given only a 17% CVE overlap, running Syft+Grype alongside Trivy provides the most comprehensive coverage. The combined unique finding set is substantially larger than either tool alone.

### 3.5 Integration Considerations

**CI/CD integration:** Both tools are available as Docker images, making pipeline integration straightforward. A recommended pattern runs Trivy first (secrets + vuln in one pass) and Grype second (GHSA coverage), then merges findings into a unified report.

**SBOM as pipeline artifact:** The recommended pattern is: Syft generates SBOM → SBOM stored as pipeline artifact → Grype and other tools consume SBOM. This decouples generation from analysis and enables historical re-scanning against old SBOMs when new CVEs are published.

**False positive management:** Both tools flag intentionally vulnerable packages in Juice Shop (vm2, old jsonwebtoken). In production, `.grype.yaml` and `.trivyignore` files should suppress accepted risks with documented justifications and expiry dates.

---

## Summary

| Dimension | Syft + Grype | Trivy |
|-----------|-------------|-------|
| Total packages found | 1,001 | 997 |
| Total vulnerabilities | 117 | 116 |
| Unique CVE/advisory IDs | 90 | 88 |
| CVE overlap with other tool | 26 (29%) | 26 (30%) |
| Secrets found | 0 | 2 |
| Unique license types | 32 | 28 |
| Tools required | 2 | 1 |
| Primary advisory source | GHSA | NVD + OS vendors |

The most important takeaway from this lab is that **no single tool provides complete coverage**. Syft+Grype and Trivy each found roughly 64 vulnerabilities the other missed entirely. For production security programs, both toolchains should be run in parallel and their findings unified in a vulnerability management platform like Dependency-Track or DefectDojo.