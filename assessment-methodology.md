# Assessment Methodology

**How to run a security assessment with these checklists: rules of engagement, data handling, test modes, severity, reporting, and retest**

> The other guides tell you what a hardened system looks like. This one tells you how to check a system against them without causing harm, how to rate what you find consistently, and how to write it up so that someone can fix it and prove it is fixed. It was written after two assessments run with an AI coding agent: one on a single WordPress/Docker site with direct fix access, one on a multi-environment healthcare SaaS from the outside only. Both produced useful findings. Both also showed the same gaps: severities assigned by feel, outdated components missed because nobody listed versions, no rules for what to do when real patient data and live session tokens turned up, and no report format or retest step.

---

## Table of Contents

1. [Rules of Engagement](#1-rules-of-engagement)
2. [Data Handling During Testing](#2-data-handling-during-testing)
3. [Test Modes and What Each Can Verify](#3-test-modes-and-what-each-can-verify)
4. [Finding Categories](#4-finding-categories)
5. [Severity Rubric](#5-severity-rubric)
6. [Report Template](#6-report-template)
7. [Remediation and Retest Loop](#7-remediation-and-retest-loop)
8. [Using an AI Agent Safely](#8-using-an-ai-agent-safely)

---

## 1. Rules of Engagement

Rules of engagement (RoE) are the written agreement that makes the difference between a security assessment and unauthorised access. Agree them before the first request is sent, even when you own the system.

- [ ] **Get written authorisation from someone who owns the risk.** For your own VPS, a note in your repo is enough. For anything else, it must be signed or emailed by a person with authority over every asset in scope, and it must name you (and any tooling, including AI agents) as the tester.

  ```text
  Authorisation reference: AUTH-2026-11-001
  Authorised by:           <name, role>, <date>
  Tester(s):               <name>; AI agent run under tester's account
  Valid from / until:      2026-11-10 09:00 UTC / 2026-11-21 18:00 UTC
  ```

  > **Why this matters:** Cloud providers, hosting companies, and third-party SaaS (CDN, BaaS, email, payment) have their own testing policies. Authorisation from your client does not cover infrastructure the client does not own. Check the provider's published penetration testing policy before touching anything hosted there.

- [ ] **Define scope as an explicit list, not a description.** List hostnames, IP ranges, environments, repositories, and accounts. Anything not on the list is out of scope by default.

  ```text
  In scope:
    app.example.com, api.example.com          (production, read-only tests)
    staging.example.com, api.staging.example.com (full test set)
    github.com/example/web (white-box, read-only)
  Out of scope:
    mail.example.com, third-party SSO provider, payment provider,
    any customer-owned integration endpoint, denial-of-service testing,
    social engineering, physical access
  ```

- [ ] **Name every environment and state what is allowed in each.** Production, staging, test, and preprod often share databases, buckets, or credentials. Treat any environment that is connected to production data as production.

- [ ] **Set time windows.** Active scanning only during agreed hours, with the operations team aware. Passive checks (DNS, certificate transparency, public headers) can run any time.

- [ ] **Set rate limits for your own testing.** Your scanner is a load test the owner did not plan for.

  ```bash
  # Port scan: polite timing, capped rate
  nmap -T3 --max-rate 50 -Pn -p- staging.example.com

  # Web discovery: one thread, delay between requests
  ffuf -u https://staging.example.com/FUZZ -w wordlist.txt -t 1 -p 0.5

  # Nikto: pause between tests
  nikto -h https://staging.example.com -Pause 1
  ```

  Never test rate limiting or brute-force protection on production at full speed. Prove the absence of a limit with a short burst (for example 30 requests in 10 seconds) against a test account you control, then stop.

- [ ] **Write down stop conditions.** Testing pauses immediately, and the emergency contact is called, if any of these happen:
  - Error rate or latency on the target rises noticeably during your tests
  - You reach personal data, health data, payment data, or live credentials (see Section 2)
  - You find evidence that someone else has already compromised the system (webshell, unknown admin user, unexpected outbound traffic)
  - You are about to act on an asset that is not on the scope list
  - A test would modify or delete data that you did not create

- [ ] **Record an emergency contact on both sides.** A name and phone number that answers during the test window, not a shared inbox. Include who decides whether to continue after a stop.

- [ ] **Log everything you send.** Keep timestamped command history and tool output so that any anomaly the owner sees can be matched to (or ruled out from) your traffic.

  ```bash
  script -q -a "assessment-$(date +%F).log"
  ```

> **Why this matters:** During the external healthcare SaaS assessment, real session tokens and possibly real patient records were reachable from public endpoints. The repo had no RoE, so there was no agreed answer to "do we stop here, and who do we tell?" The answer must exist before the test starts.

---

## 2. Data Handling During Testing

The goal is to prove that access exists, not to exercise it. A finding is fully proven by showing that the door is open; you do not need to walk through it.

- [ ] **Prove access with counts and metadata, never with bulk content.** Record the record count, field names, and one redacted record. Do not download tables, buckets, or exports.

  ```bash
  # Good: count and schema only
  curl -s "https://api.staging.example.com/v1/patients?limit=1" \
    -H "Authorization: Bearer $TEST_TOKEN" | jq '{total: .meta.total, fields: (.data[0] | keys)}'

  # Bad: never do this
  # curl ... "?limit=100000" > patients.json
  ```

- [ ] **Redact the single sample record before it leaves the terminal.** Replace names, dates of birth, identifiers, contact details, clinical values, and tokens with placeholders. Keep only enough to show which fields are exposed.

  ```bash
  jq '.data[0] | with_entries(.value = (if (.value|type)=="string" then "<redacted:\(.value|length) chars>" else "<redacted>" end))'
  ```

- [ ] **If you reach personal data, health data (PHI), or live credentials: stop.** Then, in order:
  1. Stop the test that reached it. Do not run follow-up requests "to confirm".
  2. Record minimal evidence: URL or path, timestamp, request (with your own auth redacted), count, field names.
  3. Notify the emergency contact and the authorising person immediately, by the agreed channel.
  4. Treat it as a possible incident from that moment. The owner, not the tester, decides whether it is reportable.

  > **Why this matters:** If the data was reachable by you, it was reachable by anyone, and the clock for breach assessment may already be running. Under GDPR Article 33 a controller must notify the supervisory authority without undue delay and, where feasible, within 72 hours of becoming aware of a personal data breach. In the US, the HIPAA Breach Notification Rule (45 CFR 164.400 to 414) requires covered entities and business associates to assess and notify breaches of unsecured PHI within set deadlines. This is context, not legal advice: the owner's legal or privacy lead decides what applies. Your job is to give them accurate facts quickly and to not make the exposure larger.

- [ ] **Never use a discovered credential beyond proving it is valid**, unless the authorisation explicitly allows it. Proving validity means one harmless read (for example `GET /me`, `aws sts get-caller-identity`, a token introspection call). It does not mean listing buckets, reading mail, or pivoting.

  ```bash
  # Prove an exposed cloud key is live, then stop. Read the values without echo so they
  # stay out of shell history and the session log (add AWS_SESSION_TOKEN for ASIA... keys).
  read -rs AWS_ACCESS_KEY_ID; read -rs AWS_SECRET_ACCESS_KEY
  export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY; aws sts get-caller-identity
  unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
  ```

- [ ] **Report live credentials for rotation the same day.** A credential found during a test is compromised whether or not you used it. Session tokens must be revoked, not just left to expire.

- [ ] **Store evidence encrypted, on one machine, with an expiry.**

  ```bash
  tar czf - evidence/ | age -r <recipient-public-key> > evidence-2026-11.tar.gz.age
  find evidence/ -type f -exec shred -u {} +   # after the encrypted archive is verified
  ```

  `shred` is not reliable on SSDs, journaling, or copy-on-write filesystems. Keep raw evidence on an encrypted volume from the start, so deleting the volume key is the real deletion.

- [ ] **Delete evidence after closure.** Keep the report (redacted) and delete raw evidence once all findings are retested and closed, or at the date agreed in the RoE. Record the deletion date in the report.

- [ ] **Never paste raw evidence into chat tools, tickets, or AI prompts.** Tickets get the redacted version and a pointer to the encrypted archive.

---

## 3. Test Modes and What Each Can Verify

Every checklist item can be verified in one or more modes. Choosing the mode up front prevents the most common reporting error: marking an item PASS when it was never testable from where you stood.

| Mode | Access | Can verify | Cannot verify |
|------|--------|------------|---------------|
| **Black-box external** | Internet only, no accounts | Exposed ports, TLS, headers, DNS, public files, source maps, error pages, unauthenticated APIs, rate limits on public endpoints | Anything behind login, server config, code, logging, backups |
| **Authenticated (grey-box)** | One or more test accounts per role | Above, plus authorisation (IDOR, role escalation, tenant isolation), session handling, business logic, authenticated rate limits | Server config, code paths not reachable from the UI, detection and backup controls |
| **White-box** | Source code, config, and read-only server or cloud console access | Everything above plus config files, dependency versions, secrets in repos, logging, backups, CI/CD | Runtime behaviour that differs from config (always confirm critical items live) |

White-box procedure is in [whitebox-audit.md](whitebox-audit.md).

Mark a checklist item **Not testable** when the mode cannot reach it. Do not mark it PASS, and do not infer it from indirect signals. In the healthcare SaaS assessment, several guides were effectively "externally blocked": they needed server access that the external mode did not have. That is a coverage gap to report, not a pass.

### Guide coverage by mode

`Full` = most items verifiable. `Partial` = some items verifiable, list which in the coverage table. `No` = not verifiable in this mode.

| Guide | Black-box | Grey-box | White-box |
|-------|-----------|----------|-----------|
| [linux-server-hardening.md](linux-server-hardening.md) | Partial (open ports, SSH banner and auth methods) | Partial (same) | Full |
| [cloudflare-hardening.md](cloudflare-hardening.md) | Partial (origin exposure, TLS mode, HSTS, WAF behaviour) | Partial (same) | Full (with dashboard read access) |
| [local-to-production-checklist.md](local-to-production-checklist.md) | Partial (post-deploy checks, DNS security, public `.env`/`.git`) | Partial | Full |
| [security-audit-automation.md](security-audit-automation.md) | No | No | Full |
| [incident-response-checklist.md](incident-response-checklist.md) | No | No | Partial (readiness: contacts, log retention, runbook exists) |
| [disaster-recovery.md](disaster-recovery.md) | No | No | Partial (backups exist and restore drill evidence) |
| [wordpress-server-hardening.md](wordpress-server-hardening.md) | Partial (REST API, enumeration, version disclosure, login protection, SPF/DKIM/DMARC) | Partial (plus admin access strategy) | Full |
| [php-application-hardening.md](php-application-hardening.md) | Partial (error disclosure, debug mode, exposed framework files) | Partial (plus mass assignment, upload, SSRF behaviour) | Full |
| [frontend-security.md](frontend-security.md) | Full for shipped code (bundles, source maps, CSP, CORS, SRI) | Full | Full (plus build config and dependencies) |
| [vulnerability-intelligence.md](vulnerability-intelligence.md) | Partial (versions from banners, headers, asset fingerprints) | Partial | Full (lockfiles, package lists, image tags) |
| [php-version-upgrade-path.md](php-version-upgrade-path.md) | Partial (PHP version if disclosed) | Partial | Full |
| [access-control-and-api-security.md](access-control-and-api-security.md) | Partial (unauthenticated endpoints, BaaS/storage with public keys) | Full | Full |
| [legacy-hosting-apache.md](legacy-hosting-apache.md) | Partial (server banner, `.htaccess` exposure, directory listing, TLS) | Partial | Full |
| [whitebox-audit.md](whitebox-audit.md) | No | No | Full |

> **Why this matters:** A report that says "60 findings" without saying which half of the checklist was never examined reads as a clean bill of health for the rest. The coverage table (Section 6) is what tells the reader where the unknowns are.

---

## 4. Finding Categories

Every finding gets exactly one category. If a finding fits two, pick the one that describes the fix.

| Category | Definition | Examples |
|----------|------------|----------|
| **Misconfiguration** | A setting, header, file, or deployment choice is wrong; the code and versions are fine | TLS 1.0 enabled, missing HSTS, source maps served in production, directory listing, debug mode on, origin IP reachable, missing DNSSEC, permissive CORS |
| **Access control and secrets** | Someone can reach data or actions they should not, or a secret is exposed | IDOR on `/patients/{id}`, BaaS table readable with the public key, API key in a JS bundle, session token in a URL, no rate limit on login, `.env` downloadable |
| **Outdated or EOL component** | A runtime, framework, library, OS, or image is past end of life or has known vulnerabilities | PHP 7.4 in production, jQuery 1.x, unpatched WordPress plugin, base image with KEV-listed CVE |
| **Code-level vulnerability** | A defect in application code that a config change cannot fix | SQL injection, `unserialize()` on user input, type-juggling auth bypass, stored XSS via `innerHTML` |
| **Detection/response gap** | An attack would succeed or go unnoticed because monitoring, logging, backups, or response is missing | No auth failure logging, no alerting on admin creation, backups never restore-tested, no incident contact list |

> **Why this matters:** In the healthcare SaaS assessment, 39 of 60 findings were misconfiguration and only 1 was an outdated component. That ratio was not a sign of a well-patched estate. It was a sign that nobody had inventoried versions. If one category is near zero, ask whether you tested for it before you accept it. Use [vulnerability-intelligence.md](vulnerability-intelligence.md) to build the version inventory first.

---

## 5. Severity Rubric

Severity must be repeatable: two testers rating the same finding should land on the same level, and the rationale must be written down. Use this procedure.

### Step 1: Base score

Score the finding with CVSS v4.0 base metrics using the [FIRST CVSS v4.0 calculator](https://www.first.org/cvss/calculator/4.0). Record the vector string, not only the number. The [specification](https://www.first.org/cvss/v4.0/specification-document) requires labelling which metric groups are included: a base-only score is **CVSS-B**; with threat metrics it is **CVSS-BT**; with environmental metrics **CVSS-BE**; all three **CVSS-BTE**.

Map the base score to a starting level with the standard scale: Critical 9.0 to 10.0, High 7.0 to 8.9, Medium 4.0 to 6.9, Low 0.1 to 3.9, Info 0.0 or no direct impact.

### Step 2: Adjust

Move the level up or down by these factors. Each adjustment must be written in the rationale.

| Factor | Raise when | Lower when |
|--------|-----------|------------|
| **Exploitability** | CVE is in [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog); [EPSS](https://www.first.org/epss/) probability is high (for example above 0.1, or top 5 percent percentile); public exploit code exists | No public exploit, low EPSS, requires conditions not present in this deployment |
| **Exposure** | Reachable from the internet without authentication | Requires an authenticated account; reachable only from an internal network or VPN |
| **Data sensitivity** | Exposes PHI, PII, payment data, or credentials; affects multiple tenants | Affects only public or test data |
| **Chaining** | Combines with another finding into a worse outcome (for example origin IP exposed plus admin panel without WAF) | Isolated, with compensating controls verified live |

```bash
# Is it known exploited?
curl -s https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json \
  | jq -r '.vulnerabilities[] | select(.cveID=="CVE-2021-44228") | .cveID, .dateAdded'

# How likely is exploitation in the next 30 days? (EPSS, 0 to 1)
curl -s "https://api.first.org/data/v1/epss?cve=CVE-2021-44228" | jq '.data[0] | {epss, percentile, date}'
```

### Step 3: Policy overrides

Some findings get a fixed minimum regardless of score:

- Any live credential, token, or private key exposed publicly: **Critical**.
- Any unauthenticated read of PHI or multi-tenant PII: **Critical**.
- Any runtime, framework, or OS past end of security support in production: at least **High**. A distribution package that still receives security backports from its vendor is not past support; record the source of that support.
- Any CVE listed in CISA KEV on an internet-facing asset: at least **High**, normally **Critical**.

### Worked examples

| Finding | Level | Rationale |
|---------|-------|-----------|
| JavaScript source maps served in production and containing live API credentials | **Critical** | Base alone might rate an information disclosure as Medium. Policy override: live credential exposed to the internet without authentication. Chaining: the credential grants backend access. |
| Backend-as-a-Service database tables readable with the public (anon) key shipped in the frontend | **Critical** | The public key is meant to be public, so access control rests entirely on row-level rules. With rules missing, any visitor can read the data. Unauthenticated, internet-facing, sensitive data. |
| TLS 1.0 enabled on a public endpoint | **High** or **Medium** | TLS 1.0 is deprecated (RFC 8996) and fails most compliance baselines. Rate **High** if the endpoint carries PHI, credentials, or payment data, or if a compliance regime applies. Rate **Medium** if TLS 1.2+ is preferred, modern clients negotiate it, and the endpoint carries no sensitive data: practical downgrade attacks are hard, so the residual risk is mostly compliance. |
| DNSSEC not enabled on the domain | **Low** | Needs a DNS spoofing or cache poisoning position to exploit; CAA, HSTS, and registrar lock reduce impact. Defence in depth, not an open door. |
| PHP 7.4 (end of life) in production, no known CVE currently matched | **High** (policy) | No CVE today does not mean no vulnerability: it means nobody publishes fixes any more. The next CVE will never be patched. Upgrade work takes weeks, so the rating must create pressure now. See [php-version-upgrade-path.md](php-version-upgrade-path.md). |
| Login endpoint with no rate limit, abuse confirmed with a short burst | **High** if internet-facing with no MFA; **Medium** with MFA | Credential stuffing is routine; MFA is a verified compensating control. |
| Server version banner disclosed | **Info** or **Low** | Aids fingerprinting only. Raise it if the disclosed version is EOL, and then report the EOL component as its own finding. |

### Why scanner severities must be re-rated

In the healthcare SaaS assessment, a commercial scanner rated many of the same issues differently from the manual review, in both directions. That is expected, and scanner output must not be pasted into a report unchanged:

- Scanners score the generic issue, not your deployment. They do not know whether the endpoint carries PHI, sits behind authentication, or chains with another finding.
- Scanners over-rate header and banner findings because they are easy to detect, and under-rate access control failures because they cannot detect them at all.
- Scanner versions of CVSS differ (v3.1 vs v4.0), and some vendors use proprietary scales.

Use the scanner rating as an input to Step 1 and record it in the finding ("scanner rated: Medium"), then apply Steps 2 and 3. When your rating differs, say why in one sentence.

---

## 6. Report Template

Copy this skeleton. Keep evidence redacted (Section 2). One report per assessment; findings are numbered per report.

````markdown
# Security Assessment Report: {TARGET}

**Authorisation:** {AUTHORISATION_REF} | **Mode:** {black-box / grey-box / white-box}
**Test window:** 2026-11-10 to 2026-11-21 | **Report date:** 2026-11-24 | **Version:** 1.0
**Tester(s):** {names; AI agent used: yes/no, which}

## 1. Executive summary

Three to six sentences: overall risk, the top three issues in plain language,
whether personal or health data was reachable, and what to do first.

## 2. Scope

| Asset | Environment | In scope | Notes |
|-------|-------------|----------|-------|
| app.example.com | production | yes | read-only tests |
| api.staging.example.com | staging | yes | full test set |
| sso provider | n/a | no | third party |

Out of scope: {OUT_OF_SCOPE}

## 3. Method

Mode, tools and versions, rate limits applied, checklist guides used,
stop conditions triggered (if any) and what happened.

## 4. Findings by severity and environment

| Environment | Critical | High | Medium | Low | Info | Total |
|-------------|----------|------|--------|-----|------|-------|
| production  | 0 | 0 | 0 | 0 | 0 | 0 |
| staging     | 0 | 0 | 0 | 0 | 0 | 0 |
| **Total**   | 0 | 0 | 0 | 0 | 0 | 0 |

| Category | Critical | High | Medium | Low | Info |
|----------|----------|------|--------|-----|------|
| Misconfiguration | | | | | |
| Access control and secrets | | | | | |
| Outdated or EOL component | | | | | |
| Code-level vulnerability | | | | | |
| Detection/response gap | | | | | |

## 5. Findings

### F-001: Source maps expose live API credentials

| Field | Value |
|-------|-------|
| Category | Access control and secrets |
| Severity | Critical |
| Rationale | CVSS-B 8.7 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N); raised: live credential, internet-facing, no auth (policy override). Scanner rated: Medium. |
| Affected assets | app.example.com (production), app.staging.example.com |
| Evidence (redacted) | `GET /static/js/main.4f2a.js.map` returned 200; file contains `API_KEY="sk_live_<redacted 32 chars>"`; validity proven with one `GET /me` at 2026-11-11 10:42 UTC. |
| Checklist reference | frontend-security.md, Section 1, "Source Maps in Production" |
| Remediation | Rotate the key and revoke sessions; disable source map upload in the build; block `*.map` at the web server. Effort: S (under 1 day). |
| Verification | `curl -s -o /dev/null -w '%{http_code}' https://app.example.com/static/js/main.4f2a.js.map` returns 404; old key returns 401. |
| Status | Open |
| Owner | {name} |
| Retest date | 2026-12-01 |

## 6. Checklist coverage

| Guide | Section / item | Result | Note |
|-------|----------------|--------|------|
| cloudflare-hardening.md | 3. Origin IP cloaking | FAIL | F-004 |
| cloudflare-hardening.md | 4. SSL/TLS | PASS | Full (strict) verified |
| linux-server-hardening.md | 4. Fail2ban | Not testable | needs server access |
| wordpress-server-hardening.md | all | N/A | not a WordPress site |

Totals: PASS n, FAIL n, N/A n, Not testable n.

## 7. Data handling statement

Personal or health data reached: yes/no. If yes: when, how much (count only),
who was notified and when. Evidence location and planned deletion date.

## 8. Retest log

| Finding | Retest date | Result | Evidence |
|---------|-------------|--------|----------|
````

Effort scale for remediation: **S** under 1 day, **M** 1 to 5 days, **L** 1 to 4 weeks, **XL** more than 4 weeks or needs a project (for example a runtime upgrade).

---

## 7. Remediation and Retest Loop

- [ ] **Fix in this order.**
  1. Exposed live credentials and sessions: rotate the secret, invalidate every session and token issued under it, and check logs for use since exposure. Rotation without session invalidation leaves the attacker logged in.
  2. Any KEV-listed CVE on an internet-facing asset.
  3. Remaining Critical findings, then unauthenticated High findings.
  4. Authenticated High findings and EOL components (start the upgrade project now even if it takes months).
  5. Medium, then Low, batched by owner and by deploy.

- [ ] **Agree a deadline per severity.** A common starting point: Critical 7 days (credentials and KEV within 24 to 72 hours), High 30 days, Medium 90 days, Low next planned maintenance. Record exceptions with an owner and an expiry date.

- [ ] **Retest with the same command that proved the finding.** The verification command in each finding block is the retest. Store the before and after output, redacted.

  ```bash
  # Example retest record
  date -u +%FT%TZ
  curl -sI https://app.example.com | grep -i strict-transport-security
  ```

- [ ] **Close a finding only when all of these are true:**
  - The verification command now shows the expected secure result, from the same vantage point as the original test
  - The fix is deployed to every affected environment listed, not only one
  - For secrets: the old value is confirmed rejected, not just replaced
  - No regression: the related checklist items still pass
  - The retest date, tester, and evidence are recorded in the retest log

- [ ] **Re-rate, do not delete, partially fixed findings.** If TLS 1.0 is disabled on production but not staging, the finding stays open with reduced scope.

- [ ] **Set a recurring cadence.**
  - Weekly: automated checks from [security-audit-automation.md](security-audit-automation.md), KEV and dependency diffs from [vulnerability-intelligence.md](vulnerability-intelligence.md)
  - Quarterly: black-box retest of the full coverage table; restore drill from [disaster-recovery.md](disaster-recovery.md)
  - Yearly, or after a major architecture change: full assessment in the deepest mode you can get authorised

> **Why this matters:** Neither of the two assessments behind this guide had a retest step. A fix that was "deployed" but never verified is indistinguishable from a fix that was never made.

---

## 8. Using an AI Agent Safely

An AI coding agent can work through these checklists quickly and is good at reading config, running checks, and drafting findings. It will also act confidently on wrong assumptions. Run it inside the same RoE as a human tester, with tighter defaults. A ready-made prompt is in [AUDIT_PROMPT.md](AUDIT_PROMPT.md).

- [ ] **Run read-only first.** The first pass produces findings, not changes. Give the agent read-only credentials and a read-only filesystem mount where possible. Allow fixes only in a separate, explicitly approved second pass.

- [ ] **Require a checklist reference and evidence for every finding.** Each finding must cite the guide, section, and item it tests, and include the command and redacted output that proves it. Discard findings without both: they are guesses.

- [ ] **Forbid destructive and data-exfiltrating commands.** State it in the prompt and enforce it in the tool's permission settings where available. Deny list at minimum: `rm -rf`, `DROP`, `DELETE`, `TRUNCATE`, `UPDATE` on production, `docker system prune`, `git push --force`, mass downloads (`wget -r`, `aws s3 sync`, `pg_dump`/`mysqldump` of production), and any request with a large `limit` parameter.

- [ ] **Give it the rate limits and stop conditions explicitly.** The agent does not know that a 500-request loop is rude. Put the numbers in the prompt.

- [ ] **A human reviews every fix before it is applied.** Review the diff, the reason, and the rollback. In the WordPress assessment, where the agent applied fixes directly, this review was the only control between a correct finding and a wrong fix on a live site.

- [ ] **Never paste secrets or PHI into prompts.** Use environment variables or a secrets manager that the agent's tools read at runtime; refer to them by name. If the agent discovers a secret, it must report the location and redact the value, not repeat it.

  > Everything the agent's tools print (HTTP responses, config dumps, query results) is sent to the model provider as part of the conversation. Confirm that your agreement with the provider covers that data before an agent runs tests that can reach PHI or personal data, or keep those tests manual. Feed it white-box collector output only after the redaction review.

- [ ] **Keep the full transcript.** Store it with the evidence, encrypted, under the same retention rules. It is your record of what was sent to the target and why.

- [ ] **Treat agent severity ratings as drafts.** Apply Section 5 yourself. Agents, like scanners, tend to rate what is easy to detect higher than what is hard to detect.

---

*Last reviewed: 2026-11 | Applies to: Security assessments of self-hosted and SaaS web applications using these checklists, run by humans or AI coding agents, in black-box, grey-box, or white-box mode*
