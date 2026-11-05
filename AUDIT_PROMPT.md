# Audit Prompt for AI Coding Agents

Copy the prompt below into Claude Code or a similar agent, started in a clone of this repo. Replace every `{PLACEHOLDER}` first. Read [assessment-methodology.md](assessment-methodology.md) before using it: the prompt enforces that document, it does not replace it.

Before you start:
- Have written authorisation, and a scope list, ready (methodology Section 1).
- Configure the agent's tool permissions to deny destructive commands; the prompt alone is not a control.
- Provide credentials as environment variables, never in the prompt text.
- Everything the agent's tools print is sent to the model provider. Confirm your agreement with the provider covers any personal data or PHI the tests may reach (methodology Section 8). In white-box mode, give the agent collector output only after the redaction review in whitebox-audit.md.

---

```text
You are running a security assessment using the checklists in this repository.
Follow assessment-methodology.md exactly. If this prompt and that file conflict,
stop and ask.

## Parameters
TARGET:             {TARGET}
MODE:               {MODE}   (black-box | grey-box | white-box)
AUTHORISATION_REF:  {AUTHORISATION_REF}
IN_SCOPE:           {IN_SCOPE}
OUT_OF_SCOPE:       {OUT_OF_SCOPE}
ENVIRONMENTS:       {ENVIRONMENTS}   (name: allowed tests, e.g. "production: read-only")
TEST_WINDOW:        {TEST_WINDOW}    (UTC)
STACK:              {STACK}          (e.g. "PHP 8.x Laravel, React, nginx, Cloudflare")
CREDENTIALS:        {CREDENTIAL_ENV_VARS}  (env var names only, e.g. TEST_USER_TOKEN)
EMERGENCY_CONTACT:  {EMERGENCY_CONTACT}
OUTPUT_FILE:        {OUTPUT_FILE}    (e.g. reports/2026-11-assessment.md)

## Hard rules (never break these)
1. READ-ONLY. Do not modify, create, or delete anything on the target. Do not
   apply fixes. Do not run: rm -rf, DROP, DELETE, TRUNCATE, UPDATE, INSERT,
   docker system prune, git push, mass downloads (wget -r, aws s3 sync,
   mysqldump, pg_dump), or any request with limit/page_size above 1.
2. SCOPE. Only touch assets in IN_SCOPE. If a hostname, IP, bucket, or API is
   not listed, do not send it any request. Ask instead.
3. RATE. Max 2 requests per second per host. nmap at -T3 --max-rate 50.
   Brute-force or rate-limit tests: at most 30 requests, only against test
   accounts in CREDENTIALS, then stop.
4. DATA. Prove access with counts, field names, and at most ONE record,
   redacted before you print it. Never save raw responses containing personal
   data, health data, payment data, or secrets.
5. STOP CONDITIONS. Stop all testing, print "STOP: <reason>", and wait for me if:
   - you reach personal data, health data (PHI), or a live credential/token
   - the target slows down or starts returning errors you did not cause on purpose
   - you see signs of an existing compromise
   - the next step would touch an out-of-scope asset or modify data
   For PHI or credentials, also record: URL/path, UTC timestamp, count, field
   names, and remind me to notify EMERGENCY_CONTACT now.
6. CREDENTIALS FOUND. Prove validity with one harmless call (e.g. GET /me,
   aws sts get-caller-identity) and nothing more. Never print the value; show
   the first 4 characters and the length only.
7. NO SECRETS IN OUTPUT. Redact tokens, keys, passwords, personal data in
   everything you write, including the report and your own messages.
8. EVIDENCE OR NOTHING. Every finding must cite the guide, section, and item it
   tests, plus the exact command and redacted output that proves it. If you
   cannot prove it, list it under "Unconfirmed" in Method, not as a finding.

## Procedure
Step 0. Confirm parameters. Print the scope list, mode, window, and rules back
        to me in 10 lines or fewer. Wait for "go".
Step 1. Inventory. Build a version inventory first (runtime, framework, web
        server, CMS, plugins, JS libraries, OS, images) using
        vulnerability-intelligence.md. For each item: version, source of the
        version, EOL status, matched CVEs, KEV listed (yes/no), EPSS score.
Step 2. Walk the guides in this order. Skip a guide only if it does not apply to
        STACK, and record it as N/A in coverage:
          1. linux-server-hardening.md
          2. cloudflare-hardening.md
          3. legacy-hosting-apache.md
          4. local-to-production-checklist.md
          5. wordpress-server-hardening.md
          6. php-application-hardening.md
          7. php-version-upgrade-path.md
          8. frontend-security.md
          9. access-control-and-api-security.md
         10. vulnerability-intelligence.md (results from Step 1)
         11. security-audit-automation.md
         12. incident-response-checklist.md (readiness only)
         13. disaster-recovery.md (readiness only)
         14. whitebox-audit.md (white-box mode only)
        For each checklist item record PASS, FAIL, N/A, or Not testable.
        Use the coverage-by-mode table in assessment-methodology.md Section 3:
        an item your MODE cannot reach is "Not testable", never PASS.
Step 3. Categorise each FAIL into exactly one category:
        Misconfiguration | Access control and secrets | Outdated or EOL component
        | Code-level vulnerability | Detection/response gap
        If "Outdated or EOL component" is zero, re-check Step 1 before going on.
Step 4. Rate each finding with assessment-methodology.md Section 5:
        CVSS v4.0 base vector and score (label CVSS-B), then adjust for KEV,
        EPSS, exposure, data sensitivity, chaining, then apply policy overrides.
        Write a one-line rationale naming every adjustment. If a scanner rated
        it, record the scanner rating and why yours differs.
Step 5. Chain check. List any findings that combine into a worse outcome and
        re-rate them.
Step 6. Write the report to OUTPUT_FILE using the template in
        assessment-methodology.md Section 6, with every section filled. Each
        finding block must include: ID, title, category, severity + rationale,
        affected assets, redacted evidence, checklist reference, remediation
        with effort (S/M/L/XL), verification command, status (Open), owner
        (blank), retest date (blank).
Step 7. Print to me, in this order:
        a) Findings per category x severity:
           | Category | Critical | High | Medium | Low | Info | Total |
           (all five categories, plus a Total row)
        b) Findings per environment x severity (same columns).
        c) Coverage per guide:
           | Guide | PASS | FAIL | N/A | Not testable |
        d) The top 5 actions in fix order (methodology Section 7: credentials
           and session invalidation first, then KEV, then Critical).
        e) Stop conditions triggered, if any, and data reached (counts only).
        f) Anything you were unsure about.

## Style
Be terse. No speculation presented as fact. When a check fails to run, say so
and mark the item Not testable with the reason. Do not propose code changes
unless I ask for a fix pass.
```

---

## Optional: fix pass

Run only after the report is reviewed, on a non-production environment first, with a human approving each change:

```text
Using {OUTPUT_FILE}, propose a fix for finding {FINDING_ID} only. Show the diff,
why it fixes the checklist item, how to roll it back, and the verification
command. Do not apply it until I reply "apply {FINDING_ID}". After applying, run
the verification command and append the result to the retest log.
```

---

*Last reviewed: 2026-11 | Applies to: Claude Code and similar AI coding agents running assessments with these checklists*
