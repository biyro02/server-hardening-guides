# Access Control and API Security

**Who can reach what, with which credential: authorization testing, unauthenticated surface, shared secrets, BaaS, sessions, CORS, database privileges, email spoofing, and rate limiting**

> **Only test systems you own or have written authorisation to test.** Every command in this guide sends real requests. Agree scope, time windows, and data handling first: see [assessment-methodology.md, Rules of Engagement](assessment-methodology.md#1-rules-of-engagement) and [Data Handling During Testing](assessment-methodology.md#2-data-handling-during-testing). Third-party platforms (BaaS, CDN, email providers) have their own testing policies; your client's permission does not cover them.

> This guide exists because of one assessment. A multi-environment healthcare SaaS was checked against the other guides in this repo and produced 60 findings: 39 misconfiguration and 19 access control or exposed secrets. Seven of the ten criticals were access control: a Parse Server readable with only the public application id (users, conversations), a master key in client HTML that allowed session token theft, a static "API password" header compiled into the JS bundle, pre-auth endpoints returning configuration, internal AI services and API docs reachable from the internet, CORS `*` on an API authenticated by custom headers, no rate limiting or lockout, and MD5 in the auth path. Email authentication (DMARC `p=none`, SPF `~all`, no CAA) failed in every environment. None of these needed an exploit. They needed someone to ask "what happens if I send this request as somebody else, or as nobody?"

---

## Table of Contents

1. [Authorization Model Testing (BOLA, BFLA, Property Level)](#1-authorization-model-testing-bola-bfla-property-level)
2. [Unauthenticated Surface Inventory](#2-unauthenticated-surface-inventory)
3. [Static Shared Secrets and Client-Side Credentials](#3-static-shared-secrets-and-client-side-credentials)
4. [BaaS Exposure (Parse Server, Firebase, Supabase)](#4-baas-exposure-parse-server-firebase-supabase)
5. [Session and Token Hygiene](#5-session-and-token-hygiene)
6. [CORS and Headers for APIs](#6-cors-and-headers-for-apis)
7. [Database Least Privilege](#7-database-least-privilege)
8. [Domain and Email Authentication](#8-domain-and-email-authentication)
9. [Rate Limiting and Abuse](#9-rate-limiting-and-abuse)

References used throughout: [OWASP API Security Top 10 2023](https://owasp.org/API-Security/editions/2023/en/0x11-t10/) (API1 BOLA, API2 Broken Authentication, API3 Broken Object Property Level Authorization, API4 Unrestricted Resource Consumption, API5 BFLA, API8 Security Misconfiguration, API9 Improper Inventory Management).

---

## 1. Authorization Model Testing (BOLA, BFLA, Property Level)

> Authentication answers "who are you". Authorization answers "may you touch this object, call this function, set this field". Scanners cannot test the second question because they do not know who owns what. You need at least two accounts and a list of IDs.

**Set up the test identities.** Minimum: two users in tenant A with different roles (`A-admin`, `A-user`), one user in tenant B (`B-user`), and no session at all (`anon`). Create one object of each important type as `A-user` and record its ID.

```bash
# Put tokens in environment variables, never in shell history files you will share
export API=https://api.staging.example.com
export TA=...   # A-user token
export TAA=...  # A-admin token
export TB=...   # B-user token
export OBJ=1234 # an object owned by A-user
```

- [ ] **Test BOLA / IDOR (API1): every object ID in a path, query, body, or header must be checked against the caller.** Replay A's request with B's token. The correct answer is `404` (or `403`); a `200` with A's data is a critical finding.

  ```bash
  # Baseline: owner can read it
  curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $TA" "$API/v1/patients/$OBJ"
  # Swap the caller: other tenant must not
  curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $TB" "$API/v1/patients/$OBJ"
  # Same object via nested route under the attacker's own parent
  curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $TB" "$API/v1/accounts/<B-account-id>/patients/$OBJ"
  # Tenant selected by header or body: change it, keep your own token. One record, owners only, no content
  curl -s -H "Authorization: Bearer $TB" -H "X-Tenant-Id: <A-tenant-id>" "$API/v1/patients?limit=1" \
    | jq '{returned: (.data | length), tenants: ([.data[]?.account_id] | unique)}'
  # Write paths matter more than reads. Only against objects your test identities created, never production
  curl -s -o /dev/null -w '%{http_code}\n' -X PATCH -H "Authorization: Bearer $TB" \
    -H 'Content-Type: application/json' -d '{"note":"bola-test"}' "$API/v1/patients/$OBJ"
  ```

  Do not stop at the obvious `GET /things/{id}`. The routes that usually miss the check are bulk and export endpoints (`POST /export` with an ID list), file downloads by key, report generators, search with an `account_id` filter, "related" lookups (`/patients/{id}/notes`), and IDs inside JSON bodies.

- [ ] **Test BFLA (API5): every privileged function must check the role, not just the session.** Call admin functions as a normal user, change the HTTP method, and try method override headers.

  ```bash
  # Admin route as a normal user
  curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $TA" "$API/v1/admin/users"
  # Method switch: GET is checked, DELETE sometimes is not.
  # <other-user-id> must be a throwaway test user you created: if the check is missing, it is deleted
  curl -s -o /dev/null -w '%{http_code}\n' -X DELETE -H "Authorization: Bearer $TA" "$API/v1/users/<other-user-id>"
  # Method override (some frameworks honour these)
  curl -s -o /dev/null -w '%{http_code}\n' -X POST -H "X-HTTP-Method-Override: DELETE" \
    -H "Authorization: Bearer $TA" "$API/v1/users/<other-user-id>"
  ```

- [ ] **Test object property level authorization (API3) in both directions.** Inbound: can the caller set fields it should not (`role`, `account_id`, `is_verified`, `owner_id`, `price`)? Outbound: does the response include fields the caller should not see (password hash, MFA secret, internal flags, other users' email)?

  ```bash
  # Inbound: mass assignment of privileged fields (on your own test account, outside production)
  curl -s -X PATCH -H "Authorization: Bearer $TA" -H 'Content-Type: application/json' \
    -d '{"name":"x","role":"admin","account_id":<B-account-id>,"is_verified":1}' "$API/v1/me"
  curl -s -H "Authorization: Bearer $TA" "$API/v1/me" | jq '{role, account_id, is_verified}'

  # Outbound: look for fields that should never leave the server
  curl -s -H "Authorization: Bearer $TA" "$API/v1/users/me" \
    | jq 'paths(scalars) | join(".")' | grep -iE 'password|hash|secret|mfa|totp|token|salt'
  ```

  For Laravel specifics (`$fillable`, `$request->merge()` pitfalls) see [php-application-hardening.md, Mass Assignment](php-application-hardening.md#mass-assignment) and [request()->merge() Feeding create()](php-application-hardening.md#request-merge-feeding-create).

- [ ] **Automate it as an authorization matrix test.** Manual testing finds the first bug; a matrix in CI stops the next one. List each route, each identity, and the expected status. New routes without a row fail the build (see Section 2).

  ```php
  // tests/Feature/AuthorizationMatrixTest.php (Pest)
  dataset('matrix', [
      // [method, uri-template, actor, expected status]
      ['GET',    '/v1/patients/{a_patient}', 'a_user',  200],
      ['GET',    '/v1/patients/{a_patient}', 'b_user',  404],
      ['GET',    '/v1/patients/{a_patient}', 'anon',    401],
      ['PATCH',  '/v1/patients/{a_patient}', 'b_user',  404],
      ['GET',    '/v1/admin/users',          'a_user',  403],
      ['GET',    '/v1/admin/users',          'a_admin', 200],
  ]);

  it('enforces the authorization matrix', function (string $method, string $uri, string $actor, int $status) {
      $fx = authzFixtures();                          // creates tenants, users, objects once
      $uri = strtr($uri, $fx->placeholders());        // {a_patient} becomes a real id
      $req = $actor === 'anon' ? $this : $this->actingAs($fx->user($actor), 'sanctum');
      $req->json($method, $uri)->assertStatus($status);
  })->with('matrix');
  ```

**Fix in Laravel.** Resolve objects through the caller's scope, then authorize with a policy. Either alone is fragile.

```php
// Scoped query: an ID from another tenant simply does not exist for this caller (404)
$patient = $request->user()->account->patients()->findOrFail($id);

// Policy for role and ownership rules (Laravel 11+: base controller has no authorize() helper)
use Illuminate\Support\Facades\Gate;
Gate::authorize('update', $patient);

// Nested route model binding: child must belong to parent
Route::scopeBindings()->group(function () {
    Route::get('/accounts/{account}/patients/{patient}', [PatientController::class, 'show']);
});

// Admin functions: gate the whole group, not each method
Route::middleware(['auth:sanctum', 'can:admin'])->prefix('v1/admin')->group(/* ... */);

// Outbound: return an API Resource with an explicit field list, never the raw model
return new PatientResource($patient);
```

**Fix in any stack.** Derive the tenant from the authenticated principal, never from a header, query parameter, or body field. Put the ownership filter in one place (repository, query scope, row-level security) so a new endpoint inherits it. Use non-sequential public IDs (UUIDv7, ULID) as defence in depth only; unguessable IDs do not replace the check, because IDs leak through URLs, logs, and exports.

**How to verify**

```bash
# Run the matrix suite
php artisan test --filter=AuthorizationMatrix

# Laravel: find controllers that load models by raw id without scoping
grep -rnE "::(find|findOrFail)\(\\\$(id|request)|::where\(.id.,[[:space:]]*\\\$" app/Http/Controllers | head -50
# Each hit must either be scoped through the user/tenant or followed by Gate::authorize / policy
```

**Common mistakes**

- Checking that the user is logged in and calling that authorization.
- Returning `403` for other tenants' objects. It confirms the ID exists; prefer `404`.
- Tenant ID taken from a request header "because the frontend always sends the right one".
- A global tenant scope that is bypassed by `withoutGlobalScopes()`, `DB::table()`, raw SQL, or queue jobs that run without a user.
- Testing only reads. Updates, deletes, exports, and file downloads are where BOLA hurts most.

---

## 2. Unauthenticated Surface Inventory

> Every route that answers without a session is part of your public API whether you documented it or not (OWASP API9, Improper Inventory Management). In the assessment above, the unauthenticated surface included full interactive API docs, configuration endpoints returning keys, and internal AI services. Nobody had decided to publish them; nobody had decided not to.

- [ ] **Rule: every endpoint reachable without authentication has a written justification.** Keep a file in the repo listing each public route, why it is public, and who approved it. CI fails if a route without auth middleware is not on the list.

  ```yaml
  # security/public-endpoints.yml
  - route: "POST /v1/auth/login"
    reason: "Login"
    owner: "backend lead"
  - route: "GET /up"
    reason: "Load balancer health check, returns 200 with empty body"
    owner: "ops"
  ```

- [ ] **List routes from the code, not from memory.** In Laravel, filter routes that carry no auth middleware. The JSON `middleware` field holds resolved class names (`Illuminate\Auth\Middleware\Authenticate:sanctum`, `Illuminate\Routing\Middleware\ValidateSignature`), not aliases, so match case-insensitively and add your own auth middleware class names to the pattern.

  ```bash
  php artisan route:list --json --except-vendor \
    | jq -r '.[] | select((.middleware // []) | map(test("authenticate|validatesignature|^auth"; "i")) | any | not)
             | "\(.method)\t\(.uri)"'
  # Also check vendor routes (docs, debug tools, dashboards): run again without --except-vendor
  ```

  Other stacks: Symfony `bin/console debug:router` plus `access_control`; Express/Fastify: grep router registrations and compare with the auth middleware order; Next.js: list `app/api/**/route.*` and `pages/api/**`.

- [ ] **Probe the known-dangerous paths on every environment, not just production.** Staging and test hosts are usually less protected and often share data or credentials.

  ```bash
  # Run only against hosts in your authorised scope
  for p in docs api/documentation swagger-ui.html swagger/index.html openapi.json openapi.yaml \
           v3/api-docs api-docs graphql graphiql playground health healthz status metrics \
           actuator actuator/env config api/config settings init feature-flags \
           telescope horizon _debugbar/open _ignition/health-check phpinfo.php info.php \
           server-status .env .git/HEAD admin adminer.php phpmyadmin/ ; do
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "https://api.staging.example.com/$p")
    [ "$code" != "404" ] && echo "$code  /$p"
  done
  ```

- [ ] **Treat API documentation as an internal tool.** Swagger UI, Scribe (`/docs`), L5-Swagger (`/api/documentation`), and Redoc give an attacker a complete, typed map including deprecated and admin routes. Publish docs behind auth or as a static artifact built from a filtered spec.

- [ ] **Disable GraphQL introspection and IDEs in production.**

  ```bash
  curl -s -X POST -H 'Content-Type: application/json' \
    -d '{"query":"{__schema{queryType{name} types{name}}}"}' https://api.example.com/graphql | head -c 300
  # Expected: an error, not a type list
  ```

- [ ] **Health and config endpoints return the minimum.** A health check returns `200` and nothing else. A pre-auth config endpoint (feature flags, SSO settings, mobile bootstrap) returns only values that are safe to publish on a billboard. Grep the response for `key`, `secret`, `token`, `password`, `dsn`, `host`.

  ```bash
  # Print key paths with only the first 4 characters and the length of each value
  curl -s https://api.example.com/api/config \
    | jq -r 'paths(scalars) as $p | (getpath($p) | tostring) as $v | "\($p|join(".")) = \($v[0:4])... (\($v|length) chars)"' \
    | grep -iE 'key|secret|token|pass|dsn|host|bucket|internal'
  ```

- [ ] **Internal services are not on the internet.** Model inference APIs, notebook servers, vector databases, admin panels, queue dashboards, and metrics exporters must bind to a private network or sit behind authentication at the proxy. Common defaults to look for: `11434` (Ollama), `8888` (Jupyter), `7860` / `8501` (Gradio / Streamlit demos), `6333` (Qdrant), `9090` (Prometheus), `15672` (RabbitMQ management), `5601` (Kibana).

  ```bash
  # Authorised hosts only; polite rate
  nmap -T3 --max-rate 50 -Pn -p 80,443,3000,5000,5601,6333,7860,8000,8080,8443,8501,8888,9090,11434,15672 app.example.com
  ```

- [ ] **Find every host before testing paths.** Certificate transparency lists hostnames you forgot (see [local-to-production-checklist.md, DNS Security](local-to-production-checklist.md#11-dns-security)). Probe what answers with a rate-limited HTTP prober, then run content discovery only on in-scope hosts.

  ```bash
  curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq -r '.[].name_value' | sort -u > hosts.txt
  # Review hosts.txt against your scope list BEFORE the next commands
  httpx -l hosts.txt -status-code -title -tech-detect -rate-limit 5 -silent
  ffuf -u https://staging.example.com/FUZZ -w /path/to/wordlist.txt -rate 5 -mc all -fc 404
  ```

**How to verify**

```bash
# CI gate: every public route must be in the justification file
php artisan route:list --json \
  | jq -r '.[] | select((.middleware // []) | map(test("authenticate|validatesignature|^auth"; "i")) | any | not)
           | "\(.method | split("|")[0]) /\(.uri | ltrimstr("/"))"' \
  | sort > /tmp/public-actual.txt
yq -r '.[].route' security/public-endpoints.yml | sort > /tmp/public-approved.txt
comm -23 /tmp/public-actual.txt /tmp/public-approved.txt   # must print nothing
```

**Common mistakes**

- Removing docs from navigation but leaving the route live.
- Assuming staging is private because nobody links to it. Certificate transparency publishes every hostname that got a certificate.
- Protecting `/admin` in the web app but not the API routes the admin UI calls.
- Debug tools enabled by environment variable on a "temporary" preprod that then gets production data. See [php-application-hardening.md, Telescope and Horizon Without Auth](php-application-hardening.md#telescope-and-horizon-without-auth).
- Probing with a scanner that follows redirects to the login page and reports `200` for everything. Check the final body, not only the status.

---

## 3. Static Shared Secrets and Client-Side Credentials

> A secret that ships to the browser or the mobile app is not a secret. An "API password" header that every client sends, a BaaS master key in a `<script>` block, or a vendor key in a `VITE_` variable authenticates the application, not the user, and anyone can download the application. Treat it as equivalent to no authentication.

The general rules for frontend secrets and source maps are in [frontend-security.md, Secrets in Client-Side Code](frontend-security.md#secrets-in-client-side-code) and [Source Maps in Production](frontend-security.md#source-maps-in-production). The server-side pattern of rendering a master key into HTML is in [local-to-production-checklist.md, Secrets Audit](local-to-production-checklist.md#3-pre-deploy-secrets-audit). This section covers detection on a live target and the remediation order.

- [ ] **Replace static shared headers with per-user credentials.** If the API accepts `X-Api-Pass: <same value for everyone>` as its only gate for some routes, those routes are public. Move them behind the same session, OAuth, or token auth as the rest, or make them genuinely public and justify them (Section 2).

  > **Why this matters:** combined with `Access-Control-Allow-Origin: *` and `Access-Control-Allow-Headers` that include the custom header, any website can call your API from a visitor's browser. Combined with no rate limiting, anyone can call it from a script. The header adds nothing that an attacker does not already have.

- [ ] **If a client must identify itself (mobile app id, BaaS application id), treat that value as public.** Design as if it were printed on the login page. Authorization must hold with only that value known.

- [ ] **Scan what you actually serve, not only the repository.** Build-time injection means the repo can be clean while the bundle is not.

  ```bash
  # Download the live entry page and every script it references (authorised target)
  mkdir -p live && cd live
  curl -s https://app.example.com/ -o index.html
  grep -oE '(src|href)="[^"]+\.js"' index.html | cut -d'"' -f2 | while read -r s; do
    curl -s "https://app.example.com/${s#/}" -o "$(basename "$s")"
    curl -s -o /dev/null -w "%{http_code}  ${s}.map\n" "https://app.example.com/${s#/}.map"
  done
  grep -HoiE '(api[-_]?pass(word)?|master[-_]?key|service[-_]?role|secret|x-api-key)["'\'' :=]+[^"'\'' ,]{6,}' *.js index.html
  ```

- [ ] **Run a secrets scanner on the full git history and on the build output.** Current syntax (verify with `--help` on your installed version, flags changed recently):

  ```bash
  # gitleaks v8.19+: 'detect' and 'protect' are deprecated in favour of 'git' and 'dir'
  gitleaks git -v .                 # full history of the repo in the current directory
  gitleaks dir -v dist/             # built assets, including .map files

  # trufflehog v3: --results replaces the older --only-verified
  trufflehog git file://. --results=verified,unknown
  trufflehog filesystem dist/ --results=verified,unknown
  ```

  Note: older commands in other guides in this repo (`gitleaks detect`, `trufflehog --only-verified`) still run on many versions but are deprecated.

  > **Verification uses the credential.** trufflehog verifies a finding by calling the provider's API with it. On a client's repository or bundle that is use of a found credential, so it must be covered by the authorisation (one harmless call per secret, see [assessment-methodology.md](assessment-methodology.md#2-data-handling-during-testing)); otherwise run with `--no-verification` and report the secrets as unverified.

- [ ] **Check mobile builds too.** An Android APK is a zip; `unzip -p app.apk 'assets/*' | strings | grep -iE 'key|secret|pass'` and the same patterns on `classes*.dex` find most embedded credentials. React Native bundles live in `assets/index.android.bundle`.

**Remediation order when a server-side secret was exposed**

1. **Rotate.** Issue a new secret and make the old one stop working everywhere (API, BaaS, workers, integrations). Removing it from the frontend without rotating it changes nothing: it is already in caches, archives, and attacker notes.
2. **Invalidate sessions and tokens.** Anything issued or readable while the secret was exposed is suspect. For a BaaS master key that means every row in the session table (Section 4). For an app signing key it means every token it signed.
3. **Review use of the old secret.** Search access logs for requests carrying it from unexpected IPs or user agents during the exposure window. See [incident-response-checklist.md, Credential Rotation](incident-response-checklist.md#7-credential-rotation).
4. **Remove it from history last.** `git filter-repo` and a force push stop future clones from carrying it, but do not un-leak it. Doing this first gives a false sense of closure and destroys evidence you need for step 3.

**How to verify**

```bash
# Old secret must be rejected
curl -s -o /dev/null -w '%{http_code}\n' -H "X-Api-Pass: <old value>" https://api.example.com/v1/<route>
# Route must still require a user
curl -s -o /dev/null -w '%{http_code}\n' -H "X-Api-Pass: <new value>" https://api.example.com/v1/<route>   # expect 401
# Bundle and maps clean
gitleaks dir -v live/ && echo "bundle clean"
```

**Common mistakes**

- "It is obfuscated." Minifiers and obfuscators do not hide string literals.
- Moving the secret from the JS bundle to a pre-auth `/config` endpoint the JS fetches at startup.
- Rotating the key but leaving existing sessions alive.
- Rewriting git history and announcing the incident closed.

---

## 4. BaaS Exposure (Parse Server, Firebase, Supabase)

> Backend-as-a-service platforms are designed to be called directly from the client with a public key. That is safe only when every table, class, and bucket has server-enforced rules. The default for many projects created in a hurry is "readable by anyone with the public key". The server-side key audit is in [local-to-production-checklist.md, Secrets Audit](local-to-production-checklist.md#3-pre-deploy-secrets-audit); this section is about testing the rules from the attacker's position.

- [ ] **Test with only the public key, the way an attacker would.** Take the values from the shipped bundle, nothing else. If you can list users, sessions, messages, or business records, the rules are broken regardless of what the dashboard says.

  ```bash
  # Parse Server: application id only (plus client/JS key if the server requires one)
  P=https://parse.example.com/parse; APPID=<from bundle>
  for c in _User _Session _Role _Installation Conversation Message; do
    printf '%-14s ' "$c"
    curl -s -H "X-Parse-Application-Id: $APPID" "$P/classes/$c?limit=1&count=1" \
      | jq -c '{code, error, count, fields: (.results[0] // {} | keys)}'
  done
  # Expected for sensitive classes: {"code":119,...} permission denied, or an empty result.
  # Never print the record itself: a readable _Session row contains a live sessionToken.

  # Firebase Realtime Database
  curl -s "https://<project>-default-rtdb.firebaseio.com/.json?shallow=true"      # expect "Permission denied"
  # Cloud Firestore REST, unauthenticated (field names only)
  curl -s "https://firestore.googleapis.com/v1/projects/<project>/databases/(default)/documents/users?pageSize=1" \
    | jq '{error: .error.status, fields: (.documents[0].fields // {} | keys)}'
  # Firebase Storage bucket listing (object names can be personal data: count only)
  curl -s "https://firebasestorage.googleapis.com/v0/b/<project>.appspot.com/o?maxResults=1" \
    | jq '{error: .error.code, listed: (.items // [] | length)}'

  # Supabase: publishable (sb_publishable_...) or legacy anon key (field names only)
  curl -s "https://<ref>.supabase.co/rest/v1/profiles?select=*&limit=1" -H "apikey: $SUPA_PUBLISHABLE" \
    | jq 'if type == "array" then {returned: length, fields: (.[0] // {} | keys)} else . end'
  ```

- [ ] **Parse Server: lock down at three levels.** Class-Level Permissions on every class (deny public `find`, `get`, `count`, `create` where not needed), ACLs on every object, and server options:

  ```js
  // Parse Server options (verify names against your version's Definitions)
  {
    masterKeyIps: ['127.0.0.1', '::1'],   // default since 6.x; never widen to 0.0.0.0/0
    allowClientClassCreation: false,      // set explicitly
    enforcePrivateUsers: true,            // _User not publicly readable; set explicitly
    // the master key never leaves server env; Parse Dashboard runs on a private network
  }
  ```

  > **Why this matters:** with the master key, `GET /classes/_Session` returns every live `sessionToken`. Any of those tokens sent as `X-Parse-Session-Token` acts as that user, including admins. Rotating the master key does not revoke them: delete the session rows too.

- [ ] **Firebase: rules are the only access control.** The web API key identifies the project and is not secret. Search rules for `allow read, write: if true;` and for time-boxed test-mode rules (`request.time < timestamp.date(...)`) that someone extended instead of replacing. Scope reads to `request.auth.uid` and validate writes with `request.resource.data`. Use App Check as abuse reduction, not as authorization.

- [ ] **Supabase: RLS on every table in an exposed schema, policies that reference `auth.uid()`, and the secret key server-only.** The `sb_secret_...` key (and the legacy `service_role` key) bypasses RLS entirely. Supabase is retiring the legacy JWT keys; when migrating, disable the old ones after the new keys are deployed or both remain valid.

  ```sql
  -- Tables in exposed schemas without RLS (run as an admin role)
  SELECT schemaname, tablename FROM pg_tables
  WHERE schemaname IN ('public') AND NOT rowsecurity;

  -- Views run as their owner and bypass RLS unless security_invoker is set (PostgreSQL 15+)
  SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = 'public' AND c.relkind = 'v'
    AND NOT coalesce(array_to_string(c.reloptions, ',') ~* 'security_invoker=(true|on|1|yes)', false);
  ```

- [ ] **Buckets and file storage follow the same rules.** Public bucket listing exposes uploads (photos, documents) even when the database is locked.

**How to verify:** rerun the public-key commands above after every rules change and in CI against staging. Expected for every sensitive collection: permission denied or empty. Keep the output as evidence.

**Common mistakes**

- Locking `_User` but not `_Session`, or not the custom classes holding the actual data.
- Testing rules while logged in to the dashboard (which uses admin credentials).
- Fixing rules in production but not in staging, which often runs on a copy of production data.
- Assuming "requires a valid user session" is enough: any self-registered user then reads everything.

---

## 5. Session and Token Hygiene

> OWASP API2 (Broken Authentication). Most findings here are not exotic: tokens that never expire, sessions that survive a password change, login endpoints without throttling, and legacy hash functions.

- [ ] **Invalidate sessions on password change, password reset, MFA change, and role removal.** The user who changes a password after a compromise expects the attacker to be logged out.

  ```php
  // Laravel web sessions: requires the auth.session (AuthenticateSession) middleware on those routes
  Auth::logoutOtherDevices($request->input('password'));
  // Sanctum / personal access tokens
  $user->tokens()->delete();
  // Stateless JWT: include a per-user version claim and bump it, or keep a denylist until expiry
  $user->increment('token_version');
  ```

- [ ] **Invalidate sessions when signing or encryption keys rotate.** Rotating `APP_KEY`, a JWT signing key, or a BaaS master key is not finished until tokens signed or readable under the old key are gone. Laravel 11+ supports `APP_PREVIOUS_KEYS` for graceful decryption; use it for data, not as a reason to keep old sessions.

- [ ] **Set explicit lifetimes.** Short access tokens (minutes to an hour), refresh tokens with rotation and reuse detection, and an absolute session maximum. Sanctum's `expiration` defaults to `null` (tokens never expire): set it.

  ```php
  // config/sanctum.php
  'expiration' => 60 * 24,      // minutes
  // config/session.php
  'lifetime' => 60, 'expire_on_close' => false, 'secure' => true, 'http_only' => true, 'same_site' => 'lax',
  ```

- [ ] **Provide server-side revocation.** A user and an admin can list active sessions and revoke one or all. If you cannot revoke a token, you cannot respond to an incident.

- [ ] **Throttle and lock out per account and per IP.** Per-IP limits stop one machine; per-account limits stop a botnet guessing one password. Use progressive delays or temporary locks, not permanent lockout, which becomes a denial-of-service tool. NIST SP 800-63B caps consecutive failed attempts on one account at 100 as an upper bound; most applications should be far lower.

  ```php
  // app/Providers/AppServiceProvider.php (Laravel 11+)
  RateLimiter::for('login', function (Request $request) {
      $email = Str::lower((string) $request->input('email'));
      return [
          Limit::perMinute(5)->by('acct:'.$email),            // per account
          Limit::perMinute(20)->by('ip:'.$request->ip()),     // per IP
      ];
  });
  // routes: ->middleware('throttle:login') on login, password reset, MFA verify, OTP send
  ```

- [ ] **Credential stuffing needs more than lockout.** Reject known-breached passwords at registration and change (`Password::min(12)->uncompromised()` in Laravel), alert on many accounts failing from one source, and require MFA for anything privileged.

- [ ] **MFA is mandatory for admin and support roles,** and the MFA verify endpoint has its own throttle. A 6-digit code with no rate limit falls to brute force.

- [ ] **Hash passwords with Argon2id or bcrypt only.** OWASP Password Storage Cheat Sheet: Argon2id with at least 19 MiB memory, 2 iterations, parallelism 1; bcrypt with cost at least 10 and passwords capped at 72 bytes. MD5, SHA1, and unsalted or single-round SHA-256 are findings even when "only used for the legacy check".

  ```php
  $hash = password_hash($password, PASSWORD_ARGON2ID);    // or PASSWORD_BCRYPT / Hash::make()
  if (password_verify($password, $hash) && password_needs_rehash($hash, PASSWORD_ARGON2ID)) {
      // store the new hash
  }
  ```

  **Migrating from MD5 without a forced reset:** wrap existing hashes once (`password_hash(md5_hex, ...)`), mark them, verify legacy users with `password_verify(md5($input), $stored)`, then rehash with the plain password on next successful login and clear the marker. No MD5 value remains at rest after the one-time migration.

- [ ] **Compare secrets in constant time and never with `==`.** See [php-application-hardening.md, Timing Attacks on Hash Comparison](php-application-hardening.md#timing-attacks-on-hash-comparison) and [Type Juggling and Loose Comparison](php-application-hardening.md#type-juggling-and-loose-comparison).

- [ ] **Do not reveal which part failed.** Login, password reset, and registration return the same message and similar timing whether or not the account exists.

**How to verify**

```bash
# Session survives password change? (should be 401 afterwards)
OLD=$TA
curl -s -X POST -H "Authorization: Bearer $TA" -H 'Content-Type: application/json' \
  -d '{"current_password":"...","password":"...","password_confirmation":"..."}' "$API/v1/me/password"
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $OLD" "$API/v1/me"

# Token lifetime: decode a JWT and read exp (no verification, inspection only)
cut -d. -f2 <<<"$TA" | tr '_-' '/+' | base64 -d 2>/dev/null | jq '{iat, exp}'

# Hash algorithms at rest (MySQL example; adjust table and column)
SELECT LEFT(password,4) AS prefix, LENGTH(password) AS len, COUNT(*) FROM users GROUP BY 1,2;
-- $2y$ = bcrypt, $arg = argon2; 32-char hex = MD5; 40-char hex = SHA1
```

**Common mistakes**

- Logging out "other devices" on the web while mobile API tokens stay valid.
- JWTs with a 30-day `exp` and no revocation path.
- Lockout keyed only by IP behind a proxy, so every user shares one counter (Section 9).
- `md5($password . $salt)` described as "salted, therefore fine".

---

## 6. CORS and Headers for APIs

> The browser-side explanation of CORS misconfiguration is in [frontend-security.md, CORS Misconfiguration](frontend-security.md#cors-misconfiguration). This section covers what the API server must send and how to test it. Remember that CORS only constrains browsers: it is not access control, and `curl` ignores it entirely.

- [ ] **Use an exact allowlist of origins.** No `*` on any endpoint that is authenticated by cookies or by headers the browser can be made to send. No reflection of the request `Origin`. No regex that matches `example.com.attacker.net` or `attackerexample.com`. Reject `Origin: null`.

  ```php
  // config/cors.php (Laravel)
  'paths' => ['api/*', 'sanctum/csrf-cookie'],
  'allowed_origins' => ['https://app.example.com', 'https://admin.example.com'],
  'allowed_origins_patterns' => [],          // avoid; if used, anchor with ^ and $
  'allowed_methods' => ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
  'allowed_headers' => ['Content-Type', 'Authorization', 'X-Requested-With', 'X-XSRF-TOKEN'],
  'supports_credentials' => true,
  'max_age' => 600,
  ```

  ```nginx
  # nginx, if CORS is handled at the proxy: exact matches only
  map $http_origin $cors_origin {
      default                       "";
      "https://app.example.com"     $http_origin;
      "https://admin.example.com"   $http_origin;
  }
  add_header Access-Control-Allow-Origin $cors_origin always;
  add_header Vary Origin always;
  ```

- [ ] **Handle preflight deliberately.** `OPTIONS` must not require auth (browsers do not send it) and must not reach business logic. Return the allowed methods and headers only for allowlisted origins.

- [ ] **Send `Vary: Origin`** whenever the CORS response depends on the origin, or a cache will serve one origin's headers to another.

- [ ] **Security headers on every response, including errors.** `401`, `403`, `404`, `405`, `429`, and `500` responses are often generated by the proxy or the framework's exception handler and skip the middleware that adds headers. In nginx, `add_header` without `always` is dropped on error codes.

  ```nginx
  add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
  add_header X-Content-Type-Options "nosniff" always;
  add_header Cache-Control "no-store" always;     # API responses carrying personal data
  add_header Content-Security-Policy "default-src 'none'; frame-ancestors 'none'" always;   # JSON APIs
  ```

  Error bodies must be generic JSON. No stack traces, SQL, file paths, or framework banners (see [php-application-hardening.md, APP_DEBUG in Production](php-application-hardening.md#app_debug-in-production)).

**How to verify**

```bash
# Hostile origin: must not be echoed, must not get credentials
curl -s -D - -o /dev/null -H "Origin: https://evil.example" https://api.example.com/v1/me | grep -i '^access-control'
# Null origin and suffix tricks
for o in null https://app.example.com.evil.example https://evilapp.example.com; do
  echo "== $o"; curl -s -D - -o /dev/null -H "Origin: $o" https://api.example.com/v1/me | grep -i '^access-control-allow-origin'
done
# Preflight for a custom auth header
curl -s -D - -o /dev/null -X OPTIONS -H "Origin: https://evil.example" \
  -H "Access-Control-Request-Method: POST" -H "Access-Control-Request-Headers: x-api-pass" \
  https://api.example.com/v1/patients | grep -i '^access-control'
# Headers present on error responses
for u in /v1/does-not-exist /v1/me; do
  echo "== $u"; curl -s -D - -o /dev/null "https://api.example.com$u" | grep -iE '^(HTTP|strict-transport|x-content-type|cache-control)'
done
```

**Common mistakes**

- `Access-Control-Allow-Origin: *` on an API authenticated by a static header: any site can call it with the header from the public bundle.
- Allowlist checked with `str_contains` or an unanchored regex.
- `localhost` and `http://` dev origins left in the production allowlist.
- Headers configured in the app middleware only, so proxy-generated `502` and `429` responses go out bare.

---

## 7. Database Least Privilege

> If the application user can `DROP`, `GRANT`, read files, or connect from anywhere, then any SQL injection or leaked `.env` becomes full database takeover. Separate what the application needs at runtime from what migrations need at deploy time.

- [ ] **Separate the runtime user from the migration user.** The runtime user gets `SELECT, INSERT, UPDATE, DELETE` (and `EXECUTE` if you use procedures) on the application schema only. The migration user adds `CREATE, ALTER, DROP, INDEX, REFERENCES` and is used only by the deploy job.

  ```sql
  CREATE USER 'app_rt'@'10.0.1.%' IDENTIFIED BY '<generated>';
  GRANT SELECT, INSERT, UPDATE, DELETE ON appdb.* TO 'app_rt'@'10.0.1.%';

  CREATE USER 'app_migrate'@'10.0.1.%' IDENTIFIED BY '<generated>';
  GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, DROP, INDEX, REFERENCES,
        CREATE VIEW, SHOW VIEW, TRIGGER ON appdb.* TO 'app_migrate'@'10.0.1.%';
  ```

  ```bash
  # Laravel: a second connection used only by the deploy step
  php artisan migrate --force --database=mysql_migrate
  ```

- [ ] **The application user never holds `ALL PRIVILEGES`, `SUPER`, `FILE`, `PROCESS`, `GRANT OPTION`, `CREATE USER`, or `SHUTDOWN`,** and in MySQL 8 none of the dynamic admin privileges (`SYSTEM_VARIABLES_ADMIN`, `CONNECTION_ADMIN`, `BINLOG_ADMIN`, and others). `FILE` turns SQL injection into file read and write on the database host.

- [ ] **Restrict the host part.** `'app'@'%'` accepts connections from anywhere the network allows. Use the application subnet or container network. Combine with the firewall rules in [linux-server-hardening.md](linux-server-hardening.md#3-firewall-ufw--docker): the database port is not exposed publicly.

- [ ] **One set of users per environment.** Staging must not share a password with production, and a staging application must not have network reach to the production database. Read-only reporting and BI tools get their own `SELECT`-only user, scoped to the tables or views they need.

- [ ] **No anonymous users, no `root` from remote hosts, no empty passwords.**

**How to verify**

```sql
-- Who exists and from where (MySQL 8 and MariaDB)
SELECT user, host FROM mysql.user ORDER BY user, host;

-- Grants for one account
SHOW GRANTS FOR 'app_rt'@'10.0.1.%';

-- Global privileges held by anyone other than admin accounts (both engines)
SELECT GRANTEE, PRIVILEGE_TYPE, IS_GRANTABLE
FROM information_schema.USER_PRIVILEGES
WHERE PRIVILEGE_TYPE IN ('SUPER','FILE','PROCESS','SHUTDOWN','CREATE USER','RELOAD','GRANT OPTION')
   OR IS_GRANTABLE = 'YES'
ORDER BY GRANTEE;

-- Schema-level grants (look for ALL on the app schema)
SELECT GRANTEE, TABLE_SCHEMA, PRIVILEGE_TYPE FROM information_schema.SCHEMA_PRIVILEGES ORDER BY GRANTEE;

-- MySQL 8 only: dynamic privileges
SELECT USER, HOST, PRIV FROM mysql.global_grants WHERE USER NOT IN ('root','mysql.session','mysql.sys') ORDER BY USER;

-- Wildcard hosts and remote root
SELECT user, host FROM mysql.user WHERE host = '%' OR (user = 'root' AND host NOT IN ('localhost','127.0.0.1','::1'));

-- Empty passwords: MySQL 8
SELECT user, host FROM mysql.user WHERE authentication_string = '' AND account_locked = 'N';
-- Empty passwords: MariaDB 10.4+ (mysql.user is a view over mysql.global_priv)
SELECT user, host FROM mysql.user WHERE password = '' AND authentication_string = '' AND plugin IN ('mysql_native_password','');
```

On managed databases (RDS, Cloud SQL, and similar) you may not have access to `mysql.*` tables; `SHOW GRANTS` for each application user and `information_schema.USER_PRIVILEGES` still work.

**Common mistakes**

- Using the provider's admin user in the application `.env` because it was the one the console showed.
- Running migrations on application boot with the runtime user, which forces the runtime user to hold DDL.
- A "read-only" reporting user that was granted `ALL` "temporarily".
- Same database password across environments, so one leaked staging `.env` opens production.

---

## 8. Domain and Email Authentication

> Email spoofing is an access-control problem for your users: if anyone can send `From: security@yourdomain` and it lands in the inbox, your password-reset and alert emails become a phishing template. In the assessment above, every environment had DMARC `p=none` and SPF `~all`. The SMTP relay setup and basic records are in [wordpress-server-hardening.md, Email Security](wordpress-server-hardening.md#12-email-security-spf--dkim--dmarc); CAA, registrar lock, and certificate transparency are in [local-to-production-checklist.md, DNS Security](local-to-production-checklist.md#11-dns-security). This section is the enforcement path for any application domain.

- [ ] **SPF ends in `-all` once every sender is listed.** Stay under the 10 DNS-lookup limit (each `include`, `a`, `mx`, `redirect` counts); exceeding it is a `permerror` and SPF fails for everyone.

  ```text
  example.com.  TXT  "v=spf1 include:_spf.google.com include:mailgun.org -all"
  ```

- [ ] **DKIM signs everything you send,** with 2048-bit keys, from every sending platform (app relay, marketing, helpdesk, CRM). Rotate selectors when providers change.

- [ ] **DMARC progresses from monitoring to enforcement, with reports going somewhere a person reads.** `p=none` is a monitoring mode, not a protection. Plan the steps with dates.

  ```text
  # Week 0: monitor
  _dmarc.example.com.  TXT  "v=DMARC1; p=none; rua=mailto:dmarc@example.com; fo=1"
  # After reports show all legitimate sources aligned (typically 2 to 6 weeks)
  _dmarc.example.com.  TXT  "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"
  # Final
  _dmarc.example.com.  TXT  "v=DMARC1; p=reject; sp=reject; rua=mailto:dmarc@example.com"
  ```

  DMARC was updated in 2026 (RFC 9989, obsoleting RFC 7489): the `pct` tag is removed and replaced by a binary `t=y` test flag, and `np=` sets policy for non-existent subdomains. The record still starts with `v=DMARC1`. Older receivers still read `pct`, so avoid relying on partial percentages during rollout.

- [ ] **Non-sending domains and subdomains are locked explicitly.** Parked domains, old brands, and environment subdomains are the easiest to spoof.

  ```text
  parked.example.   TXT  "v=spf1 -all"
  parked.example.   MX   0 .                        ; null MX, RFC 7505
  _dmarc.parked.example.  TXT  "v=DMARC1; p=reject; sp=reject"
  ```

- [ ] **MTA-STS and TLS-RPT for inbound mail** (RFC 8461, RFC 8460), so mail to your domain cannot be downgraded to plaintext by an on-path attacker. Start in `testing`, move to `enforce`.

  ```text
  _mta-sts.example.com.   TXT  "v=STSv1; id=20261104"
  _smtp._tls.example.com. TXT  "v=TLSRPTv1; rua=mailto:tlsrpt@example.com"
  # Served at https://mta-sts.example.com/.well-known/mta-sts.txt
  version: STSv1
  mode: testing
  mx: mx1.example.com
  max_age: 604800
  ```

- [ ] **CAA records on every domain that has certificates.** CAA is its own DNS record type, not TXT. Add `accounturi` (RFC 8657) if your CA supports it, so only your ACME account can issue.

- [ ] **BIMI is optional** and only works after DMARC enforcement (`quarantine` or `reject`). Major mailbox providers also require a mark certificate (VMC or CMC). Treat it as a branding feature, not a control.

**How to verify**

```bash
D=example.com
dig +short TXT $D | grep -i spf                     # one record, ends in -all
dig +short TXT _dmarc.$D                            # p=quarantine or p=reject, rua present
dig +short TXT <selector>._domainkey.$D             # DKIM public key present
dig +short CAA $D
dig +short TXT _mta-sts.$D; curl -s https://mta-sts.$D/.well-known/mta-sts.txt
dig +short TXT _smtp._tls.$D
dig +short MX $D
# Repeat for every sending subdomain and every parked domain
```

Send a test message to a mailbox you control and read the `Authentication-Results` header: `spf=pass`, `dkim=pass`, `dmarc=pass` with the right domain alignment.

**Common mistakes**

- Leaving `p=none` for years because nobody reads the reports.
- Two SPF TXT records on the same name (invalid; receivers treat SPF as failed).
- Forgetting third-party senders (helpdesk, billing, CRM) before moving to `reject`, then breaking password-reset delivery.
- Protecting the apex domain while `staging.example.com` and old brand domains have no records at all.

---

## 9. Rate Limiting and Abuse

> OWASP API4 (Unrestricted Resource Consumption) and API6 (Unrestricted Access to Sensitive Business Flows). Without limits, login is a password-guessing service, OTP endpoints are an SMS bill, and exports are a data exfiltration pipe. Edge limits (see [cloudflare-hardening.md, Rate Limiting](cloudflare-hardening.md#7-rate-limiting)) and nginx limits stop volume; per-account limits in the application stop targeted abuse. You need both.

- [ ] **nginx: separate zones for authentication and for expensive endpoints, and return `429`.** The WordPress-specific zones are in [wordpress-server-hardening.md, Nginx Configuration](wordpress-server-hardening.md#2-nginx-configuration); the pattern for an API:

  ```nginx
  # http {} block
  limit_req_zone $binary_remote_addr zone=api_auth:10m   rate=10r/m;
  limit_req_zone $binary_remote_addr zone=api_heavy:10m  rate=6r/m;
  limit_req_zone $binary_remote_addr zone=api_general:20m rate=20r/s;
  limit_req_status 429;
  limit_req_log_level warn;

  # server {} block
  location ~ ^/(v1/auth/|v1/login|v1/password/|v1/mfa/|v1/otp/) {
      limit_req zone=api_auth burst=5 nodelay;
      proxy_pass http://app;
  }
  location ~ ^/v1/(exports?|reports|pdf|search|ai)/ {
      limit_req zone=api_heavy burst=3 nodelay;
      proxy_pass http://app;
  }
  location /v1/ {
      limit_req zone=api_general burst=40 nodelay;
      client_max_body_size 10m;
      proxy_pass http://app;
  }
  ```

  > **Why this matters:** behind Cloudflare or a load balancer, `$binary_remote_addr` is the proxy's address unless `real_ip_header` and `set_real_ip_from` are configured for trusted proxy ranges only. Every user then shares one bucket, and the limit either blocks everyone or is raised until it blocks no one. Never trust `X-Forwarded-For` from arbitrary clients.

- [ ] **Application limits keyed by account, not only by IP.** Credential stuffing comes from thousands of IPs, a few attempts each. Key login limits by the target account (Section 5), key business actions (send OTP, invite user, export) by the authenticated user, and key public form submissions by IP plus a fingerprint.

- [ ] **Cap work per request.** Maximum page size (`?limit=` clamped server side), maximum IDs per bulk request, maximum date range on reports, GraphQL depth and cost limits, upload size, and timeouts on calls to downstream services, including AI inference.

- [ ] **Lockout vs credential stuffing: choose deliberately.** Hard account lockout lets an attacker lock out any user whose email they know. Prefer per-account progressive delay or short temporary locks, notify the account owner, require MFA or a challenge after repeated failures, and alert on many accounts failing from related sources.

- [ ] **Return `429` with `Retry-After`, and log it.** A limit that triggers silently cannot be tuned, and an attack that hits it repeatedly is a signal for [security-audit-automation.md](security-audit-automation.md) or fail2ban (see [linux-server-hardening.md, Fail2ban](linux-server-hardening.md#4-fail2ban)).

**How to verify**

```bash
# Authorised targets only. Login: expect 401s followed by 429s
for i in $(seq 1 30); do
  curl -s -o /dev/null -w '%{http_code}\n' -X POST -H 'Content-Type: application/json' \
    -d '{"email":"ratelimit-test@example.com","password":"wrong"}' https://api.staging.example.com/v1/auth/login
done | sort | uniq -c

# Per-account limit holds across IPs? Repeat the loop from a second authorised source address;
# the account should stay throttled even though the IP is new.

# Retry-After present
curl -s -D - -o /dev/null -X POST -H 'Content-Type: application/json' \
  -d '{"email":"ratelimit-test@example.com","password":"wrong"}' https://api.staging.example.com/v1/auth/login \
  | grep -iE '^(HTTP|retry-after|x-ratelimit)'

# Page size is clamped. Only as a user of a test tenant seeded with synthetic records, never real data
curl -s -H "Authorization: Bearer $TA" "$API/v1/patients?limit=100000" | jq '{returned: (.data | length)}'
```

**Common mistakes**

- Rate limiting `/login` but not `/password/forgot`, `/mfa/verify`, `/otp/send`, or the mobile login route.
- Limits configured on the web route group but not the API group, or on one environment only.
- Real client IP not restored behind a proxy, so limits are global.
- Running the verification loop against production without agreement and locking a real user out. Use a dedicated test account.

---

*Last reviewed: 2026-11 | Applies to: REST and GraphQL APIs and their web/mobile clients; Laravel and generic PHP backends; Parse Server, Firebase, Supabase; MySQL 8 and MariaDB 10.4+; nginx; any domain that sends or receives email*
