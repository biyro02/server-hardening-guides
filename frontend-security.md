# Frontend Security Hardening

**Non-obvious vulnerabilities in web frontends — what looks correct but silently fails**

> This guide covers mistakes in client-side code, frontend frameworks, and build tooling that are easy to introduce and hard to detect. Many of these look secure, pass code review, and only fail under specific attacker-controlled conditions. Basic advice like "sanitize user input" is included only where the common implementation of that advice is itself wrong.

---

## Table of Contents

1. [Universal Frontend Security](#1-universal-frontend-security)
   - [Secrets in Client-Side Code](#secrets-in-client-side-code)
   - [Source Maps in Production](#source-maps-in-production)
   - [CORS Misconfiguration](#cors-misconfiguration)
   - [postMessage Without Origin Validation](#postmessage-without-origin-validation)
   - [localStorage for Auth Tokens](#localstorage-for-auth-tokens)
   - [eval() and new Function()](#eval-and-new-function)
   - [Prototype Pollution](#prototype-pollution)
   - [Content Security Policy for SPAs](#content-security-policy-for-spas)
   - [Third-Party Scripts Without Subresource Integrity](#third-party-scripts-without-subresource-integrity)
   - [DOM XSS via innerHTML and Friends](#dom-xss-via-innerhtml-and-friends)
   - [javascript: URL Injection](#javascript-url-injection)
   - [Open Redirect via window.location](#open-redirect-via-windowlocation)
2. [Pure JavaScript and jQuery](#2-pure-javascript-and-jquery)
   - [jQuery .html() with User Content](#jquery-html-with-user-content)
   - [JSONP via jQuery Ajax](#jsonp-via-jquery-ajax)
   - [$.getScript() with User URL](#getscript-with-user-url)
   - [jQuery < 1.9 Selector XSS](#jquery--19-selector-xss)
   - [jQuery < 3.5 parseHTML and Attribute XSS](#jquery--35-parsehtml-and-attribute-xss)
   - [document.write with Cookie or Location](#documentwrite-with-cookie-or-location)
   - [Inline Event Handlers with User Data](#inline-event-handlers-with-user-data)
   - [JSONP Callback Injection](#jsonp-callback-injection)
   - [XMLHttpRequest Without CSRF Token](#xmlhttprequest-without-csrf-token)
   - [window.name as Data Transport](#windowname-as-data-transport)
3. [React](#3-react)
   - [dangerouslySetInnerHTML Without Sanitization](#dangerouslysetinnerhtml-without-sanitization)
   - [javascript: in href Props](#javascript-in-href-props)
   - [REACT_APP_ Environment Variables](#react_app_-environment-variables)
   - [ref and Direct DOM Manipulation](#ref-and-direct-dom-manipulation)
   - [SSR Hydration Mismatch](#ssr-hydration-mismatch)
   - [eval() in useEffect or Event Handlers](#eval-in-useeffect-or-event-handlers)
   - [React DevTools in Production](#react-devtools-in-production)
4. [Vue.js](#4-vuejs)
   - [v-html with User Content](#v-html-with-user-content)
   - [VITE_SECRET and VUE_APP_ Variables](#vite_secret-and-vue_app_-variables)
   - [Server-Side Template Injection in Vue SSR](#server-side-template-injection-in-vue-ssr)
   - [Vue 2 Prototype Pollution via $set](#vue-2-prototype-pollution-via-set)
   - [$el.innerHTML Bypass](#elinnerhtml-bypass)
   - [Vue Router Open Redirect](#vue-router-open-redirect)
5. [Angular](#5-angular)
   - [bypassSecurityTrustHtml](#bypasssecuritytrusthtml)
   - [Angular Template Injection](#angular-template-injection)
   - [innerHTML Binding](#innerhtml-binding)
   - [enableProdMode Missing](#enableprodmode-missing)
   - [HttpClient XSRF Configuration](#httpclient-xsrf-configuration)
6. [Next.js and Nuxt.js](#6-nextjs-and-nuxtjs)
   - [NEXT_PUBLIC_ and NUXT_PUBLIC_ Variables](#next_public_-and-nuxt_public_-variables)
   - [getServerSideProps Over-fetching](#getserversideprops-over-fetching)
   - [API Routes Without Authentication](#api-routes-without-authentication)
   - [SSRF via fetch() in getServerSideProps](#ssrf-via-fetch-in-getserversideprops)
   - [next.config.js Rewrites as Open Proxy](#nextconfigjs-rewrites-as-open-proxy)
   - [next.config.js env Block Client Exposure](#nextconfigjs-env-block-client-exposure)
   - [productionBrowserSourceMaps](#productionbrowsersourcemaps)
7. [Build Tool Security](#7-build-tool-security)
   - [Source Maps in Production Webpack and Vite](#source-maps-in-production-webpack-and-vite)
   - [.env Files in Version Control](#env-files-in-version-control)
   - [Debug Code in Production Builds](#debug-code-in-production-builds)
   - [Tree-Shaking Does Not Remove Side-Effect Imports](#tree-shaking-does-not-remove-side-effect-imports)
   - [Webpack DefinePlugin Hardcoding Secrets](#webpack-defineplugin-hardcoding-secrets)
8. [Dependency Security](#8-dependency-security)
   - [npm install Without package-lock.json](#npm-install-without-package-lockjson)
   - [npm audit Not in CI](#npm-audit-not-in-ci)
   - [Typosquatting](#typosquatting)
   - [postinstall Hook Execution](#postinstall-hook-execution)
   - [Unpinned Versions in package.json](#unpinned-versions-in-packagejson)
   - [npm link and Local File Dependencies](#npm-link-and-local-file-dependencies)

---

## 1. Universal Frontend Security

> **Applies to:** All web frontends regardless of framework, library, or build tool.
> **These apply everywhere.** Framework-specific items follow in later sections.

---

### Secrets in Client-Side Code

**Vulnerable pattern:**

```javascript
// Hardcoded API keys in JS source
const API_KEY = 'sk-abc123456789';
const STRIPE_SECRET = 'sk_live_xyz';
const INTERNAL_API = 'https://internal.corp.example.com/api/v2';

// In a config file bundled with the app:
export const config = {
    googleMapsKey: 'AIzaSy...',
    sentryDsn: 'https://abc@sentry.io/123',
    databaseUrl: 'postgres://user:password@db.internal/app',
};
```

**Why it fails:**

All JavaScript delivered to the browser is readable by anyone. Minification obscures variable names but does not hide string values — `strings` or the browser DevTools Network tab reveals every string literal in the bundle. Build tools that replace `process.env.SECRET` at compile time embed the secret as a string literal in the output bundle.

**Fixed pattern:**

```javascript
// Client-side code should only use public keys
const STRIPE_PUBLISHABLE_KEY = 'pk_live_xyz';  // publishable = intended to be public

// Secrets must stay on the server — proxy through your own API
// Client calls:
const response = await fetch('/api/analyze', {
    method: 'POST',
    body: JSON.stringify({ text: userInput }),
});
// Server (/api/analyze) holds the API key and calls the third-party service
```

```bash
# Scan your built bundle for potential secrets before deploying:
grep -rE '(secret|password|api_key|token|private_key)\s*[:=]\s*["\x27][A-Za-z0-9+/=_\-]{20,}' dist/
```

---

### Source Maps in Production

**Vulnerable pattern:**

```
# Files publicly accessible on production:
/static/js/main.abc123.js
/static/js/main.abc123.js.map   ← exposes full unminified source
```

**Why it fails:**

Source map files (`.map`) contain the complete original source code, including variable names, comments, internal API URLs, authentication logic, and anything else the minifier stripped. An attacker who discovers these files can read the application's full source, find logic vulnerabilities, identify undocumented API endpoints, and spot hardcoded values that minification would otherwise obscure.

**Fixed pattern:**

```bash
# Check if source maps are publicly accessible:
curl -s -o /dev/null -w "%{http_code}" https://yourapp.example.com/static/js/main.js.map
# Should return 404, not 200

# Find all map files in your build output:
find dist/ -name '*.map'
```

```nginx
# Nginx: block source map access
location ~* \.map$ {
    deny all;
    return 404;
}
```

```javascript
// webpack.config.js: never generate source maps in production
module.exports = {
    mode: 'production',
    devtool: false,  // no source maps
    // If you need maps for error tracking only: use 'hidden-source-map'
    // This generates maps but does NOT include the SourceMappingURL comment
    // Upload maps to your error tracker manually, then delete them from the CDN
    devtool: process.env.CI ? 'hidden-source-map' : false,
};
```

---

### CORS Misconfiguration

**Vulnerable pattern:**

```
# Response headers from API server:
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```

**Why it fails two ways:**

First, `*` with `credentials: true` is outright rejected by browsers per the CORS spec — a request that sends credentials (cookies, Authorization headers) against an `*` origin will be blocked. This appears to "work" in some testing tools (like Postman, which does not enforce CORS) but silently breaks for authenticated users in the browser.

Second, the more dangerous pattern: dynamically reflecting the `Origin` header without validation:

```
# Request:
Origin: https://attacker.example.com

# Server response (reflecting origin without validation):
Access-Control-Allow-Origin: https://attacker.example.com
Access-Control-Allow-Credentials: true
```

This allows any origin to make credentialed cross-origin requests, reading authenticated API responses from the user's browser.

**Fixed pattern:**

```javascript
// Node.js / Express: validate origin against an allowlist
const allowedOrigins = ['https://yourapp.example.com', 'https://www.yourapp.example.com'];

app.use((req, res, next) => {
    const origin = req.headers.origin;
    if (allowedOrigins.includes(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Credentials', 'true');
    }
    // If origin is not in the allowlist: do not set CORS headers at all
    next();
});
```

```nginx
# Nginx CORS with origin validation:
map $http_origin $cors_origin {
    default                          "";
    "https://yourapp.example.com"    "$http_origin";
    "https://www.yourapp.example.com" "$http_origin";
}

add_header Access-Control-Allow-Origin $cors_origin always;
# Only add Credentials header when origin matched:
add_header Access-Control-Allow-Credentials "true" always;
```

---

### postMessage Without Origin Validation

**Vulnerable pattern:**

```javascript
// Receiving postMessage without checking the sender's origin
window.addEventListener('message', function(event) {
    // No event.origin check — any frame can send messages
    const data = JSON.parse(event.data);
    document.getElementById('content').innerHTML = data.html;
});
```

**Why it fails:**

Any page loaded in a frame or opened in a window can send `postMessage` to any other window it has a reference to. Without validating `event.origin`, a third-party site that embeds your page (or opens it as a popup) can inject arbitrary messages and control your page's behavior.

**Fixed pattern:**

```javascript
window.addEventListener('message', function(event) {
    // Validate origin before processing
    const allowedOrigins = ['https://yourapp.example.com', 'https://partner.example.com'];

    if (!allowedOrigins.includes(event.origin)) {
        return;  // ignore messages from unknown origins
    }

    let data;
    try {
        data = JSON.parse(event.data);
    } catch {
        return;
    }

    // Now safe to process — but still escape before inserting into DOM
    document.getElementById('content').textContent = data.text;  // not innerHTML
});
```

---

### localStorage for Auth Tokens

**Vulnerable pattern:**

```javascript
// Storing auth token in localStorage after login
localStorage.setItem('auth_token', response.token);

// Reading it back for every request:
const token = localStorage.getItem('auth_token');
fetch('/api/data', {
    headers: { 'Authorization': 'Bearer ' + token }
});
```

**Why it fails:**

`localStorage` is accessible from any JavaScript running on the page — including injected JavaScript from XSS vulnerabilities, malicious browser extensions, and third-party analytics scripts. A single XSS payload can exfiltrate all tokens stored in `localStorage`. `httpOnly` cookies cannot be read by JavaScript at all.

**Fixed pattern:**

```javascript
// Do not use localStorage for auth tokens.
// Use httpOnly, Secure, SameSite=Strict cookies set by the server.
```

```
Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Strict; Path=/
```

```javascript
// The browser sends the cookie automatically — no JS needed:
fetch('/api/data', {
    credentials: 'same-origin',  // sends cookies with the request
});
```

> **Note:** If you must store tokens client-side (e.g., for cross-origin requests or mobile apps), use `sessionStorage` instead of `localStorage` to limit the token's lifespan to the browser tab. It is still readable by JavaScript, but is cleared when the tab closes. For long-lived tokens, the only secure option is `httpOnly` cookies.

---

### eval() and new Function()

**Vulnerable pattern:**

```javascript
// Evaluating user input as code
eval(userInput);
new Function(userInput)();

// Less obvious patterns:
setTimeout(userInput, 0);         // string argument to setTimeout = eval()
setInterval(userInput, 1000);     // same
document.write('<script>' + userInput + '</script>');

// Template literal with tagged template:
const result = eval(`return ${userExpression}`);
```

**Why it fails:**

`eval()`, `new Function()`, and string-form `setTimeout`/`setInterval` execute arbitrary JavaScript in the current page's context with full access to the DOM, cookies, and any variables in scope. Content Security Policy blocks `eval()` when `unsafe-eval` is not in the directive, but that only works if CSP is deployed.

**Fixed pattern:**

```javascript
// Parse and evaluate mathematical expressions safely (example use case):
// Instead of eval('2 + 3 * 4'), use a safe expression parser
import { evaluate } from 'mathjs';  // sandboxed expression evaluator
const result = evaluate('2 + 3 * 4');

// For JSON: use JSON.parse(), not eval()
const data = JSON.parse(userInput);  // throws on invalid JSON; does not execute code

// setTimeout/setInterval: always pass a function, not a string
setTimeout(() => doThing(safeParam), 0);  // not: setTimeout('doThing(' + param + ')', 0)
```

---

### Prototype Pollution

**Vulnerable pattern:**

```javascript
// Object.assign() with deeply nested user input
Object.assign(config, userSettings);

// Lodash _.merge() before 4.17.5:
_.merge({}, JSON.parse(userInput));

// Manual recursive merge:
function merge(target, source) {
    for (const key of Object.keys(source)) {
        if (typeof source[key] === 'object') {
            merge(target[key] = target[key] || {}, source[key]);
        } else {
            target[key] = source[key];
        }
    }
}
// Payload: {"__proto__": {"isAdmin": true}}
// After merge: ({}).isAdmin === true  for ALL objects in the runtime
```

**Why it fails:**

JavaScript objects inherit from `Object.prototype` via the prototype chain. A property set on `Object.prototype` becomes visible on every plain object in the runtime. An attacker who can get the string `__proto__` processed as an object key during a merge or deep copy can add properties to `Object.prototype`, affecting authentication checks, access control flags, and template rendering for every subsequent operation in the same process.

**Fixed pattern:**

```javascript
// Option 1: use Object.create(null) for merge targets — no prototype chain
const target = Object.create(null);
_.merge(target, userInput);

// Option 2: sanitize keys before merging
function sanitizedMerge(target, source) {
    for (const key of Object.keys(source)) {
        if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
            continue;  // skip dangerous keys
        }
        if (typeof source[key] === 'object' && source[key] !== null) {
            target[key] = target[key] || {};
            sanitizedMerge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
}

// Option 3: use JSON.parse() with a reviver to strip prototype keys
const safe = JSON.parse(userInput, (key, value) => {
    if (key === '__proto__') return undefined;
    return value;
});

// Update lodash to 4.17.21+ which includes the prototype pollution fix
```

---

### Content Security Policy for SPAs

**Vulnerable pattern:**

```html
<!-- CSP that is effectively disabled -->
<meta http-equiv="Content-Security-Policy"
      content="default-src 'self' 'unsafe-inline' 'unsafe-eval'">
```

**Why it fails:**

`unsafe-inline` permits all inline `<script>` tags and inline event handlers. `unsafe-eval` permits `eval()`. Together, they defeat the two main protections CSP provides: blocking injected `<script>` content and blocking code execution from strings. A CSP with both directives active is the same as having no CSP for XSS purposes.

SPAs often "need" `unsafe-inline` because they inject inline scripts for hydration data or dynamic styles. There are correct alternatives.

**Fixed pattern:**

```html
<!-- Nonce-based CSP: each inline script gets a unique per-request nonce -->
<meta http-equiv="Content-Security-Policy"
      content="default-src 'self'; script-src 'self' 'nonce-RANDOM_NONCE'; style-src 'self' 'nonce-RANDOM_NONCE'">

<script nonce="RANDOM_NONCE">
    window.__INITIAL_DATA__ = {...};
</script>
```

```javascript
// Server-side (Node.js): generate a nonce per request
import crypto from 'crypto';

app.use((req, res, next) => {
    res.locals.nonce = crypto.randomBytes(16).toString('base64');
    res.setHeader(
        'Content-Security-Policy',
        `default-src 'self'; script-src 'self' 'nonce-${res.locals.nonce}'; object-src 'none'`
    );
    next();
});
```

```javascript
// For React/Next.js: use hash-based CSP for static inline scripts
// Generate the hash of your inline script:
// echo -n 'window.__INITIAL_DATA__ = {};' | openssl dgst -sha256 -binary | openssl base64
// Then: script-src 'sha256-<hash>'
```

---

### Third-Party Scripts Without Subresource Integrity

**Vulnerable pattern:**

```html
<!-- CDN-hosted script with no integrity check -->
<script src="https://cdn.example.com/jquery/3.7.1/jquery.min.js"></script>
<link rel="stylesheet" href="https://cdn.example.com/bootstrap/5.3/bootstrap.min.css">
```

**Why it fails:**

If the CDN is compromised, or if the URL serves a mutable resource (not a version-pinned asset), an attacker who gains access to the CDN can replace the file with a version that includes malicious JavaScript. Your users download and execute the attacker's code in the context of your site. This type of supply chain attack has happened with real CDNs.

**Fixed pattern:**

```html
<!-- Include the integrity hash and crossorigin attribute -->
<script
    src="https://cdn.example.com/jquery/3.7.1/jquery.min.js"
    integrity="sha384-1H217gwSVyLSIfaLxHbE7dRb3v4mYCKbpQvzx0cegeju1MVsGrX5xXxAvs/HgeFs"
    crossorigin="anonymous">
</script>
```

```bash
# Generate the SRI hash for a local copy of the file:
cat jquery.min.js | openssl dgst -sha384 -binary | openssl base64 -A
# Then prefix with 'sha384-'

# Or use the SRI Hash Generator: https://www.srihash.org/
```

> **Note:** Self-hosting is more secure than CDN + SRI, because you control the file and there is no dependency on a third-party CDN's availability or integrity. Use SRI when you must use a CDN.

---

### DOM XSS via innerHTML and Friends

**Vulnerable pattern:**

```javascript
// Setting innerHTML with user content
element.innerHTML = userContent;
element.outerHTML = '<div>' + userContent + '</div>';
document.write(userContent);
document.writeln(userContent);

// jQuery equivalent:
$(element).html(userContent);

// Setting via attribute reflection:
const name = new URLSearchParams(location.search).get('name');
document.getElementById('greeting').innerHTML = 'Hello, ' + name;
// URL: ?name=<img src=x onerror=alert(1)>
```

**Why it fails:**

`innerHTML`, `outerHTML`, and `document.write()` parse the string as HTML, including `<script>` tags, inline event handlers (`onerror`, `onload`), and SVG/MathML elements with event attributes. A single unescaped user value in any of these sinks causes XSS.

**Fixed pattern:**

```javascript
// Use textContent for plain text — never parses as HTML
element.textContent = userContent;

// For URL parameters reflected into the page:
const name = new URLSearchParams(location.search).get('name') ?? '';
document.getElementById('greeting').textContent = 'Hello, ' + name;

// If HTML output is genuinely required: use DOMPurify
import DOMPurify from 'dompurify';
element.innerHTML = DOMPurify.sanitize(userContent);

// DOMPurify configuration for strict contexts:
element.innerHTML = DOMPurify.sanitize(userContent, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a'],
    ALLOWED_ATTR: ['href'],
    ALLOW_DATA_ATTR: false,
});
```

---

### javascript: URL Injection

**Vulnerable pattern:**

```javascript
// Building a link from user input
const url = userInput;
document.getElementById('link').href = url;
// <a href="javascript:alert(document.cookie)"> — executes on click

// Or via setAttribute:
element.setAttribute('href', redirectUrl);
element.setAttribute('src', userImageUrl);
// 'javascript:alert(1)' is a valid value for href
// 'javascript:...' is also valid for src in some contexts
```

**Why it fails:**

`javascript:` is a valid URL scheme. Any attribute that accepts URLs — `href`, `src`, `action`, `formaction`, `xlink:href` — can execute JavaScript if given a `javascript:` value. Unlike `innerHTML` XSS, this executes only when the user interacts with the element (clicks a link, submits a form), but it bypasses CSP policies that do not include `script-src`.

**Fixed pattern:**

```javascript
function safeUrl(url) {
    try {
        const parsed = new URL(url, window.location.href);
        // Allow only http and https schemes
        if (!['http:', 'https:'].includes(parsed.protocol)) {
            return '#';
        }
        return parsed.href;
    } catch {
        return '#';
    }
}

document.getElementById('link').href = safeUrl(userInput);
```

> **Note:** React validates `href` for `javascript:` since version 16.9 but only logs a warning — it does not block the value. Angular sanitizes URLs in `[href]` bindings by default. Vue does not sanitize `href` in `v-bind:href`. In all frameworks, explicit validation of user-supplied URLs is more reliable than relying on framework-level protection.

---

### Open Redirect via window.location

**Vulnerable pattern:**

```javascript
// Redirecting to a URL from query parameters
const next = new URLSearchParams(location.search).get('next');
window.location.href = next;
window.location.replace(next);

// Protocol-relative URL bypass: //attacker.example.com
// Absolute URL: https://attacker.example.com
// javascript: URL: javascript:alert(1)
```

**Why it fails:**

An open redirect allows attackers to use your domain as a stepping stone in phishing attacks. An email that says "Click here to verify your account: https://yourapp.example.com/login?next=https://attacker.example.com" appears to link to your legitimate domain. After login, the user is silently redirected to the attacker's phishing page.

**Fixed pattern:**

```javascript
function safeRedirect(url) {
    try {
        const parsed = new URL(url, window.location.href);
        // Allow only same-origin redirects
        if (parsed.origin !== window.location.origin) {
            return '/';
        }
        return parsed.pathname + parsed.search + parsed.hash;
    } catch {
        return '/';
    }
}

const next = new URLSearchParams(location.search).get('next') ?? '/';
window.location.replace(safeRedirect(next));
```

---

## 2. Pure JavaScript and jQuery

> **Applies to:** Sites using jQuery or vanilla JS without a modern bundled framework.
> **Quick detect:**
> ```bash
> # In page source:
> grep -i 'jquery' index.html
> # Or in browser console:
> jQuery.fn.jquery
> ```
> **Not using jQuery?** Skip to [React](#3-react) or [Vue.js](#4-vuejs).

---

### jQuery .html() with User Content

**Vulnerable pattern:**

```javascript
// Setting content with .html() — equivalent to innerHTML
$('#container').html(userData);
$('.result').html(response.message);

// Also:
$(element).append('<span>' + userInput + '</span>');  // parses as HTML
$(element).prepend(userInput);
$(element).after(userInput);
$(element).before(userInput);
```

**Why it fails:**

jQuery's `.html()` method maps directly to `innerHTML`. The `.append()`, `.prepend()`, `.after()`, and `.before()` methods also parse their string arguments as HTML when given strings. Any user-controlled content passed to these methods causes XSS.

**Fixed pattern:**

```javascript
// Use .text() for plain text — never parses HTML
$('#container').text(userData);

// For appending elements: create them explicitly
const span = $('<span>').text(userInput);  // .text() on a new element
$('#container').append(span);

// If HTML must be rendered: sanitize first
$('#container').html(DOMPurify.sanitize(userData));
```

---

### JSONP via jQuery Ajax

**Vulnerable pattern:**

```javascript
$.ajax({
    url: 'https://api.example.com/data',
    dataType: 'jsonp',
    success: function(data) { /* ... */ }
});

// Or:
$.getJSON('https://api.example.com/data?callback=?', handler);
```

**Why it fails:**

JSONP works by injecting a `<script>` tag with a user-controlled callback parameter. The server wraps JSON data in a function call: `callbackName({"key":"value"})`. This is inherently cross-origin script execution. If the JSONP endpoint is compromised, or if the callback parameter is not strictly validated by the server, an attacker can inject arbitrary JavaScript. Additionally, JSONP endpoints send the user's cookies to the third-party server.

**Fixed pattern:**

```javascript
// Use CORS + fetch() instead of JSONP
// Requires the API server to support CORS headers

fetch('https://api.example.com/data', {
    method: 'GET',
    headers: { 'Accept': 'application/json' },
    credentials: 'omit',  // do not send cookies to third-party
})
.then(res => res.json())
.then(data => { /* ... */ });
```

---

### $.getScript() with User URL

**Vulnerable pattern:**

```javascript
// Loading a script from a user-supplied URL
const scriptUrl = new URLSearchParams(location.search).get('plugin');
$.getScript(scriptUrl);

// Or: loading scripts based on user settings
$.getScript('https://cdn.example.com/plugins/' + userPluginName + '.js');
```

**Why it fails:**

`$.getScript()` injects a `<script>` tag and executes the loaded file as JavaScript in the current page context. Allowing user-controlled input in the URL parameter is equivalent to allowing the user to execute arbitrary JavaScript on your page.

**Fixed pattern:**

```javascript
// Allowlist of known script URLs
const allowedScripts = {
    'chart':  'https://cdn.example.com/plugins/chart.min.js',
    'export': 'https://cdn.example.com/plugins/export.min.js',
};

const pluginName = new URLSearchParams(location.search).get('plugin');
if (allowedScripts.hasOwnProperty(pluginName)) {
    $.getScript(allowedScripts[pluginName]);
}
// If pluginName is not in the allowlist: do nothing
```

---

### jQuery < 1.9 Selector XSS

**Vulnerable pattern:**

```javascript
// jQuery before 1.9: passing location.hash to $() executes HTML
$(location.hash);

// If URL is: https://site.com/#<img src=x onerror=alert(1)>
// jQuery < 1.9 would execute this as HTML, not find a DOM element
```

**Why it fails:**

Before jQuery 1.9, `$(selector)` was ambiguous between "find a DOM element matching this CSS selector" and "create HTML from this string". When the selector looked like HTML (started with `<`), jQuery would create it, executing any scripts or event handlers. `location.hash` is attacker-controlled via the URL.

**Fixed pattern:**

```javascript
// Upgrade to jQuery 1.9+ (which requires selectors to start with # or be a DOM element)

// If stuck on old jQuery: check hash before passing to $()
const hash = location.hash;
if (hash && /^#[A-Za-z0-9_-]+$/.test(hash)) {
    $(hash).show();
}
```

---

### jQuery < 3.5 parseHTML and Attribute XSS

**Vulnerable pattern:**

```javascript
// jQuery 3.4 and below: $.parseHTML includes script tags by default
const html = $.parseHTML(userContent);
$(container).append(html);

// jQuery 3.4 and below: <img> with onerror executes even without scripts
// due to how jQuery handles certain attribute combinations
$.parseHTML('<img onerror="alert(1)" src=x>');
// Executes in jQuery < 3.5
```

**Why it fails:**

jQuery 3.4 introduced a regression where certain HTML patterns with event attributes were executed even when script execution was supposed to be suppressed. jQuery 3.5 fixed this. Code on jQuery 3.4 that calls `$.parseHTML()` with user content is vulnerable to event attribute XSS.

**Fixed pattern:**

```javascript
// Upgrade to jQuery 3.5.0 or later

// When using $.parseHTML() with untrusted content:
// Pass keepScripts = false (this has been the signature since jQuery 1.8)
const nodes = $.parseHTML(userContent, document, false);

// Better: use DOMPurify before passing to any jQuery DOM method
const clean = DOMPurify.sanitize(userContent);
$(container).html(clean);
```

---

### document.write with Cookie or Location

**Vulnerable pattern:**

```javascript
// Reflecting URL parameters or cookies into the page via document.write
document.write(document.cookie);
document.write(location.search);
document.write('<script src="' + document.referrer + '"></script>');
document.write(decodeURIComponent(location.hash.slice(1)));
```

**Why it fails:**

`document.write()` parses content as HTML. Using it with `document.cookie` exposes credentials in the page source. Using it with `location.search`, `location.hash`, or `document.referrer` is DOM XSS because all of these values are attacker-controlled.

**Fixed pattern:**

```javascript
// Never use document.write() in application code
// For debug purposes: use console.log(document.cookie)

// To reflect URL parameters to the page:
const value = new URLSearchParams(location.search).get('key') ?? '';
document.getElementById('output').textContent = value;  // textContent, not innerHTML/write
```

---

### Inline Event Handlers with User Data

**Vulnerable pattern:**

```javascript
// Building inline event handlers with user data
element.setAttribute('onclick', "doThing('" + userInput + "')");
container.innerHTML = '<button onclick="select(\'' + itemId + '\')">Click</button>';

// In server-rendered templates:
// <div onmouseover="showTooltip('{{ user.name }}')">
// If user.name = '); alert(1); //  → executes arbitrary JS
```

**Why it fails:**

Inline event handlers are evaluated as JavaScript. Injecting user data into them is code injection. HTML escaping helps — `htmlspecialchars()` on the server side will escape `'` to `&#039;` — but JavaScript context escaping is different from HTML attribute escaping. Both layers must be applied.

**Fixed pattern:**

```javascript
// Never build inline event handlers from user data
// Attach event listeners programmatically:

const button = document.createElement('button');
button.textContent = 'Select';
button.addEventListener('click', () => select(itemId));
// itemId is a JS variable, not injected into an HTML string
container.appendChild(button);

// For data attributes (safe alternative):
button.dataset.itemId = itemId;  // stored as attribute, not code
button.addEventListener('click', (e) => {
    select(e.currentTarget.dataset.itemId);
});
```

---

### JSONP Callback Injection

**Vulnerable pattern:**

```
# Server endpoint that reflects the callback parameter:
GET /api/user?callback=handleUser
# Response: handleUser({"id":1,"name":"Alice"})

# Attacker request:
GET /api/user?callback=alert(document.cookie)//
# Response: alert(document.cookie)//({"id":1,"name":"Alice"})
# When loaded as a script tag: executes alert(document.cookie)
```

**Why it fails:**

JSONP endpoints that do not strictly validate the callback parameter allow arbitrary JavaScript injection. If an attacker can cause a victim's browser to load the JSONP URL as a script (via `<script src="...">` or CSP bypass), the callback value executes as JavaScript.

**Fixed pattern:**

```javascript
// Server-side: validate callback parameter strictly
app.get('/api/data', (req, res) => {
    const callback = req.query.callback;

    // Strict allowlist: callback must be a valid JS identifier
    if (callback && !/^[a-zA-Z_$][0-9a-zA-Z_$]*$/.test(callback)) {
        res.status(400).json({ error: 'Invalid callback name' });
        return;
    }

    const data = JSON.stringify(getApiData());
    if (callback) {
        res.setHeader('Content-Type', 'application/javascript');
        res.send(`${callback}(${data})`);
    } else {
        res.json(getApiData());
    }
});
```

---

### XMLHttpRequest Without CSRF Token

**Vulnerable pattern:**

```javascript
// AJAX POST without CSRF token
function deleteUser(userId) {
    const xhr = new XMLHttpRequest();
    xhr.open('POST', '/api/users/' + userId + '/delete');
    xhr.send();
}
```

**Why it fails:**

AJAX requests send cookies automatically (if `withCredentials` is set, or for same-origin requests). A malicious page can trigger your AJAX endpoints if CSRF protection is not in place. `SameSite=Strict` cookies mitigate this, but older browsers do not support `SameSite` and many applications have a mix of cookie policies.

**Fixed pattern:**

```javascript
// Read CSRF token from meta tag (set by server) and include in every state-changing request
const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');

function apiPost(url, data) {
    return fetch(url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': csrfToken,
        },
        body: JSON.stringify(data),
        credentials: 'same-origin',
    });
}
```

---

### window.name as Data Transport

**Vulnerable pattern:**

```javascript
// Using window.name to pass data between pages (old pattern)
// Page A:
window.name = JSON.stringify({ token: authToken });
window.location = 'https://partner.example.com/callback';

// Page B reads window.name after navigation
const data = JSON.parse(window.name);
useToken(data.token);
```

**Why it fails:**

`window.name` persists across page navigations within the same browser window/tab and across domains. When navigating from a high-trust page to a low-trust page using `window.name` as a data channel, the low-trust page can read whatever was stored. Additionally, a malicious page opened in the same tab can read and modify `window.name` before your callback page reads it.

**Fixed pattern:**

```javascript
// Use postMessage for cross-origin communication instead
// Page A:
const popup = window.open('https://partner.example.com/callback');
popup.postMessage(JSON.stringify({ token: authToken }), 'https://partner.example.com');

// Page B:
window.addEventListener('message', (event) => {
    if (event.origin !== 'https://yourdomain.example.com') return;
    const data = JSON.parse(event.data);
    useToken(data.token);
});
```

---

## 3. React

> **Applies to:** Projects with `react` in `package.json`.
> **Quick detect:**
> ```bash
> cat package.json | grep '"react"'
> ```
> **Not using React?** Skip to [Vue.js](#4-vuejs) or [Angular](#5-angular).

---

### dangerouslySetInnerHTML Without Sanitization

**Vulnerable pattern:**

```jsx
// Rendering user content with dangerouslySetInnerHTML
function Comment({ text }) {
    return <div dangerouslySetInnerHTML={{ __html: text }} />;
}

// Or with markdown rendered to HTML on the client:
function Post({ content }) {
    const html = marked(content);  // markdown to HTML
    return <article dangerouslySetInnerHTML={{ __html: html }} />;
}
```

**Why it fails:**

`dangerouslySetInnerHTML` bypasses React's escaping entirely and sets the element's `innerHTML` directly. Even if the content comes from a trusted markdown library, many markdown parsers pass through raw HTML by default, allowing XSS via `<script>` or event attributes in the markdown source.

**Fixed pattern:**

```jsx
import DOMPurify from 'dompurify';
import { marked } from 'marked';

function Comment({ text }) {
    // Sanitize before rendering
    const sanitized = DOMPurify.sanitize(text);
    return <div dangerouslySetInnerHTML={{ __html: sanitized }} />;
}

function Post({ content }) {
    // Disable raw HTML in marked, then sanitize anyway
    const html = marked(content, { mangle: false, headerIds: false });
    const sanitized = DOMPurify.sanitize(html, {
        ALLOWED_TAGS: ['p', 'strong', 'em', 'ul', 'ol', 'li', 'blockquote', 'code', 'pre'],
        ALLOWED_ATTR: [],
    });
    return <article dangerouslySetInnerHTML={{ __html: sanitized }} />;
}
```

---

### javascript: in href Props

**Vulnerable pattern:**

```jsx
// Rendering a user-supplied URL as a link
function UserLink({ url, label }) {
    return <a href={url}>{label}</a>;
}
// If url = 'javascript:alert(document.cookie)' — executes on click
```

**Why it fails:**

React does NOT block `javascript:` URLs in `href` props. Since React 16.9, the browser console logs a warning, but the link still renders and executes. Users who click the link have their JavaScript executed. This is particularly dangerous in user-generated profile links, bio URLs, and comment links.

**Fixed pattern:**

```jsx
function safeUrl(url) {
    if (!url) return '#';
    try {
        const parsed = new URL(url);
        return ['http:', 'https:'].includes(parsed.protocol) ? url : '#';
    } catch {
        // relative URL — allow it
        return url.startsWith('/') ? url : '#';
    }
}

function UserLink({ url, label }) {
    return <a href={safeUrl(url)} rel="noopener noreferrer">{label}</a>;
}
```

---

### REACT_APP_ Environment Variables

**Vulnerable pattern:**

```bash
# .env
REACT_APP_API_KEY=sk-supersecret123
REACT_APP_STRIPE_SECRET=sk_live_xyz
REACT_APP_DATABASE_URL=postgres://user:pass@db.internal/app
```

**Why it fails:**

Create React App and most React build tools bundle all variables prefixed with `REACT_APP_` into the JavaScript output. These values appear as string literals in the built bundle — readable by anyone who opens the browser DevTools or downloads the JS file. The naming convention (`REACT_APP_`) exists precisely to expose variables to the client, but developers often put secret values there because it is the easiest way to pass configuration.

**Fixed pattern:**

```bash
# .env — only public values with REACT_APP_ prefix
REACT_APP_STRIPE_PUBLISHABLE_KEY=pk_live_xyz  # publishable = designed to be public
REACT_APP_API_URL=https://api.yourapp.example.com

# Secret values belong on the server ONLY:
# STRIPE_SECRET_KEY=sk_live_xyz    ← never in REACT_APP_
# DATABASE_URL=postgres://...      ← never in REACT_APP_
```

```bash
# After each build: scan the output for known secrets
grep -r 'sk_live\|sk_test' build/static/js/
```

---

### ref and Direct DOM Manipulation

**Vulnerable pattern:**

```jsx
// Using ref to bypass React's rendering and set innerHTML directly
function UserContent({ html }) {
    const ref = useRef(null);

    useEffect(() => {
        if (ref.current) {
            ref.current.innerHTML = html;  // bypasses React sanitization
        }
    }, [html]);

    return <div ref={ref} />;
}
```

**Why it fails:**

React's escaping applies only to values rendered through JSX expressions (`{value}`). Any DOM manipulation done through refs or direct DOM API calls bypasses React's rendering pipeline entirely. `innerHTML` set via a ref has no protection.

**Fixed pattern:**

```jsx
import DOMPurify from 'dompurify';

function UserContent({ html }) {
    return (
        <div
            dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }}
        />
    );
}
// dangerouslySetInnerHTML with DOMPurify is more explicit about the risk
// and centralizes the sanitization in one place
```

---

### SSR Hydration Mismatch

**Vulnerable pattern:**

```jsx
// Component that renders differently on server vs client
function UserGreeting() {
    // On the server: no window object, so userAgent is undefined
    // On the client: window.navigator.userAgent may have been spoofed
    const isMobile = typeof window !== 'undefined' && /Mobile/.test(navigator.userAgent);
    return <div>{isMobile ? 'Mobile user' : 'Desktop user'}</div>;
}

// More dangerous: server renders sanitized content,
// client hydrates with unsanitized content due to different code paths
```

**Why it fails:**

When the server-rendered HTML and the client-hydrated React tree differ, React patches the DOM to match the client tree during hydration. If the server renders a sanitized version of user content but the client-side code renders an unsanitized version, the sanitized server output is replaced with the unsanitized client output immediately after page load — before the user has visually noticed anything changed.

**Fixed pattern:**

```jsx
// Ensure identical rendering on server and client
// Sanitize once, pass the sanitized value to both SSR and hydration

// In getServerSideProps or equivalent:
export async function getServerSideProps() {
    const rawContent = await db.getContent();
    const sanitized = DOMPurify.sanitize(rawContent);  // server-side DOMPurify
    return { props: { content: sanitized } };
}

function Post({ content }) {
    // content is already sanitized — same value on server and client
    return <article dangerouslySetInnerHTML={{ __html: content }} />;
}
```

---

### eval() in useEffect or Event Handlers

**Vulnerable pattern:**

```jsx
// Dynamic code execution in React
function DynamicWidget({ script }) {
    useEffect(() => {
        eval(script);  // executes on every render when script changes
    }, [script]);

    return <div onClick={() => new Function(userCode)()} />;
}
```

**Why it fails:**

Same as the universal `eval()` section — arbitrary code execution. React context makes it slightly worse because `useEffect` runs after every render when dependencies change, meaning attacker-controlled `script` is executed repeatedly.

**Fixed pattern:**

```jsx
// Avoid eval() entirely
// If dynamic behavior is needed: use a safe expression evaluator
// or define a fixed set of actions the script can trigger

const ALLOWED_ACTIONS = {
    showModal: () => setModalVisible(true),
    scrollTop: () => window.scrollTo(0, 0),
};

function DynamicWidget({ action }) {
    const handler = ALLOWED_ACTIONS[action];
    if (!handler) return null;
    return <button onClick={handler}>Execute</button>;
}
```

---

### React DevTools in Production

**Vulnerable pattern:**

```jsx
// No production mode enforcement
// App served without NODE_ENV=production — React DevTools hooks remain active
// index.js:
ReactDOM.render(<App />, document.getElementById('root'));
// Without NODE_ENV=production, React runs in development mode
```

**Why it fails:**

React development mode runs additional checks and change detection cycles. More importantly, when React DevTools is installed in the browser, development-mode React exposes the entire component tree, props, and state to the DevTools extension — and by extension, to any browser extension that uses the DevTools API. In development mode, component internals are accessible via `__REACT_DEVTOOLS_GLOBAL_HOOK__`.

**Fixed pattern:**

```bash
# Build with production mode — this disables DevTools hooks
NODE_ENV=production npm run build

# Verify the bundle does not contain development mode checks:
grep '__DEV__\|process.env.NODE_ENV.*development' build/static/js/main.*.js
# Should return nothing in a production build
```

---

## 4. Vue.js

> **Applies to:** Projects with `vue` in `package.json`.
> **Quick detect:**
> ```bash
> cat package.json | grep '"vue"'
> ```
> **Not using Vue?** Skip to [Angular](#5-angular).

---

### v-html with User Content

**Vulnerable pattern:**

```html
<!-- Rendering user content with v-html -->
<div v-html="user.bio"></div>
<div v-html="comment.text"></div>
<div v-html="article.summary"></div>
```

**Why it fails:**

`v-html` sets `innerHTML` directly, bypassing Vue's template escaping. It is Vue's equivalent of React's `dangerouslySetInnerHTML`. Any user-controlled string rendered via `v-html` without sanitization is XSS.

**Fixed pattern:**

```html
<!-- Use text interpolation for plain text (escaped by default) -->
<div>{{ user.bio }}</div>

<!-- If HTML is required: sanitize before passing to template -->
<div v-html="sanitizedBio"></div>
```

```javascript
import DOMPurify from 'dompurify';

export default {
    computed: {
        sanitizedBio() {
            return DOMPurify.sanitize(this.user.bio);
        }
    }
}

// Or in the Options API setup:
// props: { bio: String },
// computed: { sanitizedBio() { return DOMPurify.sanitize(this.bio); } }
```

---

### VITE_SECRET and VUE_APP_ Variables

**Vulnerable pattern:**

```bash
# .env (Vite project)
VITE_API_SECRET=sk-private123
VITE_DATABASE_PASSWORD=dbpass456

# .env (Vue CLI project)
VUE_APP_STRIPE_SECRET=sk_live_xyz
VUE_APP_PRIVATE_KEY=-----BEGIN RSA PRIVATE KEY-----
```

**Why it fails:**

Vite exposes all variables prefixed with `VITE_` to client-side code via `import.meta.env`. Vue CLI exposes all `VUE_APP_` prefixed variables via `process.env`. These values are substituted at build time as string literals in the bundle. The prefix convention signals "this is for the client" — but developers often confuse it with "this is a private variable for the app."

**Fixed pattern:**

```bash
# .env — only public configuration values in VITE_/VUE_APP_
VITE_PUBLIC_API_URL=https://api.yourapp.example.com
VITE_STRIPE_PUBLISHABLE_KEY=pk_live_xyz

# Server-only secrets: kept in server-side environment variables
# never referenced in frontend source code
```

```bash
# Scan built bundle for potential secret patterns:
grep -rE '(sk_live|sk_test|-----BEGIN|password|secret)[^'"'"']' dist/assets/*.js
```

---

### Server-Side Template Injection in Vue SSR

**Vulnerable pattern:**

```javascript
// Vue SSR: building template strings from user input
const template = `<div>${req.query.greeting}</div>`;
const app = Vue.createApp({ template });
// If greeting = '{{ constructor.constructor("return process")().env }}':
// Evaluates as Vue template — accesses Node.js environment variables
```

**Why it fails:**

Vue's template compiler treats `{{ expression }}` as JavaScript expressions evaluated in the component's context. When a user-supplied string is used as a Vue template (rather than template data), the attacker's expressions are compiled and executed as Vue template code, with access to the component instance and potentially to Node.js globals in SSR context.

**Fixed pattern:**

```javascript
// Never build Vue templates from user input
// Pass user content as data to a fixed template:

const app = createSSRApp({
    template: '<div>{{ greeting }}</div>',  // fixed template
    data() {
        return { greeting: req.query.greeting };  // user input as data, not template
    }
});
// Vue escapes {{ greeting }} — user content is treated as text, not code
```

---

### Vue 2 Prototype Pollution via $set

**Vulnerable pattern:**

```javascript
// Vue 2: using $set with attacker-controlled key path
const path = req.query.key;   // e.g., '__proto__.isAdmin'
const value = req.query.value;

// Recursive $set with user-controlled path:
function setNestedValue(obj, path, value) {
    const parts = path.split('.');
    let current = obj;
    for (let i = 0; i < parts.length - 1; i++) {
        Vue.set(current, parts[i], current[parts[i]] || {});
        current = current[parts[i]];
    }
    Vue.set(current, parts[parts.length - 1], value);
}
```

**Why it fails:**

`Vue.set()` triggers Vue's reactivity system but ultimately calls `Object.defineProperty()` on the target object and key. If the key path includes `__proto__`, `constructor`, or `prototype`, the property is set on `Object.prototype`, polluting the prototype chain for all objects in the runtime — same impact as the generic prototype pollution vulnerability described in [Universal Frontend Security](#prototype-pollution).

**Fixed pattern:**

```javascript
// Validate key paths before using them in any dynamic property setting
function isSafePath(path) {
    const dangerousKeys = ['__proto__', 'constructor', 'prototype'];
    return !path.split('.').some(key => dangerousKeys.includes(key));
}

if (isSafePath(path)) {
    setNestedValue(obj, path, value);
}
```

---

### $el.innerHTML Bypass

**Vulnerable pattern:**

```javascript
// Directly manipulating DOM via $el, bypassing Vue's rendering
mounted() {
    this.$el.innerHTML = this.userContent;
},
updated() {
    this.$el.querySelector('.content').innerHTML = this.post.body;
}
```

**Why it fails:**

Same as React's `ref` + `innerHTML` pattern. Vue's template escaping applies only to values rendered through the template system (`{{ }}` interpolations and `v-bind` directives). Direct DOM manipulation via `this.$el.innerHTML` completely bypasses Vue's protection.

**Fixed pattern:**

```javascript
// Use v-html with sanitization instead of direct DOM manipulation
// In the template:
// <div v-html="sanitizedContent"></div>

computed: {
    sanitizedContent() {
        return DOMPurify.sanitize(this.userContent);
    }
}
```

---

### Vue Router Open Redirect

**Vulnerable pattern:**

```javascript
// Redirecting to user-supplied path after login
router.push(route.query.next);

// Or in a navigation guard:
router.beforeEach((to, from, next) => {
    if (!isAuthenticated()) {
        next({ path: '/login', query: { redirect: to.fullPath } });
    } else {
        next(to.query.redirect || '/');  // redirects to user-supplied URL
    }
});
```

**Why it fails:**

`router.push()` accepts full URLs including external ones. If `route.query.next` is `https://attacker.example.com`, Vue Router will redirect there. Unlike browser-level redirects, this is less obvious to detect because it goes through the SPA's router rather than `window.location`.

**Fixed pattern:**

```javascript
function safeRedirect(path) {
    // Only allow paths that start with / and don't start with //
    if (typeof path === 'string' && path.startsWith('/') && !path.startsWith('//')) {
        return path;
    }
    return '/';
}

// In navigation guard:
next(safeRedirect(to.query.redirect));
```

---

## 5. Angular

> **Applies to:** Projects with `@angular/core` in `package.json`.
> **Quick detect:**
> ```bash
> cat package.json | grep '@angular/core'
> ```
> **Not using Angular?** Skip to [Next.js / Nuxt.js](#6-nextjs-and-nuxtjs).

---

### bypassSecurityTrustHtml

**Vulnerable pattern:**

```typescript
// Explicitly bypassing Angular's DomSanitizer
import { DomSanitizer } from '@angular/platform-browser';

@Component({
    template: '<div [innerHTML]="trustedHtml"></div>',
})
export class CommentComponent {
    trustedHtml: SafeHtml;

    constructor(private sanitizer: DomSanitizer) {}

    setContent(userHtml: string) {
        // Bypasses Angular's sanitization — XSS if userHtml is user-controlled
        this.trustedHtml = this.sanitizer.bypassSecurityTrustHtml(userHtml);
    }
}
```

**Why it fails:**

`bypassSecurityTrustHtml()` explicitly tells Angular "I have manually verified this is safe; do not sanitize it." When called with user-controlled content, Angular renders it raw. The same applies to `bypassSecurityTrustScript()`, `bypassSecurityTrustStyle()`, `bypassSecurityTrustUrl()`, and `bypassSecurityTrustResourceUrl()`.

**Fixed pattern:**

```typescript
// Do not use bypassSecurityTrust* with user-controlled content
// Angular's [innerHTML] binding sanitizes by default — use it as-is:

@Component({
    template: '<div [innerHTML]="userHtml"></div>',
    // Angular sanitizes this automatically — no bypass needed
})
export class CommentComponent {
    userHtml: string = '';

    setContent(content: string) {
        this.userHtml = content;  // Angular sanitizes when binding to [innerHTML]
    }
}

// If you need richer HTML (e.g., iframes, certain attributes Angular strips):
// sanitize with DOMPurify first, THEN use bypassSecurityTrustHtml:
import DOMPurify from 'dompurify';

setContent(content: string) {
    const sanitized = DOMPurify.sanitize(content);
    this.trustedHtml = this.sanitizer.bypassSecurityTrustHtml(sanitized);
}
```

---

### Angular Template Injection

**Vulnerable pattern:**

```typescript
// Using JIT compiler to compile user-supplied template strings at runtime
import { Compiler, Component, NgModule } from '@angular/core';

@Injectable()
export class DynamicTemplateService {
    constructor(private compiler: Compiler) {}

    async renderUserTemplate(templateString: string) {
        @Component({ template: templateString })
        class DynamicComponent {}

        @NgModule({ declarations: [DynamicComponent] })
        class DynamicModule {}

        const factory = await this.compiler.compileModuleAndAllComponentsAsync(DynamicModule);
        // templateString is now compiled as Angular template — full expression access
    }
}
```

**Why it fails:**

Angular templates are compiled to JavaScript. A user-supplied template string is executed as Angular template code, with full access to the component's scope, injected services, and (depending on the component) potentially to global references. Angular template syntax includes expression evaluation (`{{ }}`) that accesses component properties and methods — an attacker-controlled template can read and exfiltrate data from the component's scope.

**Fixed pattern:**

```typescript
// Do not compile user input as Angular templates
// Render user content as data, not as a template:

@Component({
    // Fixed template — user content passed as a bound property, not template code
    template: '<div class="dynamic-content">{{ userContent }}</div>',
})
export class SafeDynamicComponent {
    @Input() userContent: string = '';
    // Angular's {{ }} escapes HTML — user cannot inject template expressions
}
```

---

### innerHTML Binding

**Vulnerable pattern:**

```html
<!-- Angular sanitizes [innerHTML] by default, but... -->
<div [innerHTML]="content"></div>

<!-- The issue: content was already processed by bypassSecurityTrustHtml upstream -->
```

```typescript
// Data flows from an HTTP response through a service that calls bypassSecurityTrust*
// By the time it reaches [innerHTML], Angular thinks it's already trusted
httpClient.get('/api/content').subscribe(data => {
    this.content = this.sanitizer.bypassSecurityTrustHtml(data.html);
    // Later rendered via [innerHTML] — Angular skips its own sanitization
});
```

**Why it fails:**

Angular's `[innerHTML]` sanitizes `string` values, but if the value is already a `SafeHtml` type (returned by `bypassSecurityTrustHtml()`), Angular skips sanitization. If `bypassSecurityTrust*` is called anywhere in the data pipeline before rendering, `[innerHTML]` provides no protection.

**Fixed pattern:**

```typescript
// Track SafeHtml vs string types carefully
// Prefer keeping content as plain strings until the template binding
httpClient.get<{html: string}>('/api/content').subscribe(data => {
    this.content = data.html;  // plain string — Angular sanitizes at [innerHTML]
});
```

---

### enableProdMode Missing

**Vulnerable pattern:**

```typescript
// main.ts — no production mode check
import { platformBrowserDynamic } from '@angular/platform-browser-dynamic';
import { AppModule } from './app/app.module';

platformBrowserDynamic().bootstrapModule(AppModule);
// Development mode by default — additional change detection cycles run
```

**Why it fails:**

Angular development mode runs change detection twice per cycle to detect side effects. This doubles the execution of lifecycle hooks and change detection logic, can surface timing-dependent behavior differences, and may behave differently from production in subtle ways that only appear under specific conditions. Additionally, development mode Angular exposes `ng.probe()` globally, which allows reading the component tree and state from the browser console.

**Fixed pattern:**

```typescript
// main.ts
import { enableProdMode } from '@angular/core';
import { platformBrowserDynamic } from '@angular/platform-browser-dynamic';
import { AppModule } from './app/app.module';
import { environment } from './environments/environment';

if (environment.production) {
    enableProdMode();
}

platformBrowserDynamic().bootstrapModule(AppModule);
```

---

### HttpClient XSRF Configuration

**Vulnerable pattern:**

```typescript
// app.module.ts — HttpClientModule without XSRF configuration
@NgModule({
    imports: [
        HttpClientModule,
        // No HttpClientXsrfModule — XSRF protection is not active
    ],
})
export class AppModule {}
```

```typescript
// Or: configured with wrong cookie/header names
HttpClientXsrfModule.withOptions({
    cookieName: 'MyCustomToken',  // but server reads 'XSRF-TOKEN'
    headerName: 'X-My-Token',    // but server checks 'X-XSRF-TOKEN'
})
// Mismatch = tokens never match = XSRF protection is a silent no-op
```

**Why it fails:**

`HttpClientModule` does not enable XSRF protection by default. `HttpClientXsrfModule` must be imported explicitly, and the cookie name and header name must match what the server reads. A mismatch between Angular's configured names and the server's expected names results in requests being made without any XSRF token — no error, no warning, the protection is simply absent.

**Fixed pattern:**

```typescript
@NgModule({
    imports: [
        HttpClientModule,
        HttpClientXsrfModule.withOptions({
            cookieName: 'XSRF-TOKEN',     // must match server cookie name
            headerName: 'X-XSRF-TOKEN',  // must match server header check
        }),
    ],
})
export class AppModule {}
```

```javascript
// Server-side: set the XSRF cookie on first load (read-only, not httpOnly)
// httpOnly: false is intentional — Angular reads it with JavaScript
res.cookie('XSRF-TOKEN', generateToken(), {
    httpOnly: false,  // Angular must read this with JS
    secure: true,
    sameSite: 'Strict',
});
```

---

## 6. Next.js and Nuxt.js

> **Applies to:** Projects with `next` or `nuxt` in `package.json`.
> **Quick detect:**
> ```bash
> cat package.json | grep -E '"next"|"nuxt"'
> ```

---

### NEXT_PUBLIC_ and NUXT_PUBLIC_ Variables

**Vulnerable pattern:**

```bash
# .env.local (Next.js)
NEXT_PUBLIC_STRIPE_SECRET=sk_live_xyz
NEXT_PUBLIC_INTERNAL_API_KEY=internal-service-key-abc

# .env (Nuxt.js)
NUXT_PUBLIC_DATABASE_PASSWORD=db_pass_xyz
```

**Why it fails:**

`NEXT_PUBLIC_` and `NUXT_PUBLIC_` (Nuxt 3) are prefixes that explicitly mark variables for client-side bundling. They are substituted as string literals in the browser bundle. The prefix is a deliberate design choice — it is not a mistake, but developers frequently put non-public values there because it is the most convenient way to access configuration in both client and server code.

**Fixed pattern:**

```bash
# Client-safe values only:
NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=pk_live_xyz
NEXT_PUBLIC_API_URL=https://api.yourapp.example.com

# Server-only secrets: no NEXT_PUBLIC_ prefix
STRIPE_SECRET_KEY=sk_live_xyz        # only available in getServerSideProps, API routes
DATABASE_URL=postgres://...          # only available in server-side code
```

```javascript
// Access server-only vars only in server-side contexts:
// pages/api/payment.js
export default async function handler(req, res) {
    const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
    // process.env.STRIPE_SECRET_KEY is undefined on the client — server only
}
```

---

### getServerSideProps Over-fetching

**Vulnerable pattern:**

```javascript
// pages/profile/[id].js
export async function getServerSideProps({ params }) {
    const user = await db.user.findUnique({ where: { id: params.id } });

    return {
        props: { user },  // passes the ENTIRE user object to the client
    };
}

// user object may contain:
// { id, name, email, passwordHash, role, internalNotes, isAdmin, apiKey, ... }
```

**Why it fails:**

`getServerSideProps` serializes the returned props object and embeds it as JSON in a `<script id="__NEXT_DATA__">` tag in the page HTML. Every field returned in `props` is visible in the browser's page source, even if the component only renders a subset of the fields. The same applies to Nuxt.js's `asyncData` and `useAsyncData` — the serialized payload appears in `window.__NUXT__`.

**Fixed pattern:**

```javascript
export async function getServerSideProps({ params }) {
    const user = await db.user.findUnique({
        where: { id: params.id },
        select: {             // select only what the page needs
            id: true,
            name: true,
            bio: true,
            avatarUrl: true,
            // passwordHash: never
            // apiKey: never
            // internalNotes: never
        },
    });

    return { props: { user } };
}
```

---

### API Routes Without Authentication

**Vulnerable pattern:**

```javascript
// pages/api/admin/users.js — no auth check
export default async function handler(req, res) {
    const users = await db.user.findMany();
    res.json(users);
}

// pages/api/internal/reset-cache.js
export default async function handler(req, res) {
    await cache.flush();
    res.json({ ok: true });
}
```

**Why it fails:**

Next.js API routes (`/pages/api/`) are accessible to any HTTP client — there is no automatic authentication. Unlike pages, they do not go through `getServerSideProps` where auth checks might exist. Many developers add auth checks to UI pages but forget that API routes are separate endpoints with their own request handling.

**Fixed pattern:**

```javascript
// Middleware approach: create a wrapper for authenticated routes
function withAuth(handler) {
    return async function(req, res) {
        const session = await getSession({ req });
        if (!session) {
            res.status(401).json({ error: 'Unauthorized' });
            return;
        }
        return handler(req, res, session);
    };
}

// pages/api/admin/users.js
export default withAuth(async function handler(req, res, session) {
    if (session.user.role !== 'admin') {
        res.status(403).json({ error: 'Forbidden' });
        return;
    }
    const users = await db.user.findMany({ select: { id: true, name: true, email: true } });
    res.json(users);
});
```

---

### SSRF via fetch() in getServerSideProps

**Vulnerable pattern:**

```javascript
// pages/preview.js
export async function getServerSideProps({ query }) {
    // Fetches a user-supplied URL — runs server-side
    const response = await fetch(query.url);
    const data = await response.json();
    return { props: { data } };
}

// Attacker: /preview?url=http://169.254.169.254/latest/meta-data/
// On cloud infrastructure: returns cloud provider metadata including IAM credentials
```

**Why it fails:**

`getServerSideProps` runs on the Node.js server, not in the browser. `fetch()` inside it issues requests from the server, which has access to the internal network, cloud metadata endpoints, and localhost services. This is a classic SSRF path that is easy to overlook because the code looks like typical client-side fetching.

**Fixed pattern:**

```javascript
export async function getServerSideProps({ query }) {
    const url = query.url;

    // Validate URL against an allowlist of permitted domains
    const allowedDomains = ['api.partner.example.com', 'data.public-service.com'];
    let parsed;
    try {
        parsed = new URL(url);
    } catch {
        return { notFound: true };
    }

    if (!allowedDomains.includes(parsed.hostname) ||
        !['https:'].includes(parsed.protocol)) {
        return { notFound: true };
    }

    const response = await fetch(url);
    const data = await response.json();
    return { props: { data } };
}
```

---

### next.config.js Rewrites as Open Proxy

**Vulnerable pattern:**

```javascript
// next.config.js
module.exports = {
    async rewrites() {
        return [
            {
                source: '/proxy/:path*',
                destination: ':path*',  // passes the full path as URL — open proxy
            },
        ];
    },
};
```

**Why it fails:**

A rewrite with `:path*` as the destination passes the entire URL path component as the destination URL. A request to `/proxy/https://169.254.169.254/latest/meta-data/` will be proxied to the metadata endpoint from the server side. This is an SSRF vulnerability built into the configuration file and applies to every user of the application.

**Fixed pattern:**

```javascript
// next.config.js — only proxy to known, fixed upstream origins
module.exports = {
    async rewrites() {
        return [
            {
                source: '/api/upstream/:path*',
                destination: 'https://api.known-partner.example.com/:path*',
                // destination is a fixed domain — user controls only :path*
                // and Next.js will encode path components before substituting
            },
        ];
    },
};
```

---

### next.config.js env Block Client Exposure

**Vulnerable pattern:**

```javascript
// next.config.js
module.exports = {
    env: {
        STRIPE_SECRET: process.env.STRIPE_SECRET,
        DATABASE_URL: process.env.DATABASE_URL,
        INTERNAL_API_KEY: process.env.INTERNAL_API_KEY,
    },
};
```

**Why it fails:**

Values in `next.config.js`'s `env` block are inlined into the JavaScript bundle at build time — they are accessible client-side if referenced anywhere in client-side code. Unlike `NEXT_PUBLIC_` variables (which require explicit opt-in), the `env` block does not give visual indication of whether each value is server-only or client-exposed. Any value placed here that is referenced in a component (rather than only in `getServerSideProps` or API routes) will appear in the browser bundle.

**Fixed pattern:**

```javascript
// next.config.js — do not put secrets in the env block
module.exports = {
    env: {
        // Only values that are intentionally public
        APP_VERSION: process.env.npm_package_version,
        NEXT_PUBLIC_API_URL: process.env.API_URL,
    },
    // Server-only secrets: access via process.env directly in server-side code
    // They are available there automatically without any next.config.js entry
};
```

---

### productionBrowserSourceMaps

**Vulnerable pattern:**

```javascript
// next.config.js
module.exports = {
    productionBrowserSourceMaps: true,
};
```

**Why it fails:**

`productionBrowserSourceMaps: true` generates `.map` files and serves them publicly alongside the JS bundle. The browser DevTools Source panel shows the full reconstructed source code to anyone who opens it. This is equivalent to publishing your application's source code.

**Fixed pattern:**

```javascript
// next.config.js
module.exports = {
    productionBrowserSourceMaps: false,  // default — do not set to true in production
};

// If you need source maps for error monitoring (Sentry, etc.):
// 1. Build with source maps enabled
// 2. Upload maps to your error monitoring service
// 3. Delete the .map files from the deployment before serving
// Sentry Next.js integration handles this automatically via @sentry/nextjs
```

---

## 7. Build Tool Security

> **Applies to:** Any project with a JavaScript build step (Webpack, Vite, Parcel, Rollup, esbuild).
> **Quick detect:**
> ```bash
> cat package.json | grep -E '"webpack"|"vite"|"parcel"|"rollup"|"esbuild"'
> ```

---

### Source Maps in Production Webpack and Vite

**Vulnerable pattern:**

```javascript
// webpack.config.js
module.exports = {
    mode: 'production',
    devtool: 'source-map',  // generates .map files served publicly
};

// vite.config.js
export default {
    build: {
        sourcemap: true,  // generates .map files in dist/
    },
};
```

**Why it fails:**

Source map files contain the full original source code with original file paths, variable names, and comments. They are automatically linked from the minified bundle via a `//# sourceMappingURL=` comment at the end of each JS file. Any browser or automated scanner can discover and read them.

**Fixed pattern:**

```javascript
// webpack.config.js — no source maps in production
module.exports = {
    mode: 'production',
    devtool: false,
};

// If uploading to error tracker only:
module.exports = {
    devtool: 'hidden-source-map',
    // Generates .map files but does NOT add the sourceMappingURL comment
    // Upload .map files to error tracker, then delete them before deploy
};
```

```javascript
// vite.config.js
export default {
    build: {
        sourcemap: false,  // default in production mode — leave it off
    },
};
```

---

### .env Files in Version Control

**Vulnerable pattern:**

```bash
# .gitignore does not include all .env variants
.env
# Missing:
# .env.local
# .env.development
# .env.production
# .env.staging
# .env.test
# .env.*.local
```

**Why it fails:**

`.env.local` and `.env.production` files often contain real credentials and are frequently not covered by a `.gitignore` entry that only lists `.env`. Once committed to a repository, even if removed in a later commit, the secrets remain in git history and are accessible via `git log -p`.

**Fixed pattern:**

```bash
# .gitignore — comprehensive .env exclusions
.env
.env.*
!.env.example
!.env.schema

# Audit existing git history for committed secrets:
git log --all --full-history -p | grep -E '(PASSWORD|SECRET|API_KEY|TOKEN)\s*='
```

```bash
# If secrets were already committed: they must be revoked, not just removed
# Use git-filter-repo to remove from history, then rotate all affected credentials
git filter-repo --path .env --invert-paths
```

---

### Debug Code in Production Builds

**Vulnerable pattern:**

```javascript
// Development utilities left in the codebase
if (process.env.NODE_ENV !== 'production') {
    window.debugAPI = api;
    window.store = store;
    console.log('Current user:', user);  // leaks user data to any open DevTools
}

// But the condition is sometimes wrong:
if (process.env.DEBUG) {  // process.env.DEBUG may be truthy in production
    enableAdminPanel();
}

// Or the import is there unconditionally:
import './debug-panel';  // loaded regardless of NODE_ENV
```

**Why it fails:**

Debug code that exposes internal APIs, stores, or admin panels via `window.*` is accessible to any user in the browser console. `process.env.NODE_ENV !== 'production'` works correctly if `NODE_ENV` is set to `production` in the build, but other environment variables (`DEBUG`, `VERBOSE`, `TESTING`) may not be set consistently.

**Fixed pattern:**

```javascript
// Use only NODE_ENV for production checks
if (process.env.NODE_ENV === 'development') {
    // This is removed by dead-code elimination in production builds
    setupDebugTools();
}

// For conditional imports: use dynamic import with tree-shaking
if (process.env.NODE_ENV === 'development') {
    import('./debug-panel').then(({ setupDebugPanel }) => setupDebugPanel());
}
```

```bash
# Verify debug code is removed from the production bundle:
grep -E 'debugAPI|window\.__.*=|console\.log' dist/assets/*.js
# Should return nothing
```

---

### Tree-Shaking Does Not Remove Side-Effect Imports

**Vulnerable pattern:**

```javascript
// Top-level import with side effects
import './admin/debug-panel';      // registers admin routes, logs environment config
import './internal/metrics-dump';  // exposes window.metricsData

// Even if nothing from these modules is explicitly used,
// tree-shaking will NOT remove them if they have side effects
// (and most modules that register routes or set window.* have side effects)
```

**Why it fails:**

Tree-shaking removes exports that are not imported and used. It does not remove modules that are imported for their side effects (anything that modifies global state, registers event listeners, sets `window.*`, or calls functions at module load time). A module that sets `window.adminPanel = createAdminPanel()` at the top level will always run when imported, regardless of whether any named export from it is used.

**Fixed pattern:**

```javascript
// Only import debug/admin modules conditionally
// Never at the top level of files that are part of the production build
if (process.env.NODE_ENV === 'development') {
    require('./admin/debug-panel');
}

// In package.json: mark your app source files as side-effect free
// to help bundlers tree-shake more aggressively
{
    "sideEffects": ["*.css", "src/polyfills.js"]
    // Omitting a file from sideEffects tells Webpack it has no side effects
    // and can be tree-shaken when not explicitly used
}
```

---

### Webpack DefinePlugin Hardcoding Secrets

**Vulnerable pattern:**

```javascript
// webpack.config.js
const webpack = require('webpack');

module.exports = {
    plugins: [
        new webpack.DefinePlugin({
            'process.env.API_SECRET': JSON.stringify(process.env.API_SECRET),
            'process.env.DB_PASSWORD': JSON.stringify(process.env.DB_PASSWORD),
        }),
    ],
};
```

**Why it fails:**

`DefinePlugin` performs text substitution at compile time. Every occurrence of `process.env.API_SECRET` in source code is replaced with the string literal value. The secret is then embedded as a plain string in the minified bundle, visible in DevTools or by downloading the JS file. The substitution happens before minification, and string literals are never removed by minification.

**Fixed pattern:**

```javascript
// webpack.config.js — only substitute public values
const webpack = require('webpack');

module.exports = {
    plugins: [
        new webpack.DefinePlugin({
            // Public configuration only
            'process.env.NODE_ENV': JSON.stringify(process.env.NODE_ENV),
            'process.env.PUBLIC_API_URL': JSON.stringify(process.env.PUBLIC_API_URL),
            // Never: API_SECRET, DB_PASSWORD, STRIPE_SECRET_KEY, etc.
        }),
    ],
};

// Server-side code that needs secrets: access process.env directly at runtime
// Those values are never substituted into the bundle
```

---

## 8. Dependency Security

> **Applies to:** All projects using npm, yarn, or pnpm.
> **Quick detect:**
> ```bash
> ls package.json package-lock.json yarn.lock pnpm-lock.yaml
> ```

---

### npm install Without package-lock.json

**Vulnerable pattern:**

```bash
# package-lock.json is in .gitignore
echo 'package-lock.json' >> .gitignore
git add .gitignore

# On CI or server: npm install resolves version ranges fresh
# package.json: "lodash": "^4.0.0"
# May install 4.17.21 today and 4.17.22 (potentially different) tomorrow
```

**Why it fails:**

`npm install` with a `package.json` version range (`^4.0.0`, `~4.0.0`, `*`) resolves to the latest matching version at install time. Without a lock file, two installs at different times may produce different dependency trees. A malicious update to a transitive dependency (a dependency of a dependency) can be introduced automatically. The lock file ensures reproducible installs — every install produces the exact same dependency tree.

**Fixed pattern:**

```bash
# Commit package-lock.json to version control
# Remove it from .gitignore if present
git rm --cached package-lock.json 2>/dev/null; true
echo '!package-lock.json' >> .gitignore

# On CI: use npm ci instead of npm install
# npm ci installs exactly what is in package-lock.json — does not update it
npm ci
```

---

### npm audit Not in CI

**Vulnerable pattern:**

```yaml
# CI pipeline — installs and builds without auditing
steps:
  - run: npm ci
  - run: npm run build
  - run: npm test
  # No security audit step
```

**Why it fails:**

Known CVEs accumulate in dependencies silently. `npm audit` checks installed packages against the npm security advisory database. Without running it in CI, vulnerabilities can exist for weeks or months before being noticed — often only discovered during an incident or an external pentest.

**Fixed pattern:**

```yaml
# CI pipeline
steps:
  - name: Install dependencies
    run: npm ci

  - name: Security audit
    run: npm audit --audit-level=high
    # Fails the build on high or critical severity vulnerabilities
    # Use --audit-level=moderate if you want stricter checks

  - name: Build
    run: npm run build

  - name: Test
    run: npm test
```

```bash
# For packages with no upstream fix: use npm audit --production
# to exclude dev-only dependencies from the audit
npm audit --production --audit-level=high
```

---

### Typosquatting

**Vulnerable pattern:**

```bash
# Typo in package name
npm install lodahs         # intended: lodash
npm install recat          # intended: react
npm install expres         # intended: express
npm install babel-cli      # may be different from @babel/cli

# Less obvious: legitimate-sounding variants
npm install event-stream   # the 2018 supply chain attack package
npm install crossenv       # intended: cross-env
```

**Why it fails:**

Typosquatted packages exist on npm and PyPI that closely resemble popular packages by name. Some have been used in targeted supply chain attacks. The `event-stream` incident in 2018 involved a malicious package injected as a transitive dependency that targeted cryptocurrency wallets. There is no automatic protection against installing the wrong package.

**Fixed pattern:**

```bash
# Before installing any new package: verify the package name on npmjs.com
# Check the package's GitHub repo, weekly downloads, and publish date

# After installing: verify package-lock.json shows the expected resolved URL
grep -A3 '"lodash"' package-lock.json
# "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz" — expected
# "resolved": "https://registry.npmjs.org/lodahs/..."                   — wrong package

# Use npm's package provenance for packages that support it (npm 9.5+):
npm install lodash --foreground-scripts
# Provenance metadata links the package to its source repository
```

---

### postinstall Hook Execution

**Vulnerable pattern:**

```bash
# Any npm install of a package that has a postinstall script runs it:
npm install some-package
# package.json of some-package:
# "scripts": { "postinstall": "node ./scripts/postinstall.js" }
# That script runs with the permissions of the installing user

# On CI with --unsafe-perm or as root: full system access
```

**Why it fails:**

npm `postinstall` scripts run during `npm install` with the same permissions as the npm process. A malicious package (or a compromised version of a legitimate package) can run arbitrary code during installation — accessing environment variables, reading SSH keys, exfiltrating CI secrets, or modifying the project files.

**Fixed pattern:**

```bash
# For packages that do not require postinstall scripts: disable them
npm ci --ignore-scripts

# Verify afterward that the build still works — some packages (node-gyp, bcrypt)
# require install scripts to compile native modules
# For those: run them explicitly with known packages only
npm rebuild bcrypt  # explicit, after ignoring scripts globally

# Audit installed packages for postinstall scripts:
cat node_modules/*/package.json | jq -r 'select(.scripts.postinstall) | .name + ": " + .scripts.postinstall'
```

---

### Unpinned Versions in package.json

**Vulnerable pattern:**

```json
{
    "dependencies": {
        "react": "*",
        "axios": "latest",
        "lodash": "^4.0.0",
        "moment": ">=2.0.0"
    }
}
```

**Why it fails:**

`*` and `latest` resolve to whatever is the current latest version at install time — including breaking changes or newly introduced vulnerabilities. `^4.0.0` allows any `4.x.x` version, meaning a `4.99.0` release with a vulnerability is automatically installed. The lock file prevents this on repeat installs, but a fresh install or `npm update` will pull the latest allowed version.

**Fixed pattern:**

```json
{
    "dependencies": {
        "react": "18.2.0",
        "axios": "1.6.8",
        "lodash": "4.17.21"
    }
}
```

```bash
# Pin to exact versions for security-sensitive projects
# Use a tool like Renovate or Dependabot to get PRs for version updates
# that go through your normal code review + CI process

# To pin all current versions:
npm shrinkwrap   # creates npm-shrinkwrap.json with exact resolved versions
```

---

### npm link and Local File Dependencies

**Vulnerable pattern:**

```json
{
    "dependencies": {
        "my-private-lib": "file:../my-private-lib",
        "internal-tools": "link:../../internal/tools"
    }
}
```

```bash
# Development workflow using npm link
cd my-private-lib && npm link
cd my-app && npm link my-private-lib
# my-private-lib is symlinked from the global npm prefix — outside the project
```

**Why it fails:**

File and link dependencies resolve to local paths on the developer's machine. When the application is deployed to CI or production, those paths may not exist, causing silent fallback to cached versions, install failures, or — if the path happens to exist on the production server and points to different code — unexpected behavior. Accidentally shipping a `package.json` with a `file:` dependency to production has caused production outages and, in some cases, exposure of development tooling code.

**Fixed pattern:**

```bash
# Before any production build: verify no file: or link: dependencies remain
grep -E '"file:|link:' package.json
# Should return nothing

# For private packages: publish to a private npm registry
# (GitHub Packages, AWS CodeArtifact, Verdaccio)
# and install by package name + registry configuration in .npmrc

# .npmrc
@yourcompany:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=${NODE_AUTH_TOKEN}
```

---

*Last reviewed: 2025 | Applies to: All web frontends — vanilla JS, jQuery, React, Vue.js, Angular, Next.js, Nuxt.js, and projects built with Webpack or Vite*
