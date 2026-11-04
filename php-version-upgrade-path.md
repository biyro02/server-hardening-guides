# PHP Version Upgrade Path

**Which PHP version to move to, the cheapest route there, and what breaks on the way**

> [php-application-hardening.md](php-application-hardening.md#2-legacy-php-5x-and-early-7x) tells you how to reduce risk in legacy PHP code. This guide answers the question that comes before it: "I am on PHP 5.6, 7.1, 7.4, 8.0, 8.1 or 8.2. Which version should I move to with the least effort that actually gets me out of known vulnerabilities, and what breaks on the way?" The short answer is that the version you can reach cheapest and the version that is safe to stop at are usually different, and confusing the two is how teams end up doing two upgrades instead of one.

---

## Table of Contents

1. [Support Status as of November 2026](#1-support-status-as-of-november-2026)
2. [Choosing a Target: Least-Effort Hop vs Safe Target](#2-choosing-a-target-least-effort-hop-vs-safe-target)
3. [Breaking Changes per Hop](#3-breaking-changes-per-hop)
4. [Framework and CMS Compatibility Gates](#4-framework-and-cms-compatibility-gates)
5. [Tooling That Makes the Hop Cheap](#5-tooling-that-makes-the-hop-cheap)
6. [If You Truly Cannot Upgrade](#6-if-you-truly-cannot-upgrade)
7. [Upgrade Runbook](#7-upgrade-runbook)

---

## 1. Support Status as of November 2026

> Sources: [php.net/supported-versions.php](https://www.php.net/supported-versions.php), [php.net/eol.php](https://www.php.net/eol.php), [endoflife.date/php](https://endoflife.date/php). Re-check these pages before acting on the table; dates are fixed per branch but the "status" column ages.

PHP branches get two years of active support (bug and security fixes) followed by two years of security-only fixes. Since PHP 8.1 the end dates are aligned to 31 December.

| Branch | Released | Active support ended / ends | Security support ended / ends | Last or current release | Status (Nov 2026) |
|---|---|---|---|---|---|
| 5.6 | 2014-08-28 | 2017-01-19 | 2018-12-31 | 5.6.40 | EOL for almost 8 years |
| 7.0 | 2015-12-03 | 2018-01-04 | 2019-01-10 | 7.0.33 | EOL |
| 7.1 | 2016-12-01 | 2018-12-01 | 2019-12-01 | 7.1.33 | EOL |
| 7.2 | 2017-11-30 | 2019-11-30 | 2020-11-30 | 7.2.34 | EOL |
| 7.3 | 2018-12-06 | 2020-12-06 | 2021-12-06 | 7.3.33 | EOL |
| 7.4 | 2019-11-28 | 2021-11-28 | 2022-11-28 | 7.4.33 | EOL for 4 years |
| 8.0 | 2020-11-26 | 2022-11-26 | 2023-11-26 | 8.0.30 | EOL |
| 8.1 | 2021-11-25 | 2023-11-25 | 2025-12-31 | 8.1.34 | EOL since last year |
| 8.2 | 2022-12-08 | 2024-12-31 | **2026-12-31** | 8.2.x | Security-only, **EOL in weeks** |
| 8.3 | 2023-11-23 | 2025-12-31 | 2027-12-31 | 8.3.x | Security-only, ~13 months left |
| 8.4 | 2024-11-21 | 2026-12-31 | 2028-12-31 | 8.4.x | Active until end of 2026, then security-only |
| 8.5 | 2025-11-20 | 2027-12-31 | 2029-12-31 | 8.5.x | Active, newest stable |

PHP 8.6 is scheduled for general availability on 19 November 2026 per the [PHP 8.6 release timetable](https://wiki.php.net/todo/php86). It is not released at the time of writing; do not target it until your framework and extensions declare support.

- [ ] **Treat PHP 8.2 as already EOL for planning.** It stops receiving security fixes on 31 December 2026. Any upgrade project that starts now and lands on 8.2 will go live on an unsupported version. 8.2 is not a target, it is a starting point.

  > **Why this matters:** "Security-only" still means fixes for issues reported to the PHP project. "EOL" means new vulnerabilities in the engine, `unserialize()`, PHAR handling, `ext/` parsers (XML, GD, mbstring) and the FPM SAPI are disclosed publicly and never patched upstream. Exploits for EOL branches do not need to be clever because nobody is racing to fix them.

- [ ] **Check what you are really running, per SAPI.** CLI and FPM can be different binaries, and Docker images pin their own version independent of the host.

  ```bash
  php -v                                  # CLI
  php-fpm -v 2>/dev/null || php-fpm8.3 -v # FPM binary name differs by distro
  docker exec CONTAINER php -v            # inside a container
  # From the outside, if expose_php is on (it should not be):
  curl -sI https://example.com | grep -i x-powered-by
  ```

- [ ] **Distinguish the upstream version from the distro package version.** `7.4.3-4ubuntu2.x` or `8.2.x-1~deb12u1` are vendor builds that may carry backported fixes. Scanners that only read the version string report false positives on these, and false negatives when the vendor has stopped patching. See [Section 6](#6-if-you-truly-cannot-upgrade).

---

## 2. Choosing a Target: Least-Effort Hop vs Safe Target

Two different questions:

- **Least-effort hop:** the newest version your code runs on with minimal changes. Often a minor bump inside the same major (7.1 to 7.4, 8.0 to 8.1).
- **Safe target:** the version you can actually stop at and run in production for a meaningful period while receiving security fixes.

When the least-effort hop lands on an EOL branch, it is a stepping stone, not a destination. Doing it in production means you pay for a full deploy, test and rollback cycle and are still exposed.

### Decision rule

- [ ] **Minimum safe target = the oldest branch with at least ~12 months of security support left on your planned go-live date.** Twelve months is the window you need to schedule the next upgrade without another emergency.

  As of November 2026:

  | Branch | Security support left on 2026-11-04 | Meets the 12-month rule? |
  |---|---|---|
  | 8.2 | ~2 months | No |
  | 8.3 | ~14 months | Barely. Fails for any go-live after about January 2027 |
  | 8.4 | ~26 months | Yes |
  | 8.5 | ~38 months | Yes |

- [ ] **Recommended target = the newest branch your dependency tree resolves on, 8.4 or 8.5.** The work to go from 8.3 to 8.4 or 8.5 is small compared to whatever got you to 8.x in the first place. Stopping at 8.3 buys about one year before you do this again.
- [ ] **Pick 8.5 if `composer why-not php 8.5` returns nothing and your required extensions are available for it.** Otherwise pick 8.4. Note that 8.5 removed the `disable_classes` ini directive (see [Section 3](#80-to-81-82-83-84-85)); if your hardening relies on it you need a replacement control before you switch.
- [ ] **Skip intermediate versions in production.** PHP does not need to be upgraded one minor at a time. You must read and fix every migration guide between your version and the target, but you can deploy straight from 7.4 to 8.4. Intermediate versions are useful in CI as diagnostic steps (7.4 prints deprecation notices for most things 8.0 removes), not as production stops.

### Worked example: PHP 7.1

| Option | Effort | Security result |
|---|---|---|
| 7.1 to 7.4 | Low. mcrypt removal (7.2), PCRE2 (7.3), and deprecation notices | Still EOL since November 2022. **Stepping stone only.** |
| 7.4 to 8.0+ | High. This is the big breaking hop: `each()`, `create_function()`, string/number comparison, warnings becoming `TypeError` | Required no matter what |
| 8.0 to 8.4/8.5 | Medium-low. Mostly deprecations, a handful of hard breaks | Supported until end of 2028 / 2029 |

Recommendation for 7.1: **target 8.4 (or 8.5).** Run the code on 7.4 in CI and staging with `error_reporting=E_ALL` to collect the deprecation notices that predict 8.0 failures, fix them, then cut production over directly to the target. If you ship 7.4 to production as an intermediate step, put a date on the second hop or you will stay on 7.4.

If the application is a WordPress site, the WordPress version gate (see [Section 4](#4-framework-and-cms-compatibility-gates)) makes this more urgent: on 7.1 you are frozen at WordPress 6.5.

### Recommendations by starting point

| You are on | Least-effort hop | Safe target | Notes |
|---|---|---|---|
| 5.6 | 7.0 to 7.4 (if `mysql_*`/`ereg` already gone) | 8.4 / 8.5 | Realistically a partial rewrite: DB layer, crypto, error handling. Often coupled with a framework major upgrade. Budget it as a project, not a ticket. |
| 7.1 | 7.4 | 8.4 / 8.5 | See worked example above. |
| 7.4 | none that is supported | 8.4 / 8.5 | All the pain is in 7.4 to 8.0. After that, 8.1 to 8.5 is incremental. Go straight to the target. |
| 8.0 | 8.1 (EOL) | 8.4 / 8.5 | 8.1 flags passing `null` to internal non-nullable parameters; noisy but deprecations only. |
| 8.1 | 8.2 (EOL in weeks) | 8.4 / 8.5 | Do not stop at 8.2 or 8.3. Dynamic properties (8.2) and implicit nullable types (8.4) are the main work. |
| 8.2 | 8.3 | 8.4 / 8.5 | Deadline is 31 December 2026. If 8.4 cannot ship by then, 8.3 is acceptable only with the next hop already scheduled. |
| 8.3 | 8.4 | 8.4 / 8.5 | Not urgent, but plan it for 2027. |

---

## 3. Breaking Changes per Hop

> Only changes that routinely break real legacy code or change security behaviour are listed. Read the full official guide for every hop between your version and the target; each one has "Backward Incompatible Changes" and "Deprecated Features" sub-pages.

Official migration guides:

| Hop | Guide |
|---|---|
| 5.6 to 7.0 | <https://www.php.net/manual/en/migration70.php> |
| 7.0 to 7.1 | <https://www.php.net/manual/en/migration71.php> |
| 7.1 to 7.2 | <https://www.php.net/manual/en/migration72.php> |
| 7.2 to 7.3 | <https://www.php.net/manual/en/migration73.php> |
| 7.3 to 7.4 | <https://www.php.net/manual/en/migration74.php> |
| 7.4 to 8.0 | <https://www.php.net/manual/en/migration80.php> |
| 8.0 to 8.1 | <https://www.php.net/manual/en/migration81.php> |
| 8.1 to 8.2 | <https://www.php.net/manual/en/migration82.php> |
| 8.2 to 8.3 | <https://www.php.net/manual/en/migration83.php> |
| 8.3 to 8.4 | <https://www.php.net/manual/en/migration84.php> |
| 8.4 to 8.5 | <https://www.php.net/manual/en/migration85.php> |

The sub-pages follow the pattern `migrationXX.incompatible.php` and `migrationXX.deprecated.php`.

### 5.6 to 7.0

- [ ] **`mysql_*` functions are gone.** Fatal "call to undefined function". Migrate to PDO or mysqli with prepared statements, see [mysql_* Functions](php-application-hardening.md#mysql_-functions). Do not reach for a `mysql_*` shim library that wraps mysqli; it preserves the string-concatenated queries.
- [ ] **`ereg*()` / `split()` are gone.** Replace with `preg_*()`. Delimiters and escaping differ, see [ereg() Functions](php-application-hardening.md#ereg-functions).
- [ ] **`preg_replace()` `/e` modifier is gone.** Use `preg_replace_callback()`. This removal closes a code-execution vector, see [The preg_replace /e Modifier](php-application-hardening.md#the-preg_replace-e-modifier).
- [ ] **Most fatal errors become `Error` exceptions.** `catch (Exception $e)` does not catch them; global handlers need `Throwable`. Code that relied on a fatal error to stop execution can now continue if something catches `Throwable` too broadly.
- [ ] **Uniform variable syntax.** `$$foo['bar']['baz']` and `$obj->$method['key']()` are evaluated left to right now. Silent behaviour change in dynamic dispatch code.
- [ ] **ASP tags (`<%`) and `<script language="php">` are removed.** Old templates stop being parsed as PHP and may be served as plain text, leaking source.
- [ ] **Hexadecimal strings are no longer numeric.** `"0x1A" == 26` is now false.

### 7.0 to 7.4 (minor hops)

- [ ] **7.1: calling a user function with too few arguments throws `ArgumentCountError`** instead of a warning. Common in old callback code.
- [ ] **7.1: arithmetic on non-numeric strings emits "A non-numeric value encountered".** This becomes `TypeError` in 8.0, so fix it here.
- [ ] **7.2: mcrypt is removed from core.** Re-encrypt stored data on a version that still has mcrypt before you upgrade; `MCRYPT_RIJNDAEL_256` is not AES-256. See [mcrypt Removed in PHP 7.2](php-application-hardening.md#mcrypt-removed-in-php-72).
- [ ] **7.2: `each()`, `create_function()`, `__autoload()` and string `assert()` are deprecated.** They are removed or neutralised in 8.0. `create_function()` is an `eval()` wrapper; removing it is a security improvement.
- [ ] **7.2: `count()` on a non-countable (null, scalar) warns.** Becomes `TypeError` in 8.0. Very common in legacy code that does `count($maybeNull)`.
- [ ] **7.3: PCRE moves to PCRE2.** Patterns that PCRE1 tolerated fail to compile, typically an unescaped hyphen inside a character class (`[\w-.]`). `preg_match()` returns `false` and emits a warning; validation code that treats `false` as "no match" can turn into a silent bypass or a silent rejection.
- [ ] **7.4: `$str{0}` curly-brace offsets, unparenthesised nested ternaries, `get_magic_quotes_gpc()`, `array_key_exists()` on objects and the `allow_url_include` ini directive are deprecated.** All become hard errors or removals in 8.0.
- [ ] **7.4: FFI arrives.** Make sure `ffi.enable` is not `1` in web SAPIs. See [PHP Hardening](wordpress-server-hardening.md#3-php-hardening).

### 7.4 to 8.0

This is the expensive hop. Plan most of your effort here.

- [ ] **String to number comparison changed.** Comparing a number with a non-numeric string now compares as strings: `0 == "foo"` is `false` (it was `true`). This closes a class of auth bypasses where `0` was compared with a password, token or role string. It does **not** fix magic hashes: `"0e123" == "0e456"` is still `true` because both are numeric strings. Keep `hash_equals()` and `===`, see [Type Juggling and Loose Comparison](php-application-hardening.md#type-juggling-and-loose-comparison). Also audit `switch` statements and `in_array()` without the strict flag, since their results may flip silently.
- [ ] **Removed: `each()`, `create_function()`, `get_magic_quotes_gpc()`, `$str{}` offsets, `(real)` and `(unset)` casts, `track_errors` / `$php_errormsg`.** Each is a fatal error on the first call.
- [ ] **PHP 4 style constructors are no longer constructors.** A method named like the class is now just a method. The object is created without running it, so properties stay uninitialised. Silent, and dangerous when the constructor sets up access checks.
- [ ] **Internal functions throw instead of warn.** Wrong argument count throws `ArgumentCountError`; `count()` on non-countables, arithmetic on arrays and non-numeric strings throw `TypeError`. Paths that previously "worked with a warning" now 500.
- [ ] **`assert()` no longer evaluates strings**, and assertion failures throw by default. Closes an `eval()` path, see [assert() with String Argument](php-application-hardening.md#assert-with-string-argument).
- [ ] **`@` no longer silences fatal errors.** Hidden failures become visible, which is good, but check `display_errors` is off before you find out in production.
- [ ] **Default `error_reporting` is now `E_ALL` and `display_startup_errors` is on by default.** If your production ini does not set these explicitly you now inherit noisier, more revealing defaults.
- [ ] **PDO's default error mode is now exceptions.** Uncaught `PDOException` stack traces can contain SQL and connection details. Make sure `display_errors=Off` and `zend.exception_ignore_args=On` in production.
- [ ] **Unparenthesised nested ternaries are a compile error.**
- [ ] **XML-RPC moved to PECL.** Old integrations calling `xmlrpc_*` break.
- [ ] **Not relevant to the upgrade decision:** named arguments, union types, `match`, attributes. They are new features; nothing forces you to use them. Note that `match` and `mixed` are now reserved, which breaks classes or functions with those names.

### 8.0 to 8.1, 8.2, 8.3, 8.4, 8.5

Each of these is incremental, but the deprecations add up. Fix deprecations as you go; they are the next version's fatal errors.

- [ ] **8.1: passing `null` to non-nullable parameters of internal functions is deprecated** (`strlen(null)`, `trim(null)`, `htmlspecialchars(null)`). By far the noisiest deprecation in legacy code. Fix at the source of the null, not with `(string)` casts sprinkled everywhere.
- [ ] **8.1: `htmlspecialchars()` / `htmlentities()` default flags change to `ENT_QUOTES | ENT_SUBSTITUTE`.** Single quotes are now escaped by default. A security improvement for single-quoted HTML attributes, but output changes; snapshot tests and any code that compares escaped strings will break.
- [ ] **8.1: mysqli's default error mode changes from silent to exceptions.** Code that checked `if (!$result)` now gets an uncaught `mysqli_sql_exception`. Same disclosure caveat as PDO above.
- [ ] **8.1: PDO MySQL (emulated prepares) and SQLite return native `int`/`float` instead of strings.** Breaks `=== '1'` comparisons on fetched columns. `PDO::ATTR_STRINGIFY_FETCHES` restores the old behaviour.
- [ ] **8.1: internal method return types.** Classes extending internal classes (`ArrayAccess`, `Iterator`, `JsonSerializable` implementations, `SessionHandlerInterface`) without compatible return types emit deprecations. `#[\ReturnTypeWillChange]` silences them on code that must still run on 7.x.
- [ ] **8.1: `Serializable` without `__serialize()`/`__unserialize()`, `FILTER_SANITIZE_STRING`, `strftime()`, `date_sunrise()` are deprecated.**
- [ ] **8.2: dynamic properties are deprecated** (`$this->undeclared = 1`). Legacy frameworks (CodeIgniter 3, older Zend/Laminas, many WordPress plugins) rely on this heavily. Declare properties, or add `#[\AllowDynamicProperties]` to the class as a temporary measure.
- [ ] **8.2: `utf8_encode()` / `utf8_decode()` and `"${var}"` string interpolation are deprecated.**
- [ ] **8.3: mostly safe.** Watch `unserialize()` now emitting `E_WARNING` instead of `E_NOTICE` on malformed input, `range()` argument validation, and `get_class()`/`get_parent_class()` without arguments being deprecated.
- [ ] **8.4: implicitly nullable parameter types are deprecated.** `function f(Foo $x = null)` must become `function f(?Foo $x = null)`. Mechanical, and Rector fixes it (see [Section 5](#5-tooling-that-makes-the-hop-cheap)); the `?Foo` syntax is valid since 7.1, so the fix is safe to deploy before the upgrade.
- [ ] **8.4: IMAP, OCI8, PDO_OCI and pspell are moved out of core to PECL.** If you use `imap_*()` for mailbox polling, either build the PECL extension or replace it with a userland IMAP library before upgrading.
- [ ] **8.4: `password_hash()` default bcrypt cost rises from 10 to 12.** About 4x more CPU per hash on login and registration. Pass `['cost' => ...]` explicitly if your login endpoint is CPU-bound, and expect `password_needs_rehash()` to return `true` for existing hashes.
- [ ] **8.4: changing `session.sid_length`, `session.sid_bits_per_character`, `session.use_only_cookies`, `session.use_trans_sid` is deprecated**, as is `trigger_error()` with `E_USER_ERROR` and `E_STRICT`.
- [ ] **8.5: the `disable_classes` ini directive is removed.** It no longer restricts anything. Remove it from your ini and move class restrictions elsewhere (container isolation, code review, `open_basedir`).
- [ ] **8.5: OPcache is always built in.** A `zend_extension=opcache.so` line now emits a warning. `opcache.enable` and `opcache.enable_cli` still apply.
- [ ] **8.5: backtick operator (`` `cmd` ``), non-canonical casts (`(integer)`, `(boolean)`, `(double)`, `(binary)`), `case` terminated with `;`, `null` as an array offset and `$http_response_header` are deprecated.** Backticks are a `shell_exec()` alias that `grep` for `shell_exec` misses; now is a good time to find them.

---

## 4. Framework and CMS Compatibility Gates

The PHP version you can run is often decided by your framework, not your own code. Check these before you set a target.

### WordPress

Source: [PHP Compatibility and WordPress Versions](https://make.wordpress.org/core/handbook/references/php-compatibility-and-wordpress-versions/), [wordpress.org/about/requirements](https://wordpress.org/about/requirements/).

| WordPress | Minimum PHP | Highest PHP listed as supported |
|---|---|---|
| 6.0 | 5.6 | 8.1 |
| 6.1 to 6.2 | 5.6 | 8.2 |
| 6.3 | 7.0 | 8.2 |
| 6.4 to 6.5 | 7.0 | 8.3 |
| 6.6 | 7.2.24 | 8.3 |
| 6.7 to 6.8 | 7.2.24 | 8.4 |
| 6.9 | 7.2.24 | 8.5 |
| 7.0 (released May 2026) | 7.4.0 | 8.5 |

The recommended PHP version on wordpress.org is 8.3 or newer.

- [ ] **Know the version your PHP freezes WordPress at.** WordPress refuses to install a core update that the server's PHP cannot run (the update may still be listed as available).
  - PHP 5.6: frozen at WordPress 6.2.
  - PHP 7.0 or 7.1: frozen at WordPress 6.5.
  - PHP 7.2 or 7.3: frozen at WordPress 6.9.
  - PHP 7.4 or newer: current.

  > **Why this matters:** WordPress officially supports only the latest branch. The security team backports fixes to older branches as a courtesy "when possible" (down to 4.7 at the time of writing), with no guarantee per vulnerability. In practice the bigger exposure is plugins and themes: they drop old PHP and old WordPress versions independently, and a plugin you cannot update is an open plugin CVE. A site stuck on PHP 7.1 is a site that will eventually stop receiving fixes for the code most likely to be attacked.

- [ ] **Check plugins separately.** Each plugin's "Requires PHP" header is what WordPress enforces on update. Run `wp plugin list --fields=name,version,update_version,update` (WP-CLI) on the target PHP version in staging; a plugin that has `update=available` but never installs is usually blocked by its PHP requirement.

### Laravel

Source: [Laravel release notes, support policy](https://laravel.com/docs/13.x/releases).

| Laravel | PHP | Security fixes until |
|---|---|---|
| 8 | 7.3 to 8.1 | 2023-01-24 (EOL) |
| 9 | 8.0 to 8.2 | 2024-02-06 (EOL) |
| 10 | 8.1 to 8.3 | 2025-02-04 (EOL) |
| 11 | 8.2 to 8.4 | 2026-03-12 (EOL) |
| 12 | 8.2 to 8.5 | 2027-02-24 |
| 13 | 8.3 to 8.5 | 2028-03-17 |

- [ ] **Upgrade PHP and Laravel together.** An app on Laravel 8 cannot reach PHP 8.2+ without a framework upgrade, and every Laravel version older than 12 is itself EOL. Target Laravel 12 or 13 on PHP 8.4/8.5. Laravel 5.x apps also carry the mcrypt issue, see [Laravel 5.x mcrypt Dependency](php-application-hardening.md#laravel-5x-mcrypt-dependency).

### Symfony

Source: [symfony.com/releases](https://symfony.com/releases).

| Symfony | Minimum PHP | Status (Nov 2026) |
|---|---|---|
| 5.4 LTS | 7.2.5 | Security fixes only, until February 2029 (extended) |
| 6.4 LTS | 8.1 | Bug fixes end November 2026, security until November 2027 |
| 7.4 LTS | 8.2 | Bug fixes until November 2028, security until November 2029 |
| 8.x | 8.4 | Current stable line, short support windows |

- [ ] **Symfony 5.4 still being patched does not make your PHP 7.x safe.** It keeps the framework patched; the runtime underneath is still EOL. Move to 7.4 LTS on PHP 8.4/8.5.

### CodeIgniter

Source: [CodeIgniter 4 server requirements](https://codeigniter.com/user_guide/intro/requirements.html).

| PHP | Minimum CodeIgniter 4 version |
|---|---|
| 8.2 | 4.2.11 |
| 8.3 | 4.4.4 |
| 8.4 | 4.6.0 |
| 8.5 | 4.7.0 |

Current CodeIgniter 4 requires PHP 8.2 or newer, and only the latest CI4 release is maintained.

- [ ] **CodeIgniter 3 is a blocker for PHP 8.2+.** The official 3.1.13 release is reported to work on 8.1 but not on 8.2 (dynamic properties, among others), and the CI3 branch has not shipped a release with 8.2 support. On PHP 8.4/8.5 the realistic options are migrating to CI4 (a rewrite of controllers and models, see [CI 3.x Patterns That Break Silently in CI 4](php-application-hardening.md#ci-3x-patterns-that-break-silently-in-ci-4)) or a community-maintained CI3 fork that you vet like any other dependency.

---

## 5. Tooling That Makes the Hop Cheap

> Run the tools on a modern PHP (for example in a `php:8.4-cli` container) even when the code targets an old version. The tools themselves need a recent PHP; what they analyse is controlled by configuration, not by the PHP that runs them.

### Static compatibility scan: PHPCompatibility

- [ ] **Use PHPCompatibility 10.x, not 9.3.5.** 9.3.5 was released in December 2019 and does not know about PHP 8.x changes. 10.0.0 is in alpha at the time of writing; the project's README recommends installing it with the `@dev` stability flag. It requires PHP_CodeSniffer 4 (4.0.1+ per its README) and PHP 7.2+ to run.

  ```bash
  composer config allow-plugins.dealerdirect/phpcodesniffer-composer-installer true
  composer require --dev phpcompatibility/php-compatibility:"^10.0.0@dev"

  # Confirm the standard is registered
  vendor/bin/phpcs -i

  # Report everything that will not work on 8.4 or later
  vendor/bin/phpcs -ps . --standard=PHPCompatibility \
      --runtime-set testVersion 8.4- \
      --extensions=php,inc \
      --ignore=vendor/,node_modules/ \
      --report=summary
  ```

  `testVersion 8.4-` means "8.4 and every later version". Use a range like `7.4-8.4` while you still need to run on both.

- [ ] **Do not treat a clean PHPCompatibility run as proof.** It is a static, syntax-level check. It cannot see behaviour changes such as string/number comparison, `null` reaching internal functions at runtime, or dynamic properties created through variables.

### Automated refactoring: Rector

- [ ] **Use Rector to apply the mechanical fixes** (`each()` to `foreach`, `create_function()` to closures, explicit nullable types, `$str{}` to `$str[]`).

  ```bash
  composer require --dev rector/rector
  ```

  ```php
  <?php
  // rector.php
  use Rector\Config\RectorConfig;

  return RectorConfig::configure()
      ->withPaths([__DIR__ . '/src', __DIR__ . '/app'])
      ->withPhpSets(php84: true);
  ```

  ```bash
  vendor/bin/rector --dry-run   # review the diff first
  vendor/bin/rector             # apply
  ```

  > **Why this matters:** `withPhpSets(php84: true)` applies every PHP set up to 8.4, which includes rules that *adopt* new syntax, not only rules that fix removed features. The result may no longer run on your current production version. Either apply it on the cut-over branch only, or run the sets for your current version first (for example `php74: true`) to get code that runs on both. Rector's documentation also offers `->withPhpLevel(N)` to raise the rule set gradually, one pull request per level.

### Static analysis: PHPStan

- [ ] **Run PHPStan configured for the target version.** It catches calls with wrong argument types and undefined methods that only fail at runtime on the new version.

  ```bash
  composer require --dev phpstan/phpstan
  ```

  ```yaml
  # phpstan.neon
  parameters:
      level: 3
      phpVersion: 80400
      paths:
          - src
  ```

  ```bash
  vendor/bin/phpstan analyse --memory-limit=1G
  ```

  Start at a low level on legacy code and generate a baseline (`--generate-baseline`) so the upgrade diff only shows new problems.

### Dependency resolution: Composer

- [ ] **Ask Composer what blocks the target version.**

  ```bash
  composer why-not php 8.4
  # Lists every installed package whose "require" excludes PHP 8.4
  ```

- [ ] **Resolve dependencies for the target, not for the PHP that runs Composer.** Set the platform version so `composer update` picks package versions that support the target:

  ```bash
  composer config platform.php 8.4.0
  composer update --dry-run     # see what would change
  composer update
  ```

  Remove or update `config.platform.php` after the cut-over. A stale platform pin is how teams end up resolving dependencies for a version they no longer run.

### Extension availability

- [ ] **Diff loaded extensions between current production and the target image.**

  ```bash
  # Current production
  php -m | sort > /tmp/ext-current.txt

  # Target image you will deploy (use your own built image, not the bare upstream one)
  docker run --rm your-registry/app-php:8.4 php -m | sort > /tmp/ext-target.txt

  diff /tmp/ext-current.txt /tmp/ext-target.txt
  ```

  Expect losses such as `mysql` (7.0), `mcrypt` (7.2), `xmlrpc` (8.0), `imap`/`oci8`/`pspell` (8.4). Also check `composer check-platform-reqs` inside the target image.

### Run the test suite on both versions

- [ ] **Run the same tests on the current and target versions in Docker** using the official images (`php:7.4-cli`, `php:8.4-cli`, `php:8.5-cli`, and so on).

  ```bash
  for v in 7.4 8.4; do
    echo "=== PHP $v ==="
    docker run --rm -v "$PWD":/app -w /app \
      -e PHP_INI_SCAN_DIR=/usr/local/etc/php/conf.d \
      php:$v-cli \
      php -d error_reporting=E_ALL -d display_errors=stderr vendor/bin/phpunit
  done
  ```

  If dependencies differ between versions, install them per version in separate directories or images; do not reuse one `vendor/` across both. If the official images lack an extension you need, build a small Dockerfile on top with `docker-php-ext-install`.

- [ ] **No tests? Record and replay.** For legacy apps without a test suite, capture a representative set of HTTP requests (access logs, a crawler, a HAR export) and replay them against old and new versions in staging, diffing status codes and response bodies. Crude, but it finds the 500s.

---

## 6. If You Truly Cannot Upgrade

None of the options below fix the problem. They buy time, at a price, while the upgrade happens. Every option here should come with an end date.

### Distro-backported packages

- [ ] **Use the distribution's PHP package, not an upstream build, while you wait.** Distributions backport security fixes into the version they shipped, for the life of the distro release.

  | Distribution | Ships PHP | Where to check coverage |
  |---|---|---|
  | Ubuntu 20.04 | 7.4 | Standard support ended; ESM via Ubuntu Pro. [ubuntu.com/about/release-cycle](https://ubuntu.com/about/release-cycle) |
  | Ubuntu 22.04 | 8.1 | Standard support, then ESM via Ubuntu Pro |
  | Ubuntu 24.04 | 8.3 | Standard support |
  | Debian 11 (bullseye) | 7.4 | Debian LTS ended 31 August 2026. Only paid ELTS from here. [wiki.debian.org/LTS](https://wiki.debian.org/LTS) |
  | Debian 12 (bookworm) | 8.2 | Debian security, then Debian LTS |
  | Debian 13 (trixie) | 8.4 | Debian security |
  | RHEL / Alma / Rocky | per AppStream module | [RHEL Application Streams Life Cycle](https://access.redhat.com/support/policy/updates/rhel-app-streams-life-cycle) |

  On Ubuntu, `pro security-status` shows which installed packages are covered and by which service. On Debian, read `/usr/share/doc/php*-common/changelog.Debian.gz` to see which CVEs were actually backported.

  > **Why this matters:** Backports cover CVEs the vendor decides to fix in the packages they ship. They do not cover PHP versions installed from third-party repositories, PECL extensions you compiled, or your Composer dependencies. Third-party PPA or repository builds of EOL branches are not a security fix source unless the maintainer explicitly says so.

### Commercial extended lifecycle support

- [ ] **Consider paid extended support only as a bridge with a dated exit.** Options at the time of writing:
  - **TuxCare Extended Lifecycle Support for PHP:** patched builds of EOL branches. Coverage of specific branches varies by channel (some list 5.6 to 8.1, some up to 8.2); check [docs.tuxcare.com/els-for-languages/php/](https://docs.tuxcare.com/els-for-languages/php/) for the current list.
  - **Freexian Extended LTS (ELTS):** extends Debian releases after Debian LTS ends, for the packages subscribers use. [freexian.com/lts/extended](https://www.freexian.com/lts/extended/)
  - **Zend PHP LTS:** vendor-stated coverage of 7.4 through December 2026 and 8.1 through December 2027. Note that 7.4 coverage ends within weeks.

  Verify the exact branches, dates and CVE response times with the vendor before you sign. Ask specifically how long after an upstream fix their build ships it.

### Compensating controls

These reduce the blast radius. They do not reduce the number of exploitable bugs.

- [ ] **Isolate the legacy runtime in its own container** with a read-only filesystem, dropped capabilities and no access to other services' networks. See [Docker Security](linux-server-hardening.md#6-docker-security).
- [ ] **Restrict network egress.** Most PHP exploitation chains need to fetch a second stage or call back. A container that can reach only its database and a mail relay turns many RCEs into dead ends.
- [ ] **Virtual patching at the WAF** (ModSecurity with the OWASP CRS, or managed WAF rules). Effective against HTTP-borne exploits with known payloads; ineffective against memory corruption reached through legitimate-looking input (file uploads, `unserialize()`, image parsing). See [WAF Rules](cloudflare-hardening.md#6-waf-rules).
- [ ] **`disable_functions`, `open_basedir`, no `allow_url_include`.** See [PHP Hardening](wordpress-server-hardening.md#3-php-hardening). Be aware that public `disable_functions` bypass exploits exist that abuse unpatched memory-safety bugs in exactly the old engines you are trying to protect; on an EOL runtime this control is weaker than it looks.
- [ ] **Apply the code-level mitigations** in [Legacy PHP (5.x and Early 7.x)](php-application-hardening.md#2-legacy-php-5x-and-early-7x).
- [ ] **Track CVEs for the exact branch you run.** See [vulnerability-intelligence.md](vulnerability-intelligence.md) for where to look them up. If a new engine CVE is reachable from your app and your vendor has no fix, that is your upgrade deadline.

---

## 7. Upgrade Runbook

Work through these in order. Each step should be done before the next starts.

### Inventory

- [ ] **Record the current PHP version for every SAPI** (CLI, FPM, cron, queue workers) and every host or image. Workers and cron jobs are the ones that get forgotten and stay on the old version.
- [ ] **Export the current effective configuration.**

  ```bash
  php -i > php-info-current.txt
  php --ini                         # which ini files are loaded
  php -m | sort > ext-current.txt
  ```

- [ ] **List the framework, CMS and plugin versions** and their PHP ranges ([Section 4](#4-framework-and-cms-compatibility-gates)).
- [ ] **Pick the target** with the rule in [Section 2](#2-choosing-a-target-least-effort-hop-vs-safe-target) and write down the date by which it must be live.

### Compatibility scan

- [ ] **Run `composer why-not php X.Y`** and plan the dependency updates.
- [ ] **Run PHPCompatibility with `testVersion X.Y-`** and triage findings.
- [ ] **Run PHPStan with `phpVersion` set to the target.**
- [ ] **Apply Rector sets** in a branch, review the diff, commit separately from manual fixes.
- [ ] **Grep for the usual suspects** that tools miss in dynamic code:

  ```bash
  grep -rnE '\b(mysql_|ereg|split\(|each\(|create_function|mcrypt_|utf8_(en|de)code)' \
       --include='*.php' --include='*.inc' . | grep -v vendor/
  grep -rn '`' --include='*.php' . | grep -v vendor/ | grep -vE '^[^:]+:[0-9]+:\s*(//|\*|#)'   # backticks, minus comment lines
  ```

### Staging

- [ ] **Build the target image from a pinned tag** (`php:8.4.x-fpm`, not `php:latest` or `php:8`).
- [ ] **Port your php.ini settings explicitly.** On Debian and Ubuntu, each version has its own config tree (`/etc/php/7.4/...` vs `/etc/php/8.4/...`). Custom files in the old `conf.d` are not carried over; installing a new version silently gives you stock defaults.
- [ ] **Run with `error_reporting=E_ALL` and log deprecations** to a file in staging. Every deprecation is a future fatal error.
- [ ] **Exercise background work:** cron jobs, queue workers, scheduled imports, email sending, PDF/image generation. These use extensions and code paths web tests do not touch.

### Dual-run

- [ ] **Run the test suite (or request replay) on both versions in CI** until the cut-over is complete. Fail the build on any new error on the target version.
- [ ] **Keep code runnable on both versions** until production has fully switched. Do not merge target-only syntax before then.
- [ ] **Re-check stored data that changes format:** mcrypt ciphertexts (7.2), password hashes (rehash on login after 8.4's cost change), serialized objects in sessions, cache and queues (class changes can break `unserialize()`).

### Canary

- [ ] **Route a small share of traffic, or one worker pool, to the new version first.** Watch the error rate, 5xx rate, PHP-FPM slow log and response time for at least one full business cycle (including nightly jobs).
- [ ] **Flush or version shared caches and sessions** if old and new versions share them and serialized formats differ.

### Rollback

- [ ] **Keep the previous image tag deployable** and verify you can switch back in minutes. Practise it once in staging.
- [ ] **Avoid irreversible data changes during the canary window.** Re-encryption and password rehashing should be either backward-readable or done after rollback is no longer needed.

### Post-upgrade: re-harden php.ini

New versions change defaults and remove directives. Your old hardening does not automatically carry over, and some of it silently stops working.

- [ ] **Diff the effective configuration against the pre-upgrade export.**

  ```bash
  php -i > php-info-new.txt
  diff <(grep -E '=>' php-info-current.txt | sort) <(grep -E '=>' php-info-new.txt | sort)
  ```

- [ ] **Set production values explicitly** instead of relying on defaults that changed:

  ```ini
  display_errors = Off
  display_startup_errors = Off      ; on by default since 8.0
  log_errors = On
  error_reporting = E_ALL           ; default since 8.0, set it anyway
  zend.exception_ignore_args = On   ; keeps arguments out of stack traces
  expose_php = Off
  allow_url_include = Off           ; deprecated since 7.4, keep it explicit until removed
  ffi.enable = preload              ; never 1 on web SAPIs (7.4+)
  session.use_strict_mode = 1
  session.cookie_httponly = 1
  session.cookie_secure = 1
  session.cookie_samesite = Lax
  ```

- [ ] **Remove directives that no longer exist or no longer work:** `safe_mode`, `magic_quotes_*`, `register_globals` (all gone since 5.4), `track_errors` and `assert.quiet_eval` (8.0), `disable_classes` (8.5), and the `zend_extension=opcache.so` line (8.5). PHP may only warn at startup, or not at all, so a dead directive looks like an active control.
- [ ] **Stop customising session ID settings on 8.4+** (`session.sid_length`, `session.sid_bits_per_character`). Make sure your session storage accepts the default 32-character IDs.
- [ ] **Re-check `disable_functions`** against the new version's function list, and add `shell_exec`-equivalents and `mail`/`putenv` as described in [PHP Hardening](wordpress-server-hardening.md#3-php-hardening).
- [ ] **Re-check OPcache settings,** especially `opcache.restrict_api` (an empty value means unrestricted) and, on 8.4+, JIT: `opcache.jit` now defaults to `disable`, so set it explicitly if you intend to use JIT.
- [ ] **Re-run your external checks:** confirm no `X-Powered-By` header, error pages do not leak traces, and `phpinfo()` or test files are not reachable.
- [ ] **Decommission the old runtime** (packages, images, FPM pools, old `/etc/php/X.Y` trees) once rollback is no longer needed. A forgotten old FPM pool on the same host is still an exposed EOL runtime.
- [ ] **Put the next upgrade in the calendar** for no later than 12 months before the new branch's security end date.

---

*Last reviewed: 2026-11 | Applies to: PHP 5.6 to 8.5, WordPress, Laravel, Symfony, CodeIgniter and framework-free PHP applications*
