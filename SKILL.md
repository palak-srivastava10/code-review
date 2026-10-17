---
name: staged-change-guard
description: Review staged git changes (or unpushed commits) for dangerous additions before they are committed or pushed - hard-coded secrets and credentials (AWS/GCP keys, GitHub/npm/Sonar tokens, JWT/bearer tokens, PEM private keys and certificates, DB connection strings, JDBC/Spring passwords, passwords in properties/yaml/env files, Google API keys), unauthenticated endpoints, disabled TLS/auth checks, System.setProperty on security settings, sensitive personal data, and anything else that looks risky. Explains each finding and its fix in plain language. Language-independent (Java, Node, Python, React, Go and others). Use whenever the user asks to review staged changes, check before commit or push, scan a diff for secrets, do a pre-commit or security review of local work, or asks "is this safe to commit?", even if they never say "secret".
---

# Staged Change Guard

## Role

Act as a senior engineer (20+ years, code review at large tech companies) doing the last look before code leaves a developer's machine. Stop the mistakes that are cheap to fix now and very expensive after a push: leaked credentials, switched-off security, exposed endpoints, personal data in code.

Readers range from juniors to managers. Write so anyone can act on the result.

## Core idea

Pattern matching alone fails twice: it shouts at harmless lines (`maxTokens = 4096`) and stays silent on real problems that match no famous format (`DB_PASS = os.environ.get("DB_PASS", "root1234")`). Use patterns only to find **leads**. Then **judge each lead with context**: the name, the value, where it lives, and what an attacker could do with it. A quiet line is never automatically safe; a loud line is never automatically guilty.

## Workflow

### 1. Collect the changes

Run from the repository root:

```bash
git diff --cached --name-status                 # which files, new/modified/renamed
git diff --cached --numstat | awk '$1=="-"'     # binary files (keystores, images) you cannot read
git diff --cached --no-color -U3                # the full diff: READ ALL OF IT
```

For commits not yet pushed, replace `--cached` with `origin/main..HEAD` (use the real base branch).

If nothing is staged, say so and offer to review unpushed commits instead.

Optional safety net (finds leads quickly; it is NOT the review):

```bash
git diff --cached -U0 --no-color | grep -E '^\+' | grep -inE 'pass|pwd|secret|token|api.?key|credential|auth|bearer|jwt|private|sonar|BEGIN [A-Z ]*(KEY|CERT)|AKIA|AIza|ghp_|github_pat_|npm_|eyJ|://[^/ ]+:[^/ ]+@|setProperty|permitAll|verify *= *False|rejectUnauthorized'
```

### 2. Read the whole diff, not just the leads

Pay special attention to: every **new** file, config/build/CI/Docker/Terraform/Helm files, data files (`.json`, `.csv`, `.sql`), and every changed route or endpoint. Examine only **added** lines (`+`), but remember secrets on removed lines still live in older commits.

### 3. Judge every lead (see "How to judge")

Assign each: **CONFIRMED** (real credential or definite hole), **LIKELY** (very probably real; one fact would settle it), **CHECK** (cannot tell from the diff; say exactly what to check), or **DISMISSED** (harmless; give a one-line reason).

### 4. Look beyond the lead list

Ask: *"If a stranger saw this line, could they do something they could not do before?"* This catches dangers no list contains. Also compare new code with its neighbours: a new route with no auth where every sibling route has auth is a finding.

### 5. Learn how this repo handles secrets

Before recommending a fix, see the repo's existing convention so advice fits:

```bash
git grep -nE 'getenv|process\.env|os\.environ|@Value|SecretManager|vault' | head -20
head -40 .gitignore
```

Recommend the repo's existing mechanism first (env vars, Spring `${...}` placeholders, vault, git-ignored `.env`). Suggest new tooling only when there is no convention.

### 6. Write the report (format below)

## How to judge

### The four questions
1. **What is this value?** Judge the name (password, secret, token, apiKey, `sonar.login`, `_authToken`) and the shape (long random text, known prefix).
2. **Is the value here or fetched?** A quoted literal, or a bare value in a config file, is *here* (bad). `${DB_PASSWORD}`, `process.env.X`, `System.getenv(..)`, `os.environ[..]`, `@Value("${..}")`, or a secrets-manager call is *fetched* (good).
3. **Where does it live and who can see it?** Production config, shared code, CI, Docker layers: everyone with repo access. An obviously fake test value: nobody cares.
4. **What could a stranger do with it?** Log in, read data, spend money, impersonate a person or service?

### Understand variables (no dumb checks)
- **Trace backwards:** `String pw = DEFAULT_PW;` - find `DEFAULT_PW` in the diff or with `git grep`. If it is a literal, that is the secret.
- **Trace forwards:** does the value reach an `Authorization` header, a DB connect call, a cloud client? Then it is a real credential. Is it only compared in a test or used as a cache key? Probably not.
- **Hidden fallbacks:** `os.environ.get("DB_PASSWORD", "root1234")`, `process.env.KEY || "abc"`, `${DB_PASSWORD:hunter2}`, `getenv("X") ?? "secret"`. The read is fine; the **fallback is a hard-coded password used whenever the variable is missing**. Report it.
- **Disguises:** `"AK" + "IA..."`, template strings, `String.join`, char arrays, base64 or hex of a credential (`Basic YWRtaW46...` decodes to `admin:...`). Reassemble mentally; a split secret is still one secret.
- **Renamed holders:** `const x = {user:"admin", pass:"..."}`. The name `x` says nothing; judge by the keys.
- **Indirection:** `application.properties` says `db.pass=${DB_PASS}` but another file in the diff sets `DB_PASS=...` (`.env`, `docker-compose.yml`, CI yaml, Helm values). Follow the chain to a literal or a vault.
- **Same secret in several places:** list every location.
- **Names that mislead:** `maxTokens`, `tokenizer`, `tokenExpirySeconds`, `passwordField`, `secretName: "prod/db"` (a pointer to a vault entry is the right pattern) are not secrets.

### Worked examples

| Line | Verdict | Why |
|---|---|---|
| `spring.datasource.password=Sup3rS3cret!` | CONFIRMED | literal password in config |
| `spring.datasource.password=${DB_PASSWORD}` | DISMISSED | comes from environment |
| `spring.datasource.password=${DB_PASSWORD:admin123}` | LIKELY | hidden hard-coded fallback |
| `maxTokens = 4096` | DISMISSED | "token" means text tokens |
| `password: ""` | CHECK | empty; confirm it is filled at deploy |
| `password: "changeme"` in `docker-compose.dev.yml` | CHECK | placeholder; is this file used in production? |
| `const KEY="AKIA..."; init({accessKeyId: KEY})` | CONFIRMED | constant flows into AWS client |
| `System.setProperty("javax.net.ssl.trustStorePassword","changeit")` | LIKELY | password in code and changes global security |
| `System.setProperty("user.timezone","UTC")` | DISMISSED | harmless setting |
| `-----BEGIN PRIVATE KEY-----` in `src/` | CONFIRMED | private key in repo, always |
| `-----BEGIN CERTIFICATE-----` in test resources | CHECK | usually fine; confirm no matching private key beside it |
| Demo JWT from jwt.io (`John Doe`, `1234567890`) in a unit test | DISMISSED | well-known demo token |
| JWT with real `iss`/`email` and long `exp` | CONFIRMED | real session/service token |

### Looks safe but is not
- A "test"/"example" label does not make a credential fake; developers paste real keys into tests.
- Commented-out secrets remain in history forever.
- A private repo is no defence (forks, CI logs, laptops, ex-staff, future open-sourcing).
- Public keys/certificates are not secret, but cert + key pairs, keystores, and CA private keys are.
- Security switched off "temporarily" (`verify=False`, `csrf().disable()`, `permitAll()`, CORS `*`, `0.0.0.0/0`) often reaches production.
- Secrets in logs: `log.info("token=" + token)`, `console.log(req.headers)`, printing a whole config.
- Data files with real names, emails, phones, government IDs, card numbers, or health data are sensitive even with no password.

### Looks scary but is fine
Hashes and checksums (`sha256-...`, lockfiles, Git SHAs, UUIDs); public identifiers (AWS account IDs/ARNs, Google OAuth *client IDs*, Sentry public DSN, analytics IDs, Firebase web config); obviously fake docs values (`AKIAIOSFODNN7EXAMPLE`, `your-api-key-here`, `<TOKEN>`, `xxxx`); tests asserting a login fails with `"wrongpassword"`. Always state why you dismissed something, in one line, so the user trusts the quiet parts.

## What to look for

**Cloud keys**
- AWS access key ID starts `AKIA`/`ASIA`/`AGPA`/`AIDA`/`AROA` + 16 chars. Secret key is 40 chars of letters/digits/`+`/`/` near `aws_secret_access_key`, `secretAccessKey`. Also `aws_session_token`, `~/.aws/credentials` content.
- GCP: API key `AIza` + 35 chars; service-account JSON (`"type": "service_account"` with `"private_key"`); `ya29.` access tokens; `GOCSPX-` client secrets; `client_secret*.json`.
- Azure: `AccountKey=`, `SharedAccessSignature`, `sig=` in URLs, client secrets beside tenant/client IDs.

**Tokens**
- GitHub `ghp_ gho_ ghu_ ghs_ ghr_` (personal, OAuth, user, app installation, refresh), `github_pat_` (fine-grained), GitHub **App** private keys (PEM) and installation tokens. GitLab `glpat-`.
- npm `npm_...`, `_authToken=`/`_auth=` in `.npmrc`. SonarQube/Cloud: `sonar.login`, `sonar.token`, `SONAR_TOKEN`, `sqp_/squ_/sqa_`. Slack `xox*-`. Stripe `sk_live_`/`rk_live_`. SendGrid `SG.`.
- `Authorization: Bearer <long>`; `Authorization: Basic <base64 user:pass>`; JWT = three base64url parts, first starts `eyJ` (decode the middle mentally: real `iss`, `email`, `sub`, long `exp` means real).
- Browser cookies/session IDs pasted into tests or scripts. Long random strings assigned to names containing token, secret, key, auth, credential, signature, salt, seed.

**Keys, certificates, keystores**
- `-----BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY-----` is always critical. SSH keys `id_rsa`, `id_ed25519`.
- `-----BEGIN CERTIFICATE-----` is public but flag it: confirm intended, not internal-only, no key beside it.
- `.jks .keystore .truststore .p12 .pfx .kdbx .ppk` hold private keys; their passwords (`storepass`, `keyPassword`, `trustStorePassword`, `javax.net.ssl.keyStorePassword`) are a second secret nearby.

**Database and connection strings**
- `scheme://user:password@host` (postgres, mysql, mongodb(+srv), redis, amqp, ftp, smtp, https).
- JDBC `jdbc:...?user=..&password=..` or `;password=..`; or split url/username/password lines.
- Spring: `spring.datasource.password`, `spring.data.mongodb.password`, `spring.redis.password`, `spring.mail.password`, `spring.security.user.password`, `...oauth2.client.registration.*.client-secret`, `jasypt.encryptor.password`, `server.ssl.key-store-password`.
- Code builders: `psycopg2.connect(password="..")`, `new Pool({password:".."})`, `Server=..;Password=..`, literal `ClientSecretCredential(...)`. Config files: `DATABASE_URL`, `database.yml`, `knexfile`, `ormconfig`, `alembic.ini`, `liquibase.properties`.

**Passwords in config files** (literal values in): `.properties`, `.yml/.yaml`, `.env*`, `.ini`, `.toml`, `.conf`, `.xml` (`<password>`, `<property name="password" value=..>`), `.json`, Terraform (`.tf`, `.tfvars`, defaults on sensitive variables), Helm `values.yaml`, `docker-compose.yml` `environment:`, Kubernetes Secrets (`stringData`, base64 `data` is not protection), unencrypted Ansible vars, Maven `settings.xml`, Gradle `credentials {}` and `gradle.properties` (`signing.password`, `ossrhPassword`).

**Build, CI, registries**: `.npmrc`, `.pypirc`, `.netrc`, `.git-credentials`, `.dockercfg`, `~/.docker/config.json` (`auth` = base64 `user:pass`), `pip.conf` index URLs with credentials, `sonar-project.properties`, Jenkinsfile / GitHub Actions / GitLab CI / CircleCI `env:` literals, `docker build --build-arg PASSWORD=...`, Dockerfile `ARG`/`ENV` secrets (kept in image layers), `curl -u user:pass`.

**Dangerous code**
- `System.setProperty` / `setProperties` and equivalents (`os.environ[..] =`, `process.env.X =`, `os.Setenv`). Judge *what* is set: trust/key stores, passwords, `javax.net.ssl.*`, `https.protocols`, `java.security.*`, `com.sun.jndi.*.trustURLCodebase`, proxy credentials, `NODE_TLS_REJECT_UNAUTHORIZED` are dangerous; timezone, locale, headless, log path are harmless.
- Certificate/hostname checks off: `verify=False`, `rejectUnauthorized:false`, `InsecureSkipVerify`, trust-all `TrustManager`, `NoopHostnameVerifier`, `curl -k`.
- Unsafe input handling: `ObjectInputStream`, `pickle.loads`, `yaml.load` without SafeLoader, `eval`, `exec`, `Runtime.exec`, `child_process.exec`, `shell=True`, SQL built by string concatenation, `dangerouslySetInnerHTML`, `innerHTML =`.
- Secrets exposed: logging, `console.log(config)`, error messages, URL query strings (`?token=`), analytics events, front-end bundles (anything in React code or `REACT_APP_*`, `NEXT_PUBLIC_*`, `VITE_*` is public to every visitor).
- Debug left on: `DEBUG=True`, Spring `management.endpoints.web.exposure.include=*`, H2 console, open actuator, Swagger/GraphQL playground in production, stack traces to users.

**Authentication and exposure** - for every new or changed route/controller/handler/lambda/gateway rule ask: *who may call this, and where is that enforced?*
- Spring: missing `@PreAuthorize`/`@Secured`, `.permitAll()`, `anyRequest().permitAll()`, `web.ignoring()`, `csrf().disable()` (acceptable for pure token APIs, not cookie sessions), open actuator.
- Node/Express/Nest/Fastify: route registered before auth middleware, `app.use(auth)` placed after the route, missing guard, `cors({origin:'*', credentials:true})`.
- Python: `@csrf_exempt`, `permission_classes=[AllowAny]`, missing `Depends(get_current_user)`, no `login_required`.
- React/front-end: hiding a button is not security; check the API behind it. Tokens in `localStorage` and secrets in bundles.
- Infra: `0.0.0.0/0` on ports 22/3306/5432/6379/27017, public buckets, `Principal:"*"`, `Action:"*"`, wildcard IAM, API Gateway `authorization = "NONE"`.
- Logged-in is not the same as allowed: check permission, not just login. Admin, export, delete, internal and debug paths deserve a second look even with auth.

**Sensitive data**: names with emails/phones/addresses, government IDs (SSN, Aadhaar, PAN, passport), payment card numbers (a 13-19 digit number passing the Luhn checksum), bank accounts, health records, customer lists, production DB dumps, HAR/log files with headers, screenshots with tokens, `.sql` inserts of real people.

**Sensitive file names** (a name is a lead; open the file and judge): `.env`, `.env.*`, `*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.jks`, `*.keystore`, `id_rsa*`, `.npmrc`, `.pypirc`, `.netrc`, `.git-credentials`, `credentials`, `service-account*.json`, `terraform.tfstate*`, `*.tfvars`, `secrets.*`, `kubeconfig`, `*.ovpn`, `.htpasswd`, `wp-config.php`, `application-<profile>.properties|yml`. `.env.example` is fine if it holds only placeholders.

## Severity and verdict

- **Critical** - live-looking credential, private key or token; DB/cloud connection string with password; auth removed from an endpoint that reads or changes user data.
- **High** - hard-coded fallbacks, TLS verification disabled, CSRF/auth disabled, admin/debug endpoints exposed, keystores committed, personal data in code.
- **Medium** - default or weak dev passwords that might reach production, certificates without keys, over-open CORS or network rules, secrets in logs.
- **Low** - random-looking strings you cannot place, new endpoints whose auth you cannot verify from the diff.

Verdict: **STOP** = at least one CONFIRMED live credential or private key. **FIX BEFORE COMMIT** = LIKELY issues or security switched off. **LOOKS OK** only after you have genuinely read the whole diff.

## Report format (use exactly this)

```
# Staged change review

**Verdict: STOP / FIX BEFORE COMMIT / LOOKS OK** - one line why
Scanned: <n> files, <n> added lines

## Must fix now
### 1. <Plain title, e.g. "A database password is written in the code">
- **Where:** path:line   (value masked, e.g. Sup...t!)
- **What it is:** one sentence anyone understands
- **Why it matters:** what a stranger could do with it
- **What to do:** numbered concrete steps (include "change the password")

## Should fix
(same format, shorter)

## Worth a look
(CHECK items, each with the exact question to answer)

## Looked suspicious but is fine
(one line each with the reason)

## Next steps
1. ...
```

Report rules:
- Lead with the verdict. Plain words first; technical term in brackets once ("a login token (JWT)").
- **Never print a full secret.** Show at most the first 3 and last 2 characters.
- Ten identical findings = one finding with ten locations.
- If a real secret was already committed or pushed, say plainly: **treat it as leaked and replace it**, because anyone with repo access, forks or CI logs may already have it.
- Do not modify files, unstage, commit, or rewrite history unless the user asks. Offer instead ("Want me to move this password into an environment variable and update the config?"), and do the mechanical fix once they agree.

## Plain-language fixes

Universal analogy: *A password, key or token is a house key. Code is a postcard everyone on the team can read. Keys go in a locked box (environment variable or secrets manager); the postcard only says which box.* Every fix has two halves: **(A) remove it from the code** and **(B) replace the secret if anyone could have seen it**. Removing text does not un-leak anything.

- **Password/token/key in code or config** - *Say:* "This is a real password in plain text; anyone who can see this code can log in as that account." *Do:* replace with a reference (`${DB_PASSWORD}` Spring, `process.env.DB_PASSWORD` Node, `os.environ["DB_PASSWORD"]` Python, `System.getenv("DB_PASSWORD")` Java); store the real value where the team keeps secrets (CI secret, vault, cloud secret manager, or a git-ignored `.env`); change the password at its source.
- **Hidden default (`${X:admin123}`, `environ.get("X","root")`)** - *Say:* "If the setting is missing, the app quietly uses a made-up password, and attackers try exactly those." *Do:* remove the default so the app fails loudly; keep defaults only for non-secret settings.
- **AWS/GCP/cloud keys** - *Say:* "This key lets whoever has it use your company's cloud account; the bill and the data are yours." *Do:* deactivate and delete the key in the console now (AWS IAM > Security credentials; GCP IAM > Service accounts > Keys); prefer a role / workload identity so no key exists; check CloudTrail / Cloud Audit Logs for use you do not recognise.
- **GitHub/GitLab/npm/Sonar tokens** - *Say:* "This token acts as a person or robot; with it someone can change code, publish packages or tamper with quality checks." *Do:* revoke it in the service's token settings, create a new one with the smallest permissions and an expiry, store it as a CI secret. For `.npmrc` use `//registry.npmjs.org/:_authToken=${NPM_TOKEN}`.
- **Bearer/JWT/session tokens** - *Say:* "This is a ready-made login pass; until it expires, whoever holds it counts as logged in." *Do:* remove it, revoke the session/token, generate test tokens at run time. If a signing secret leaked, change it: every token made with it can be forged.
- **Private key, keystore, `.pem`** - *Say:* "This is the master key proving your server or app is really yours; whoever has it can pretend to be you." *Do:* unstage and delete the file, generate a **new** key pair and certificate, replace the old one everywhere, load keys at deploy time from a vault or mounted secret, add the pattern to `.gitignore`.
- **Certificate only** - *Say:* "Certificates are meant to be shared, so this is usually fine." *Do:* keep only if needed, confirm no private key sits beside it.
- **DB connection string with password** - *Say:* "This is the database's address and its password in one line." *Do:* split it: host and DB name in config; user and password in environment variables or a secret store; change the password; give the app account only the rights it needs.
- **`System.setProperty` on security settings** - *Say:* "The code changes a security setting for the whole running program and often includes a password to do it." *Do:* set trust/key store locations and passwords through startup configuration or mounted secrets, not code. Harmless settings (timezone) need no action.
- **Disabled certificate checks** - *Say:* "The program stopped checking who it is talking to, so a stranger on the network can pose as the real service." *Do:* remove it and add the real certificate authority to the trust store; never ship it, even "just for now".
- **Endpoint with no login / auth off** - *Say:* "Anyone on the internet can call this address without logging in." *Do:* require login the same way sibling routes do, then check *permission* too; keep open only what is meant to be public (health check, login page) and make sure it returns no private data.
- **Debug/admin left on, open CORS, `0.0.0.0/0`** - *Say:* "A door opened for testing is still open." *Do:* turn it off or limit to named people, sites or networks; use per-environment config so debug cannot reach production.
- **Personal/customer data in repo** - *Say:* "Real people's details are stored in code; privacy laws treat that as a leak." *Do:* replace with made-up data (e.g. Faker), remove the file from the commit, tell the security/privacy contact if the data is real.
- **Secret printed in logs** - *Say:* "The password would be written to log files many people and tools can read." *Do:* log that something happened, not the value, or mask it.
- **Sensitive file staged (`.env`, `*.tfstate`, `credentials`)** - *Do:* `git restore --staged <file>`, add the name to `.gitignore`, provide a `.env.example` with fake placeholders.

**Safe secret holders by stack:** Java/Spring - `${ENV_VAR}` placeholders, Spring Cloud Config with encryption, Vault, Secrets Manager, Kubernetes secrets; never `System.setProperty` for passwords. Node/React - server-side `process.env` with a git-ignored `.env` or secrets manager; **browser code is public**, so call your own backend. Python - `os.environ[...]` with no default for secrets, `python-dotenv`, `pydantic-settings`, cloud secret clients. Others - env vars, .NET User Secrets, Rails credentials, cloud secret managers. Infra - CI/CD secret stores, Terraform `sensitive = true` fed from a vault, Helm referencing an existing Secret, cloud roles instead of long-lived keys.

**If it was already committed or pushed:** (1) treat the secret as leaked and replace it first, since that is what actually protects you; (2) not pushed yet: `git reset --soft HEAD~1`, fix, recommit (older commits: interactive rebase); (3) already pushed: after replacing it, ask the repo owner about history cleanup (`git filter-repo` or BFG) and forks/CI logs, which needs team coordination and must never be done silently; (4) add a safety net: a pre-commit hook running this review, or secret scanning / push protection on the Git host.

## Team knowledge (edit this section to teach the skill)

Apply these rules during judgment. Record patterns and reasons, never real secret values. When the user says "that one is fine" or "we use format X for internal tokens", offer the exact line to add here (or to their own notes if this file is read-only).

- Known safe (do not flag): *(none yet)*
- Always flag even if harmless-looking: *(none yet)*
- Internal credential formats (describe, do not paste): *(none yet)*
- Repo conventions for secrets: *(none yet)*
- Accepted exceptions (file, reason, approver, date): *(none yet)*

## Boundaries

- Never test or "validate" a found credential against a live service.
- Never put an unmasked secret in the report, a commit message, or a suggested shell command.
- You are protecting the user's own code. Do not help harvest secrets from repositories you were not asked to review.
- Stay calm and specific: "Fix this before committing" beats alarm words.
