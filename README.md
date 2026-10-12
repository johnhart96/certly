# Certly

[![CI](https://github.com/johnhart/certly/actions/workflows/ci.yml/badge.svg)](https://github.com/johnhart/certly/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A self-hosted, web-based local certificate authority for development machines and home labs.

Add a domain, then either generate a private key and certificate in one click or upload your own certificate signing request (CSR). After you import Certly's root CA, browsers and operating systems trust every certificate it issues. You get real HTTPS for `nas.home.arpa`, `*.dev.example.com` and the like, with no browser warnings.

## Features

- **One root CA**, created on first start (RSA 4096, valid for 10 years), downloadable as `.crt` (PEM) or `.cer` (DER).
- **Per-domain scoping**: certificates are only issued for names under a domain you've added, including wildcards.
- **Two ways to issue**: generate a key and certificate in the browser UI, or upload a CSR so your private key never leaves your machine.
- **RSA and ECDSA** keys.
- **Browser-ready certificates**: SANs always present, `serverAuth`/`clientAuth`, validity capped at 825 days for Apple platforms.
- **Downloads** of the certificate, full chain and original CSR for anything you've issued.
- **Small footprint**: a single Node.js container, data in one volume, no database server, and a frontend with no build step.
- **Single sign-on** with Authentik or any other OpenID Connect provider, with optional group restrictions. Simple HTTP basic auth is also available.

## Quick start

### Use the pre-built image

Create a `docker-compose.yml`:

```yaml
services:
  certly:
    image: ghcr.io/johnhart/certly:latest
    restart: unless-stopped
    ports:
      - "127.0.0.1:3000:3000"
    volumes:
      - certly-data:/data

volumes:
  certly-data:
```

```sh
docker compose up -d
```

### Or build from source

```sh
git clone https://github.com/johnhart/certly.git
cd certly
docker compose up -d --build
```

Then open <http://localhost:3000>.

On first start Certly generates its root CA. The CA and all issued certificates are stored in the `certly-data` Docker volume, so they survive restarts and upgrades.

## Using it

1. **Trust the CA.** Click **Download CA (.crt)** and import it into your OS or browser. The page has instructions for each platform. Use the `.cer` (DER) download if Windows prefers it.
2. **Add a domain**, e.g. `domain.com`.
3. **Issue a certificate** in one of two ways:

   **Generate key** (the quickest option). Enter the hostnames, e.g. `app.domain.com, *.domain.com`, pick a key type (ECDSA P-256/P-384 or RSA 2048/4096) and click **Generate certificate**. Then download the **private key**, **certificate** and **full chain**.

   > Certly doesn't store generated private keys. The key goes to your browser once, so download it before you leave the page. The page warns you if you try to leave without downloading it.

   **Upload CSR**, if you'd rather the private key never leave your machine. Certly shows a ready-made OpenSSL command for each domain:

   ```sh
   openssl req -new -newkey rsa:2048 -nodes \
     -keyout domain.com.key -out domain.com.csr \
     -subj "/CN=domain.com" \
     -addext "subjectAltName=DNS:domain.com,DNS:*.domain.com"
   ```

   Drag and drop the CSR or paste it in, choose a validity period, and click **Sign certificate**.
4. **Download** from the certificate list at any time:
   - **Certificate**: the leaf certificate (`.crt`).
   - **Full chain**: the leaf followed by the root CA. Use this for nginx, Caddy, Traefik, HAProxy and similar servers.
   - **CSR**: the original request (only for certificates issued from a CSR).

## Signing rules

- Every requested name (for a CSR, the CN and all DNS SANs) must be the domain itself or a subdomain of it. Wildcards such as `*.domain.com` and `*.app.domain.com` are allowed. A request for `domain.com` that also asks for `other.com` is rejected.
- RSA and ECDSA (P-256 / P-384 / P-521) keys are supported.
- The CN is always copied into the Subject Alternative Name extension, because browsers ignore the CN.
- Validity defaults to 397 days and can be at most 825 days. Apple platforms reject leaf certificates valid for longer.
- Issued certificates carry `serverAuth` and `clientAuth` extended key usages.

## Configuration

Set these environment variables in `docker-compose.yml`:

| Variable          | Default           | Description                                          |
| ----------------- | ----------------- | ---------------------------------------------------- |
| `CA_NAME`         | `Certly Local CA` | CA common name. Only used when the CA is first created. |
| `CA_ORGANIZATION` | `Certly`          | CA organisation. Only used when the CA is first created. |
| `CERTLY_USERNAME` | –                 | Enables HTTP basic auth when set together with `CERTLY_PASSWORD`. |
| `CERTLY_PASSWORD` | –                 | Basic auth password.                                 |
| `CERTLY_URL`      | –                 | The URL people use to reach Certly, e.g. `https://certly.example.com`. Required for OIDC. |
| `OIDC_ISSUER`     | –                 | Enables OpenID Connect sign-in. See [Single sign-on](#single-sign-on-authentik--oidc). |
| `OIDC_CLIENT_ID`  | –                 | OIDC client ID.                                      |
| `OIDC_CLIENT_SECRET` | –              | OIDC client secret. Leave unset for a public client (PKCE only). |
| `OIDC_ALLOWED_GROUPS` | –             | Comma-separated groups allowed to sign in. Unset means any user the provider authenticates. |
| `OIDC_SCOPES`     | `openid profile email` | Scopes to request.                              |
| `SESSION_MAX_AGE_HOURS` | `12`        | How long a sign-in lasts.                            |
| `SESSION_SECRET`  | generated         | Key for signing session cookies. By default a random one is created and saved as `/data/session.secret`. |
| `PORT`            | `3000`            | Port to listen on inside the container.              |
| `DATA_DIR`        | `/data`           | Where the CA, database and certificates are stored.  |

## Single sign-on (Authentik / OIDC)

Certly can hand sign-in to Authentik, or to any other OpenID Connect provider such as Keycloak, Authelia, Zitadel or Entra ID. When it's enabled, every page and API call requires a signed-in user. The header shows who is signed in and has a **Sign out** button.

### Setting up Authentik

1. In the Authentik admin interface, go to **Applications → Providers → Create** and choose **OAuth2/OpenID Provider**:
   - **Name**: `Certly`
   - **Authorization flow**: `default-provider-authorization-implicit-consent` (or the explicit-consent flow if you want a consent screen)
   - **Client type**: `Confidential`
   - **Redirect URIs**: `Strict` and `https://certly.example.com/auth/callback`
   - **Signing key**: pick a certificate, e.g. `authentik Self-signed Certificate`, so ID tokens are signed with RS256
   - Leave the default scopes (`openid`, `email`, `profile`). Note the **Client ID** and **Client Secret**.
2. Go to **Applications → Applications → Create**, give it the slug `certly`, and select the provider you just made.
3. Optionally, limit who can sign in. Either bind groups or users to the application in Authentik (**Policy / Group / User Bindings**), or set `OIDC_ALLOWED_GROUPS` in Certly.
4. Configure Certly:

   ```yaml
   environment:
     CERTLY_URL: https://certly.example.com
     OIDC_ISSUER: https://authentik.example.com/application/o/certly/
     OIDC_CLIENT_ID: <client id>
     OIDC_CLIENT_SECRET: <client secret>
     OIDC_ALLOWED_GROUPS: certly-admins   # optional
   ```

   `OIDC_ISSUER` is the **OpenID Configuration Issuer** shown on the provider's page in Authentik.

### How it works

- Certly uses the authorization code flow with PKCE, and checks state and nonce. Only `/auth/callback` is needed as a redirect URI.
- After sign-in Certly sets an HttpOnly, `SameSite=Lax` session cookie, signed with HMAC-SHA256. It's marked `Secure` when `CERTLY_URL` uses HTTPS. No tokens from the provider are stored.
- Group membership is read from the `groups` claim in the ID token or, failing that, from the userinfo endpoint. Authentik's default `profile` scope mapping includes it.
- Sign-out clears the session and then sends you to the provider's end-session page.
- Requests that change data are refused if the browser says they came from another site.
- `CERTLY_URL` must be the address in the browser's address bar. Behind a reverse proxy, that's the public HTTPS URL, which may include a sub-path such as `https://example.com/certly`.
- To sign everyone out, delete `/data/session.secret` (or change `SESSION_SECRET`) and restart.
- OIDC and basic auth can't both be enabled.

## Security notes

Anyone who can reach Certly can get a certificate for any domain added to it, and every machine that trusts the CA will accept that certificate. For that reason:

- The compose file publishes the port on `127.0.0.1` only. If you expose Certly to your network, turn on [single sign-on](#single-sign-on-authentik--oidc) or basic auth, and put it behind TLS.
- The CA private key is stored at `/data/ca/ca.key` inside the volume (mode `0600`). It can never be downloaded through the web interface. Back up the volume if you want to keep your CA.
- The root CA has `pathlen:0`, so it can sign leaf certificates but not intermediate CAs.

## Data layout

```
/data
├── ca/
│   ├── ca.key        # root CA private key (PKCS#8 PEM)
│   └── ca.crt        # root CA certificate
├── certs/
│   ├── <id>.crt      # issued certificates
│   └── <id>.csr      # the CSRs they were issued from (generated keys are never stored)
├── db.json           # domains and certificate metadata
└── session.secret    # session cookie signing key (only with OIDC)
```

To start over with a new CA, remove the volume with `docker compose down -v`. Any certificates issued by the old CA will stop being trusted.

## Running without Docker

```sh
npm install
DATA_DIR=./data npm start
```

Requires Node.js 22 or later.

## Development

```sh
npm install
npm run dev   # restarts on file changes
npm test
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the project layout and guidelines. To report a security issue, follow [SECURITY.md](SECURITY.md) rather than opening a public issue.

## Releasing

Push a version tag to build and publish a multi-arch (amd64/arm64) image to GitHub Container Registry:

```sh
npm version patch   # or minor / major; creates the vX.Y.Z tag
git push --follow-tags
```

### Pre-releases

To mark a build as a pre-release, give it a [semver](https://semver.org) pre-release suffix such as `-beta.1` or `-rc.1`:

```sh
npm version preminor --preid beta   # 1.0.0 -> 1.1.0-beta.0
npm version prerelease              # 1.1.0-beta.0 -> 1.1.0-beta.1
npm version minor                   # 1.1.0-beta.1 -> 1.1.0 (final release)
git push --follow-tags
```

You can also edit `"version"` in `package.json` by hand. While the version has a suffix:

- the web interface shows an orange **Pre-release** badge next to the version number
- the startup log says `(pre-release)`
- the published image is only tagged with its exact version, e.g. `1.1.0-beta.1`. The `latest`, `1` and `1.1` tags keep pointing at the last full release.

## License

[MIT](LICENSE)
