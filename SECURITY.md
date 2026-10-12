# Security policy

Certly is a certificate authority. Any device that trusts its root certificate will accept every certificate it issues, so security bugs matter here.

## Reporting a vulnerability

Please **don't open a public issue**. Report it privately through [GitHub security advisories](https://github.com/johnhart/certly/security/advisories/new). Include:

- what the issue is and what an attacker could do with it
- steps to reproduce, or a proof of concept
- the version or image tag you tested

You should get a reply within a week. Once a fix has been released, you'll be credited in the release notes unless you'd rather not be.

## Supported versions

Only the latest release receives security fixes.

## Scope

In scope, for example:

- issuing a certificate for a name outside the domain it was requested under
- reading the CA private key, or any private key, through the web interface or API
- getting past sign-in (OIDC or HTTP basic auth) when it's enabled, forging sessions, or getting past the `OIDC_ALLOWED_GROUPS` restriction
- cross-site request forgery against a signed-in user
- path traversal, injection, or XSS in the web UI

Out of scope, because these are documented design decisions:

- anyone who can reach an instance without authentication can add domains and issue certificates. Keep Certly on `localhost` or a trusted network, or enable OIDC or basic auth.
- issued certificates can't be revoked (there is no CRL or OCSP).
- the CA private key is stored unencrypted in the data volume.
