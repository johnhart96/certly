import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import * as oidc from "openid-client";

const SESSION_COOKIE = "certly_session";
const LOGIN_COOKIE = "certly_login";
const LOGIN_TTL_SECONDS = 10 * 60;

/**
 * Reads OIDC settings from environment-style options. Returns null when OIDC isn't configured.
 * Throws if it's only partly configured, so mistakes show up at startup rather than at login.
 */
export function oidcOptionsFromEnv(env) {
  if (!env.OIDC_ISSUER) return null;
  const missing = ["OIDC_CLIENT_ID", "CERTLY_URL"].filter((k) => !env[k]);
  if (missing.length) throw new Error(`OIDC_ISSUER is set but ${missing.join(" and ")} ${missing.length > 1 ? "are" : "is"} missing.`);

  const hours = Number(env.SESSION_MAX_AGE_HOURS ?? 12);
  if (!(hours > 0)) throw new Error("SESSION_MAX_AGE_HOURS must be a positive number.");

  return {
    issuer: env.OIDC_ISSUER,
    clientId: env.OIDC_CLIENT_ID,
    clientSecret: env.OIDC_CLIENT_SECRET || undefined,
    publicUrl: env.CERTLY_URL,
    scopes: env.OIDC_SCOPES || "openid profile email",
    allowedGroups: (env.OIDC_ALLOWED_GROUPS || "").split(",").map((g) => g.trim()).filter(Boolean),
    sessionMaxAge: Math.round(hours * 3600),
    sessionSecret: env.SESSION_SECRET || undefined,
  };
}

/**
 * Adds OpenID Connect login (e.g. Authentik, Keycloak, Authelia) to an Express app.
 * Registers /auth/login, /auth/callback, /auth/logout and /auth/logged-out, then returns a
 * middleware that requires a valid session for everything else.
 */
export async function setupOidc(app, options, dataDir) {
  const { clientId, clientSecret, scopes, allowedGroups, sessionMaxAge } = options;
  const baseUrl = new URL(options.publicUrl.endsWith("/") ? options.publicUrl : `${options.publicUrl}/`);
  const issuerUrl = new URL(options.issuer);
  const secure = baseUrl.protocol === "https:";
  const secret = options.sessionSecret ?? (await loadOrCreateSecret(path.join(dataDir, "session.secret")));
  const redirectUri = new URL("auth/callback", baseUrl).href;
  const cookiePath = baseUrl.pathname;

  // Discovery is lazy and retried, so Certly still starts if the identity provider is briefly down.
  let configPromise;
  function getConfig() {
    configPromise ??= oidc
      .discovery(
        issuerUrl,
        clientId,
        clientSecret,
        clientSecret ? undefined : oidc.None(),
        issuerUrl.protocol === "http:" ? { execute: [oidc.allowInsecureRequests] } : undefined,
      )
      .catch((err) => {
        configPromise = undefined;
        throw err;
      });
    return configPromise;
  }
  getConfig().catch((err) => console.warn(`OIDC discovery failed (will retry on first login): ${err.message}`));

  const sign = (payload) => signValue(payload, secret);
  const verify = (value) => verifyValue(value, secret);
  const setCookie = (res, name, value, maxAge) =>
    res.append("Set-Cookie", serializeCookie(name, value, { maxAge, path: cookiePath, secure }));

  app.get("/auth/login", async (req, res, next) => {
    try {
      const config = await getConfig();
      const login = {
        state: oidc.randomState(),
        nonce: oidc.randomNonce(),
        verifier: oidc.randomPKCECodeVerifier(),
        exp: now() + LOGIN_TTL_SECONDS,
      };
      setCookie(res, LOGIN_COOKIE, sign(login), LOGIN_TTL_SECONDS);
      const url = oidc.buildAuthorizationUrl(config, {
        redirect_uri: redirectUri,
        scope: scopes,
        state: login.state,
        nonce: login.nonce,
        code_challenge: await oidc.calculatePKCECodeChallenge(login.verifier),
        code_challenge_method: "S256",
      });
      res.redirect(url.href);
    } catch (err) {
      next(new AuthError(502, "Couldn't reach the identity provider", err));
    }
  });

  app.get("/auth/callback", async (req, res, next) => {
    const login = verify(parseCookies(req)[LOGIN_COOKIE]);
    setCookie(res, LOGIN_COOKIE, "", 0);
    if (!login) return next(new AuthError(400, "Your sign-in attempt expired. Please try again."));

    let claims;
    try {
      const config = await getConfig();
      // Rebuild the URL as the browser saw it, which matters behind a reverse proxy.
      const currentUrl = new URL(`auth/callback${req.url.slice(req.path.length)}`, baseUrl);
      const tokens = await oidc.authorizationCodeGrant(config, currentUrl, {
        pkceCodeVerifier: login.verifier,
        expectedState: login.state,
        expectedNonce: login.nonce,
        idTokenExpected: true,
      });
      claims = tokens.claims();
      // Groups are often only in userinfo (depends on the provider's scope mappings).
      if (allowedGroups.length && !Array.isArray(claims.groups) && config.serverMetadata().userinfo_endpoint) {
        claims = { ...(await oidc.fetchUserInfo(config, tokens.access_token, claims.sub)), ...claims };
      }
    } catch (err) {
      return next(new AuthError(400, "Sign-in failed. Please try again.", err));
    }

    const groups = Array.isArray(claims.groups) ? claims.groups.map(String) : [];
    if (allowedGroups.length && !groups.some((g) => allowedGroups.includes(g))) {
      console.warn(`Denied sign-in for ${claims.preferred_username || claims.sub}: not in an allowed group.`);
      return next(new AuthError(403, "Your account isn't allowed to use Certly. Ask an administrator to add you to an allowed group."));
    }

    const user = {
      sub: String(claims.sub),
      name: String(claims.name || claims.preferred_username || claims.email || claims.sub),
      email: claims.email ? String(claims.email) : undefined,
      exp: now() + sessionMaxAge,
    };
    setCookie(res, SESSION_COOKIE, sign(user), sessionMaxAge);
    console.log(`Signed in: ${user.name} (${user.sub})`);
    res.redirect(baseUrl.href);
  });

  app.post("/auth/logout", async (req, res) => {
    setCookie(res, SESSION_COOKIE, "", 0);
    const loggedOut = new URL("auth/logged-out", baseUrl).href;
    try {
      const config = await getConfig();
      if (config.serverMetadata().end_session_endpoint) {
        const url = oidc.buildEndSessionUrl(config, { client_id: clientId, post_logout_redirect_uri: loggedOut });
        return res.redirect(303, url.href);
      }
    } catch {
      // Provider unreachable: the local session is gone, which is what matters.
    }
    res.redirect(303, loggedOut);
  });

  app.get("/auth/logged-out", (req, res) => {
    res.status(200).type("html").send(page("Signed out", "You've been signed out of Certly.", baseUrl));
  });

  // Everything registered after this requires a session.
  return function requireSession(req, res, next) {
    const user = verify(parseCookies(req)[SESSION_COOKIE]);
    if (!user) {
      if (req.path.startsWith("/api/")) return res.status(401).json({ error: "Not signed in", login: "auth/login" });
      return res.redirect(new URL("auth/login", baseUrl).href);
    }
    // Cookies are SameSite=Lax, but also refuse state-changing requests that a browser says came from elsewhere.
    if (!["GET", "HEAD", "OPTIONS"].includes(req.method)) {
      const origin = req.get("origin");
      const site = req.get("sec-fetch-site");
      if ((origin && origin !== baseUrl.origin) || (site && site !== "same-origin" && site !== "none")) {
        return res.status(403).json({ error: "Cross-site request refused" });
      }
    }
    req.user = { sub: user.sub, name: user.name, email: user.email };
    next();
  };
}

export class AuthError extends Error {
  constructor(status, message, cause) {
    super(message, { cause });
    this.status = status;
  }
}

export function renderAuthError(err, publicUrl) {
  const base = new URL(publicUrl.endsWith("/") ? publicUrl : `${publicUrl}/`);
  return page("Sign-in problem", err.message, base);
}

// --- Signed values ---------------------------------------------------------

function signValue(payload, secret) {
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return `${body}.${hmac(body, secret)}`;
}

function verifyValue(value, secret) {
  if (typeof value !== "string") return null;
  const [body, mac] = value.split(".");
  if (!body || !mac) return null;
  const expected = Buffer.from(hmac(body, secret));
  const given = Buffer.from(mac);
  if (given.length !== expected.length || !timingSafeEqual(given, expected)) return null;
  try {
    const payload = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
    return typeof payload.exp === "number" && payload.exp > now() ? payload : null;
  } catch {
    return null;
  }
}

function hmac(value, secret) {
  return createHmac("sha256", secret).update(value).digest("base64url");
}

async function loadOrCreateSecret(file) {
  try {
    return (await fs.readFile(file, "utf8")).trim();
  } catch (err) {
    if (err.code !== "ENOENT") throw err;
  }
  const secret = randomBytes(32).toString("base64url");
  await fs.mkdir(path.dirname(file), { recursive: true });
  await fs.writeFile(file, secret + "\n", { mode: 0o600 });
  return secret;
}

// --- Cookies ---------------------------------------------------------------

function parseCookies(req) {
  const out = {};
  for (const part of (req.headers.cookie || "").split(";")) {
    const i = part.indexOf("=");
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

function serializeCookie(name, value, { maxAge, path: cookiePath, secure }) {
  return [
    `${name}=${encodeURIComponent(value)}`,
    `Path=${cookiePath}`,
    `Max-Age=${maxAge}`,
    "HttpOnly",
    "SameSite=Lax",
    secure && "Secure",
  ]
    .filter(Boolean)
    .join("; ");
}

// --- Helpers ---------------------------------------------------------------

function now() {
  return Math.floor(Date.now() / 1000);
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}

function page(title, message, baseUrl) {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(title)} · Certly</title>
  <link rel="icon" href="${escapeHtml(new URL("favicon.svg", baseUrl).pathname)}" type="image/svg+xml">
  <style>
    :root { --bg: #f5f6f8; --surface: #fff; --border: #e1e4e9; --text: #1a1d23; --muted: #687080; --accent: #2f6fed; }
    @media (prefers-color-scheme: dark) { :root { --bg: #0f1115; --surface: #171a20; --border: #2a2f39; --text: #e6e8ec; --muted: #8d95a5; --accent: #5b8ff5; } }
    body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: var(--bg); color: var(--text); font: 15px/1.5 system-ui, sans-serif; padding: 16px; box-sizing: border-box; }
    .box { max-width: 420px; width: 100%; background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 28px; text-align: center; }
    h1 { font-size: 19px; margin: 0 0 8px; }
    p { color: var(--muted); margin: 0 0 20px; }
    a { display: inline-block; background: var(--accent); color: #fff; padding: 8px 18px; border-radius: 8px; text-decoration: none; font-weight: 600; }
  </style>
</head>
<body>
  <div class="box">
    <h1>${escapeHtml(title)}</h1>
    <p>${escapeHtml(message)}</p>
    <a href="${escapeHtml(new URL("auth/login", baseUrl).href)}">Sign in</a>
  </div>
</body>
</html>`;
}
