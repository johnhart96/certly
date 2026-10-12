import { test, before, after, describe } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import http from "node:http";
import path from "node:path";
import { createApp } from "../src/app.js";
import { oidcOptionsFromEnv } from "../src/auth.js";
import { startMockOidc } from "./mock-oidc.js";
import { tempDir } from "./helpers.js";

// Starts Certly with OIDC pointed at the mock provider. CERTLY_URL needs the port, so listen first.
async function startCertly(provider, overrides = {}) {
  const dataDir = await tempDir();
  const server = http.createServer();
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${server.address().port}/`;
  const oidc = oidcOptionsFromEnv({
    OIDC_ISSUER: provider.issuer,
    OIDC_CLIENT_ID: provider.clientId,
    OIDC_CLIENT_SECRET: provider.clientSecret,
    CERTLY_URL: base,
    ...overrides,
  });
  const { app } = await createApp({ dataDir, oidc });
  server.on("request", app);
  return {
    base,
    dataDir,
    async close() {
      server.closeAllConnections();
      await new Promise((resolve) => server.close(resolve));
      await fs.rm(dataDir, { recursive: true, force: true });
    },
  };
}

// A tiny browser: keeps cookies (by name, like a browser does across ports on one host) and follows redirects manually.
class Browser {
  cookies = new Map();

  async request(url, { method = "GET", headers = {}, body } = {}) {
    const cookie = [...this.cookies].map(([k, v]) => `${k}=${v}`).join("; ");
    const res = await fetch(url, {
      method,
      redirect: "manual",
      headers: { ...(cookie && { Cookie: cookie }), ...headers },
      body,
    });
    for (const header of res.headers.getSetCookie()) {
      const [pair, ...attrs] = header.split("; ");
      const [name, value] = [pair.slice(0, pair.indexOf("=")), pair.slice(pair.indexOf("=") + 1)];
      if (attrs.includes("Max-Age=0") || value === "") this.cookies.delete(name);
      else this.cookies.set(name, value);
    }
    return res;
  }

  // Follows redirects until a non-redirect response, returning it and the URLs visited.
  async follow(url, options) {
    const visited = [url];
    let res = await this.request(url, options);
    while (res.status >= 300 && res.status < 400) {
      url = new URL(res.headers.get("location"), url).href;
      visited.push(url);
      res = await this.request(url);
    }
    return { res, visited };
  }

  async signIn(certly) {
    const { res, visited } = await this.follow(new URL("auth/login", certly.base).href);
    assert.equal(res.status, 200, `sign-in ended on ${visited.at(-1)} with ${res.status}`);
    assert.equal(visited.at(-1), certly.base);
    assert.ok(this.cookies.has("certly_session"), "no session cookie after sign-in");
  }
}

describe("OIDC sign-in", () => {
  let provider;
  let certly;

  before(async () => {
    provider = await startMockOidc();
    certly = await startCertly(provider);
  });

  after(async () => {
    await certly.close();
    await provider.close();
  });

  test("requires sign-in for the UI and API", async () => {
    const browser = new Browser();
    const page = await browser.request(certly.base);
    assert.equal(page.status, 302);
    assert.equal(page.headers.get("location"), new URL("auth/login", certly.base).href);

    const api = await browser.request(new URL("api/ca", certly.base));
    assert.equal(api.status, 401);
    assert.deepEqual(await api.json(), { error: "Not signed in", login: "auth/login" });
  });

  test("favicon is public", async () => {
    const res = await new Browser().request(new URL("favicon.svg", certly.base));
    assert.equal(res.status, 200);
  });

  test("login redirects to the provider with PKCE, state and nonce", async () => {
    const browser = new Browser();
    const res = await browser.request(new URL("auth/login", certly.base));
    const location = new URL(res.headers.get("location"));
    assert.equal(location.href.split("?")[0], `${provider.issuer}authorize`);
    assert.equal(location.searchParams.get("code_challenge_method"), "S256");
    assert.equal(location.searchParams.get("redirect_uri"), new URL("auth/callback", certly.base).href);
    assert.equal(location.searchParams.get("scope"), "openid profile email");
    assert.ok(location.searchParams.get("state"));
    assert.ok(location.searchParams.get("nonce"));
    assert.match(res.headers.getSetCookie()[0], /^certly_login=.+; Path=\/; Max-Age=600; HttpOnly; SameSite=Lax$/);
  });

  test("full sign-in grants access and reports the user", async () => {
    const browser = new Browser();
    await browser.signIn(certly);

    const me = await (await browser.request(new URL("api/me", certly.base))).json();
    assert.deepEqual(me, { authMode: "oidc", user: { sub: "user-1", name: "Ada Lovelace", email: "ada@example.com" } });
    assert.equal((await browser.request(new URL("api/ca", certly.base))).status, 200);
    assert.ok(!browser.cookies.has("certly_login"), "login cookie should be cleared");
  });

  test("signed-in users can make changes from the same origin", async () => {
    const browser = new Browser();
    await browser.signIn(certly);
    const res = await browser.request(new URL("api/domains", certly.base), {
      method: "POST",
      headers: { "Content-Type": "application/json", Origin: new URL(certly.base).origin },
      body: JSON.stringify({ name: "oidc.test" }),
    });
    assert.equal(res.status, 201);
  });

  test("refuses cross-site changes even with a valid session", async () => {
    const browser = new Browser();
    await browser.signIn(certly);
    for (const headers of [{ Origin: "https://evil.example" }, { "Sec-Fetch-Site": "cross-site" }, { "Sec-Fetch-Site": "same-site" }]) {
      const res = await browser.request(new URL("api/domains", certly.base), {
        method: "POST",
        headers: { "Content-Type": "application/json", ...headers },
        body: JSON.stringify({ name: "csrf.test" }),
      });
      assert.equal(res.status, 403, JSON.stringify(headers));
    }
  });

  test("rejects a tampered or forged session cookie", async () => {
    const browser = new Browser();
    await browser.signIn(certly);
    const [body, mac] = browser.cookies.get("certly_session").split(".");

    const forged = Buffer.from(JSON.stringify({ sub: "admin", name: "Admin", exp: 9999999999 })).toString("base64url");
    for (const value of [`${forged}.${mac}`, `${body}.${mac.slice(0, -2)}xx`, body, "garbage"]) {
      browser.cookies.set("certly_session", value);
      assert.equal((await browser.request(new URL("api/ca", certly.base))).status, 401, value);
    }
  });

  test("callback without a login cookie, or with the wrong state, fails safely", async () => {
    const browser = new Browser();
    const noCookie = await browser.request(new URL("auth/callback?code=abc&state=xyz", certly.base));
    assert.equal(noCookie.status, 400);
    assert.match(await noCookie.text(), /sign-in attempt expired/);

    // Start a real login, then swap the state the provider sends back.
    const start = await browser.request(new URL("auth/login", certly.base));
    const authorize = await browser.request(start.headers.get("location"));
    const callback = new URL(authorize.headers.get("location"));
    callback.searchParams.set("state", "tampered");
    const res = await browser.request(callback);
    assert.equal(res.status, 400);
    assert.ok(!browser.cookies.has("certly_session"));
  });

  test("sign-out clears the session and ends the provider session", async () => {
    const browser = new Browser();
    await browser.signIn(certly);
    const res = await browser.request(new URL("auth/logout", certly.base), { method: "POST" });
    assert.equal(res.status, 303);
    const location = new URL(res.headers.get("location"));
    assert.equal(location.href.split("?")[0], `${provider.issuer}end-session`);
    assert.equal(location.searchParams.get("post_logout_redirect_uri"), new URL("auth/logged-out", certly.base).href);
    assert.ok(!browser.cookies.has("certly_session"));
    assert.equal((await browser.request(new URL("api/ca", certly.base))).status, 401);

    const loggedOut = await browser.request(new URL("auth/logged-out", certly.base));
    assert.equal(loggedOut.status, 200);
    assert.match(await loggedOut.text(), /signed out of Certly/);
  });

  test("session secret is persisted with owner-only permissions", async () => {
    const { mode } = await fs.stat(path.join(certly.dataDir, "session.secret"));
    assert.equal(mode & 0o777, 0o600);
  });
});

describe("OIDC group restriction", () => {
  let provider;
  let certly;

  before(async () => {
    provider = await startMockOidc();
    // Like Authentik's default setup when groups aren't mapped into the ID token.
    provider.groupsInIdToken = false;
    certly = await startCertly(provider, { OIDC_ALLOWED_GROUPS: "certly-admins, pki" });
  });

  after(async () => {
    await certly.close();
    await provider.close();
  });

  test("allows members of an allowed group (groups read from userinfo)", async () => {
    provider.user.groups = ["staff", "certly-admins"];
    await new Browser().signIn(certly);
  });

  test("denies users outside the allowed groups", async () => {
    provider.user.groups = ["staff"];
    const browser = new Browser();
    const { res } = await browser.follow(new URL("auth/login", certly.base).href);
    assert.equal(res.status, 403);
    assert.match(await res.text(), /isn&#39;t allowed to use Certly/);
    assert.ok(!browser.cookies.has("certly_session"));
  });
});

describe("OIDC configuration", () => {
  test("is off when OIDC_ISSUER is unset", () => {
    assert.equal(oidcOptionsFromEnv({}), null);
  });

  test("requires a client ID and public URL", () => {
    assert.throws(() => oidcOptionsFromEnv({ OIDC_ISSUER: "https://auth.example/" }), /OIDC_CLIENT_ID and CERTLY_URL are missing/);
    assert.throws(
      () => oidcOptionsFromEnv({ OIDC_ISSUER: "https://auth.example/", OIDC_CLIENT_ID: "x" }),
      /CERTLY_URL is missing/,
    );
  });

  test("parses groups, scopes and session lifetime", () => {
    const options = oidcOptionsFromEnv({
      OIDC_ISSUER: "https://auth.example/",
      OIDC_CLIENT_ID: "x",
      CERTLY_URL: "https://certly.example",
      OIDC_ALLOWED_GROUPS: " a, b ,,",
      SESSION_MAX_AGE_HOURS: "1.5",
    });
    assert.deepEqual(options.allowedGroups, ["a", "b"]);
    assert.equal(options.sessionMaxAge, 5400);
    assert.equal(options.scopes, "openid profile email");
  });

  test("can't be combined with basic auth", async () => {
    const dataDir = await tempDir();
    await assert.rejects(
      createApp({
        dataDir,
        auth: { username: "a", password: "b" },
        oidc: oidcOptionsFromEnv({ OIDC_ISSUER: "https://auth.example/", OIDC_CLIENT_ID: "x", CERTLY_URL: "https://c.example" }),
      }),
      /either OIDC or basic auth/,
    );
    await fs.rm(dataDir, { recursive: true, force: true });
  });
});
