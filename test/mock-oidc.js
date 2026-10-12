import http from "node:http";
import { createHash, generateKeyPairSync, randomBytes, sign } from "node:crypto";

const b64url = (value) => Buffer.from(value).toString("base64url");

/**
 * A minimal OpenID Connect provider laid out like Authentik
 * (issuer = /application/o/<slug>/). `/authorize` signs in `provider.user` immediately.
 */
export async function startMockOidc({ clientId = "certly", clientSecret = "secret", slug = "certly" } = {}) {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const jwk = { ...publicKey.export({ format: "jwk" }), kid: "test", alg: "RS256", use: "sig" };
  const codes = new Map();
  const tokens = new Map();

  const provider = {
    user: { sub: "user-1", name: "Ada Lovelace", email: "ada@example.com", preferred_username: "ada", groups: ["certly-admins"] },
    groupsInIdToken: true,
    issuer: "",
  };

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, provider.issuer);
    const json = (status, body) => {
      res.writeHead(status, { "Content-Type": "application/json" });
      res.end(JSON.stringify(body));
    };
    const route = url.pathname.slice(new URL(provider.issuer).pathname.length);

    if (route === ".well-known/openid-configuration") {
      return json(200, {
        issuer: provider.issuer,
        authorization_endpoint: `${provider.issuer}authorize`,
        token_endpoint: `${provider.issuer}token`,
        userinfo_endpoint: `${provider.issuer}userinfo`,
        end_session_endpoint: `${provider.issuer}end-session`,
        jwks_uri: `${provider.issuer}jwks`,
        response_types_supported: ["code"],
        subject_types_supported: ["public"],
        id_token_signing_alg_values_supported: ["RS256"],
        code_challenge_methods_supported: ["S256"],
        token_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic"],
      });
    }

    if (route === "jwks") return json(200, { keys: [jwk] });

    if (route === "authorize") {
      const p = url.searchParams;
      if (p.get("client_id") !== clientId || p.get("response_type") !== "code") return json(400, { error: "invalid_request" });
      const code = randomBytes(16).toString("hex");
      codes.set(code, {
        nonce: p.get("nonce"),
        challenge: p.get("code_challenge"),
        redirectUri: p.get("redirect_uri"),
        user: { ...provider.user },
      });
      const back = new URL(p.get("redirect_uri"));
      back.searchParams.set("code", code);
      back.searchParams.set("state", p.get("state"));
      res.writeHead(302, { Location: back.href });
      return res.end();
    }

    if (route === "token" && req.method === "POST") {
      let raw = "";
      for await (const chunk of req) raw += chunk;
      const body = new URLSearchParams(raw);
      const [basicId, basicSecret] = Buffer.from((req.headers.authorization || "").replace(/^Basic /, ""), "base64")
        .toString()
        .split(":")
        .map(decodeURIComponent);
      const id = body.get("client_id") || basicId;
      const secret = body.get("client_secret") || basicSecret;
      if (id !== clientId || secret !== clientSecret) return json(401, { error: "invalid_client" });

      const grant = codes.get(body.get("code"));
      codes.delete(body.get("code"));
      const challenge = createHash("sha256").update(body.get("code_verifier") || "").digest("base64url");
      if (!grant || grant.redirectUri !== body.get("redirect_uri") || grant.challenge !== challenge) {
        return json(400, { error: "invalid_grant" });
      }

      const now = Math.floor(Date.now() / 1000);
      const { groups, ...profile } = grant.user;
      const claims = { iss: provider.issuer, aud: clientId, iat: now, exp: now + 300, nonce: grant.nonce, ...profile };
      if (provider.groupsInIdToken) claims.groups = groups;
      const head = b64url(JSON.stringify({ alg: "RS256", kid: "test", typ: "JWT" }));
      const payload = b64url(JSON.stringify(claims));
      const signature = sign("sha256", Buffer.from(`${head}.${payload}`), privateKey).toString("base64url");

      const accessToken = randomBytes(16).toString("hex");
      tokens.set(accessToken, grant.user);
      return json(200, { access_token: accessToken, token_type: "Bearer", expires_in: 300, id_token: `${head}.${payload}.${signature}` });
    }

    if (route === "userinfo") {
      const user = tokens.get((req.headers.authorization || "").replace(/^Bearer /, ""));
      return user ? json(200, user) : json(401, { error: "invalid_token" });
    }

    json(404, { error: "not_found" });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  provider.issuer = `http://127.0.0.1:${server.address().port}/application/o/${slug}/`;
  provider.clientId = clientId;
  provider.clientSecret = clientSecret;
  provider.close = () => new Promise((resolve) => server.close(resolve));
  return provider;
}
