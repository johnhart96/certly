import path from "node:path";
import { createApp, VERSION, PRERELEASE } from "./app.js";
import { oidcOptionsFromEnv } from "./auth.js";

const PORT = Number(process.env.PORT) || 3000;
const DATA_DIR = path.resolve(process.env.DATA_DIR || "./data");
const AUTH_USER = process.env.CERTLY_USERNAME;
const AUTH_PASS = process.env.CERTLY_PASSWORD;

const { app, ca, caCreated } = await createApp({
  dataDir: DATA_DIR,
  caName: process.env.CA_NAME || undefined,
  caOrganization: process.env.CA_ORGANIZATION || undefined,
  auth: { username: AUTH_USER, password: AUTH_PASS },
  oidc: oidcOptionsFromEnv(process.env),
});

if (caCreated) console.log(`Generated new root CA "${ca.cert.subject}" in ${path.join(DATA_DIR, "ca")}`);
console.log(`CA fingerprint (SHA-256): ${ca.info.sha256}`);

app.listen(PORT, () => {
  console.log(`Certly v${VERSION}${PRERELEASE ? " (pre-release)" : ""} listening on http://0.0.0.0:${PORT}`);
  if (process.env.OIDC_ISSUER) console.log(`Authentication: OpenID Connect via ${process.env.OIDC_ISSUER}`);
  else if (AUTH_USER && AUTH_PASS) console.log("Authentication: HTTP basic auth");
  else console.log("Authentication disabled (configure OIDC or set CERTLY_USERNAME and CERTLY_PASSWORD).");
});
