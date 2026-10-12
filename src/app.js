import express from "express";
import path from "node:path";
import { timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { CertificateAuthority, UserError, DEFAULT_LEAF_DAYS, MAX_LEAF_DAYS, certInfo } from "./ca.js";
import { Store } from "./store.js";
import { setupOidc, AuthError, renderAuthError } from "./auth.js";

const PUBLIC_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "public");
export const VERSION = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")).version;
export const PRERELEASE = prereleaseOf(VERSION);

// The semver pre-release identifier, e.g. "beta.1" for "1.2.0-beta.1", or null for a normal release.
export function prereleaseOf(version) {
  return /^\d+\.\d+\.\d+-([0-9A-Za-z.-]+)(?:\+[0-9A-Za-z.-]+)?$/.exec(version)?.[1] ?? null;
}

const LABEL = "(?!-)[a-z0-9-]{1,63}(?<!-)";
const DOMAIN_RE = new RegExp(`^${LABEL}(\\.${LABEL})*$`);
const CERT_NAME_RE = new RegExp(`^(\\*\\.)?${LABEL}(\\.${LABEL})*$`);

/**
 * Builds the Certly Express app. Creates the root CA in `dataDir` on first run.
 * Returns the app plus the CA so callers can report on it.
 */
export async function createApp({ dataDir, caName = "Certly Local CA", caOrganization = "Certly", auth, oidc }) {
  const basicEnabled = Boolean(auth?.username && auth?.password);
  if (oidc && basicEnabled) {
    throw new Error("Configure either OIDC or basic auth (CERTLY_USERNAME/CERTLY_PASSWORD), not both.");
  }
  const authMode = oidc ? "oidc" : basicEnabled ? "basic" : "none";

  const ca = new CertificateAuthority(path.join(dataDir, "ca"));
  const store = new Store(dataDir);
  await store.init();
  const caCreated = await ca.init({ commonName: caName, organization: caOrganization });

  const app = express();
  app.disable("x-powered-by");

  if (oidc) {
    // Public so the sign-in and signed-out pages can show it without starting a login.
    app.get("/favicon.svg", (req, res) => res.sendFile(path.join(PUBLIC_DIR, "favicon.svg")));
    app.use(await setupOidc(app, oidc, dataDir));
  } else if (basicEnabled) {
    app.use(basicAuth(auth.username, auth.password));
  }

  app.use(express.json({ limit: "64kb" }));
  app.use(express.static(PUBLIC_DIR));

  const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

  app.get("/api/version", (req, res) => {
    res.json({ version: VERSION, prerelease: PRERELEASE });
  });

  app.get("/api/me", (req, res) => {
    res.json({ authMode, user: req.user ?? null });
  });

  // --- Certificate authority -------------------------------------------------

  app.get("/api/ca", (req, res) => {
    res.json({ ...ca.info, defaultDays: DEFAULT_LEAF_DAYS, maxDays: MAX_LEAF_DAYS });
  });

  app.get("/api/ca/download/:format", (req, res) => {
    const base = slug(caName);
    switch (req.params.format) {
      case "pem":
        return sendFile(res, `${base}.crt`, ca.certPem, "application/x-x509-ca-cert");
      case "der":
        return sendFile(res, `${base}.cer`, ca.certDer, "application/x-x509-ca-cert");
      default:
        res.status(404).json({ error: "Unknown format" });
    }
  });

  // --- Domains ---------------------------------------------------------------

  app.get("/api/domains", (req, res) => {
    res.json(store.listDomains());
  });

  app.post("/api/domains", wrap(async (req, res) => {
    const name = String(req.body?.name ?? "").trim().toLowerCase().replace(/\.$/, "");
    if (!DOMAIN_RE.test(name) || name.length > 253) throw new UserError("Enter a valid domain name, e.g. example.com");
    if (store.findDomainByName(name)) throw new UserError(`${name} has already been added.`);
    res.status(201).json(await store.addDomain(name));
  }));

  app.delete("/api/domains/:id", wrap(async (req, res) => {
    if (!store.getDomain(req.params.id)) return res.status(404).json({ error: "Domain not found" });
    await store.deleteDomain(req.params.id);
    res.status(204).end();
  }));

  // --- Certificates ----------------------------------------------------------

  app.get("/api/domains/:id/certificates", (req, res) => {
    if (!store.getDomain(req.params.id)) return res.status(404).json({ error: "Domain not found" });
    res.json(store.listCertificates(req.params.id));
  });

  app.post("/api/domains/:id/certificates", wrap(async (req, res) => {
    const domain = store.getDomain(req.params.id);
    if (!domain) return res.status(404).json({ error: "Domain not found" });

    const csrPem = String(req.body?.csr ?? "");
    if (!csrPem.includes("CERTIFICATE REQUEST")) throw new UserError("Paste or upload a PEM-encoded CSR.");

    const signed = await ca.sign(csrPem, { days: req.body?.days ?? DEFAULT_LEAF_DAYS, allowName: domainScope(domain) });
    res.status(201).json(await saveCertificate(domain, signed, { source: "csr", csrPem }));
  }));

  // Generates the private key server-side. The key is returned once in the response and never stored.
  app.post("/api/domains/:id/certificates/generate", wrap(async (req, res) => {
    const domain = store.getDomain(req.params.id);
    if (!domain) return res.status(404).json({ error: "Domain not found" });

    const names = Array.isArray(req.body?.names) ? req.body.names : [];
    const issued = await ca.generate({
      names,
      keyType: req.body?.keyType,
      days: req.body?.days ?? DEFAULT_LEAF_DAYS,
      allowName: domainScope(domain),
    });
    const record = await saveCertificate(domain, issued, { source: "generated" });
    res.status(201).json({ ...record, privateKey: issued.keyPem, certificate: issued.pem, chain: issued.pem + ca.certPem });
  }));

  function domainScope(domain) {
    return (n) => CERT_NAME_RE.test(n) && (n === domain.name || n.endsWith(`.${domain.name}`));
  }

  function saveCertificate(domain, issued, { source, csrPem }) {
    const info = certInfo(issued.cert);
    return store.addCertificate(
      {
        domainId: domain.id,
        source,
        commonName: issued.commonName,
        names: issued.names,
        keyAlgorithm: issued.keyAlgorithm,
        serialNumber: info.serialNumber,
        notBefore: info.notBefore,
        notAfter: info.notAfter,
        sha256: info.sha256,
      },
      issued.pem,
      csrPem,
    );
  }

  app.get("/api/certificates/:id/download/:kind", wrap(async (req, res) => {
    const record = store.getCertificate(req.params.id);
    if (!record) return res.status(404).json({ error: "Certificate not found" });
    const base = slug(record.commonName);
    const pem = await store.readCertificatePem(record.id);

    switch (req.params.kind) {
      case "cert":
        return sendFile(res, `${base}.crt`, pem, "application/x-pem-file");
      case "fullchain":
        return sendFile(res, `${base}.fullchain.pem`, pem + ca.certPem, "application/x-pem-file");
      case "csr":
        if (record.source === "generated") return res.status(404).json({ error: "This certificate was issued without a CSR." });
        return sendFile(res, `${base}.csr`, await store.readCsrPem(record.id), "application/pkcs10");
      default:
        res.status(404).json({ error: "Unknown download" });
    }
  }));

  app.delete("/api/certificates/:id", wrap(async (req, res) => {
    if (!store.getCertificate(req.params.id)) return res.status(404).json({ error: "Certificate not found" });
    await store.deleteCertificate(req.params.id);
    res.status(204).end();
  }));

  // --- Errors ----------------------------------------------------------------

  app.use("/api", (req, res) => res.status(404).json({ error: "Not found" }));

  app.use((err, req, res, next) => {
    if (err instanceof UserError) return res.status(400).json({ error: err.message });
    if (err instanceof AuthError) {
      if (err.cause) console.warn(`${err.message} (${err.cause.message})`);
      return res.status(err.status).type("html").send(renderAuthError(err, oidc.publicUrl));
    }
    if (err.type === "entity.too.large") return res.status(413).json({ error: "Request too large." });
    console.error(err);
    res.status(500).json({ error: "Internal server error" });
  });

  return { app, ca, caCreated };
}

// --- Helpers ---------------------------------------------------------------

function slug(name) {
  return name.replace(/^\*\./, "wildcard.").replace(/[^a-zA-Z0-9._-]+/g, "-").replace(/^-+|-+$/g, "") || "certificate";
}

function sendFile(res, filename, body, type) {
  res.set("Content-Type", type);
  res.set("Content-Disposition", `attachment; filename="${filename}"`);
  res.send(body);
}

function basicAuth(user, pass) {
  const expected = Buffer.from(`${user}:${pass}`);
  return (req, res, next) => {
    const [scheme, encoded] = (req.headers.authorization || "").split(" ");
    const given = scheme === "Basic" && encoded ? Buffer.from(encoded, "base64") : Buffer.alloc(0);
    if (given.length === expected.length && timingSafeEqual(given, expected)) return next();
    res.set("WWW-Authenticate", 'Basic realm="Certly", charset="UTF-8"');
    res.status(401).send("Authentication required");
  };
}
