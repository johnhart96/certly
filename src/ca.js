import "reflect-metadata";
import { webcrypto, randomBytes, createHash } from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import * as x509 from "@peculiar/x509";

x509.cryptoProvider.set(webcrypto);

const SIGNING_ALG = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };
const DAY = 24 * 60 * 60 * 1000;

// Browsers (Apple in particular) reject leaf certs valid for longer than this.
export const MAX_LEAF_DAYS = 825;
export const DEFAULT_LEAF_DAYS = 397;

export const KEY_TYPES = {
  "ec-p256": { name: "ECDSA", namedCurve: "P-256" },
  "ec-p384": { name: "ECDSA", namedCurve: "P-384" },
  "rsa-2048": { ...SIGNING_ALG, modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) },
  "rsa-4096": { ...SIGNING_ALG, modulusLength: 4096, publicExponent: new Uint8Array([1, 0, 1]) },
};

function toPem(der, label) {
  const b64 = Buffer.from(der).toString("base64").match(/.{1,64}/g).join("\n");
  return `-----BEGIN ${label}-----\n${b64}\n-----END ${label}-----\n`;
}

function fromPem(pem) {
  const b64 = pem.replace(/-----(BEGIN|END)[^-]+-----/g, "").replace(/\s+/g, "");
  return Buffer.from(b64, "base64");
}

// Positive, non-zero 128-bit serial (high bit cleared so DER doesn't need padding).
function randomSerial() {
  const bytes = randomBytes(16);
  bytes[0] = (bytes[0] & 0x7f) | 0x01;
  return bytes.toString("hex");
}

export function certInfo(cert) {
  const der = Buffer.from(cert.rawData);
  return {
    subject: cert.subject,
    issuer: cert.issuer,
    serialNumber: cert.serialNumber,
    notBefore: cert.notBefore.toISOString(),
    notAfter: cert.notAfter.toISOString(),
    sha256: createHash("sha256").update(der).digest("hex").toUpperCase().match(/.{2}/g).join(":"),
  };
}

export class CertificateAuthority {
  constructor(dir) {
    this.dir = dir;
    this.keyPath = path.join(dir, "ca.key");
    this.certPath = path.join(dir, "ca.crt");
  }

  async init({ commonName, organization }) {
    await fs.mkdir(this.dir, { recursive: true });
    try {
      const [keyPem, certPem] = await Promise.all([
        fs.readFile(this.keyPath, "utf8"),
        fs.readFile(this.certPath, "utf8"),
      ]);
      this.privateKey = await webcrypto.subtle.importKey("pkcs8", fromPem(keyPem), SIGNING_ALG, false, ["sign"]);
      this.cert = new x509.X509Certificate(certPem);
      return false;
    } catch (err) {
      if (err.code !== "ENOENT") throw err;
    }
    await this.#generate({ commonName, organization });
    return true;
  }

  async #generate({ commonName, organization }) {
    const keys = await webcrypto.subtle.generateKey(
      { ...SIGNING_ALG, modulusLength: 4096, publicExponent: new Uint8Array([1, 0, 1]) },
      true,
      ["sign", "verify"],
    );
    const now = Date.now();
    const name = [`CN=${commonName}`, organization && `O=${organization}`].filter(Boolean).join(", ");
    const cert = await x509.X509CertificateGenerator.createSelfSigned({
      serialNumber: randomSerial(),
      name,
      notBefore: new Date(now - DAY),
      notAfter: new Date(now + 10 * 365 * DAY),
      signingAlgorithm: SIGNING_ALG,
      keys,
      extensions: [
        new x509.BasicConstraintsExtension(true, 0, true),
        new x509.KeyUsagesExtension(
          x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign | x509.KeyUsageFlags.digitalSignature,
          true,
        ),
        await x509.SubjectKeyIdentifierExtension.create(keys.publicKey),
      ],
    });

    const pkcs8 = await webcrypto.subtle.exportKey("pkcs8", keys.privateKey);
    await fs.writeFile(this.keyPath, toPem(pkcs8, "PRIVATE KEY"), { mode: 0o600 });
    await fs.writeFile(this.certPath, cert.toString("pem") + "\n");

    this.privateKey = keys.privateKey;
    this.cert = cert;
  }

  get certPem() {
    return this.cert.toString("pem") + "\n";
  }

  get certDer() {
    return Buffer.from(this.cert.rawData);
  }

  get info() {
    return certInfo(this.cert);
  }

  // Signs a CSR. `allowName(name)` decides whether each requested DNS name is permitted.
  async sign(csrPem, { days = DEFAULT_LEAF_DAYS, allowName }) {
    let csr;
    try {
      csr = new x509.Pkcs10CertificateRequest(csrPem.trim());
    } catch {
      throw new UserError("Could not parse CSR. Expected a PEM-encoded PKCS#10 certificate request.");
    }
    if (!(await csr.verify())) throw new UserError("CSR signature is invalid.");

    const commonName = csr.subjectName.getField("CN")[0]?.toLowerCase();
    const sanExt = csr.extensions.find((e) => e instanceof x509.SubjectAlternativeNameExtension);
    const sanItems = sanExt ? sanExt.names.items : [];

    const unsupported = sanItems.filter((n) => n.type !== "dns");
    if (unsupported.length) {
      throw new UserError(`Only DNS subject alternative names are supported (found ${unsupported.map((n) => n.type).join(", ")}).`);
    }

    // Browsers ignore CN and only check SANs, so always include the CN as a SAN.
    const names = [...new Set([commonName, ...sanItems.map((n) => n.value.toLowerCase())].filter(Boolean))];
    if (!names.length) throw new UserError("CSR contains no common name or DNS names.");

    return this.#issue({
      subject: csr.subjectName.toString(),
      publicKey: csr.publicKey,
      commonName,
      names,
      days,
      allowName,
    });
  }

  // Generates a fresh key pair on the server and issues a certificate for it.
  // The private key is returned to the caller and never written to disk.
  async generate({ names, keyType = "ec-p256", days = DEFAULT_LEAF_DAYS, allowName }) {
    const algorithm = KEY_TYPES[keyType];
    if (!algorithm) throw new UserError(`Unsupported key type. Choose one of: ${Object.keys(KEY_TYPES).join(", ")}.`);

    names = [...new Set((names || []).map((n) => String(n).trim().toLowerCase()).filter(Boolean))];
    if (!names.length) throw new UserError("Enter at least one hostname.");
    this.#checkRequest(names, days, allowName);

    const keys = await webcrypto.subtle.generateKey(algorithm, true, ["sign", "verify"]);
    const publicKey = await x509.PublicKey.create(keys.publicKey);
    const issued = await this.#issue({ subject: `CN=${names[0]}`, publicKey, commonName: names[0], names, days, allowName });
    const pkcs8 = await webcrypto.subtle.exportKey("pkcs8", keys.privateKey);
    return { ...issued, keyPem: toPem(pkcs8, "PRIVATE KEY") };
  }

  #checkRequest(names, days, allowName) {
    const rejected = names.filter((n) => !allowName(n));
    if (rejected.length) throw new UserError(`Names outside this domain: ${rejected.join(", ")}`);
    days = Number(days);
    if (!(Number.isInteger(days) && days >= 1 && days <= MAX_LEAF_DAYS)) {
      throw new UserError(`Validity must be between 1 and ${MAX_LEAF_DAYS} days.`);
    }
  }

  async #issue({ subject, publicKey, commonName, names, days, allowName }) {
    this.#checkRequest(names, days, allowName);

    const now = Date.now();
    const cert = await x509.X509CertificateGenerator.create({
      serialNumber: randomSerial(),
      subject: subject || `CN=${names[0]}`,
      issuer: this.cert.subject,
      notBefore: new Date(now - 60 * 60 * 1000),
      notAfter: new Date(now + Number(days) * DAY),
      signingAlgorithm: SIGNING_ALG,
      publicKey,
      signingKey: this.privateKey,
      extensions: [
        new x509.BasicConstraintsExtension(false, undefined, true),
        // keyEncipherment only applies to RSA key exchange; EC keys get digitalSignature alone.
        new x509.KeyUsagesExtension(
          x509.KeyUsageFlags.digitalSignature |
            (publicKey.algorithm.name === "ECDSA" ? 0 : x509.KeyUsageFlags.keyEncipherment),
          true,
        ),
        new x509.ExtendedKeyUsageExtension([x509.ExtendedKeyUsage.serverAuth, x509.ExtendedKeyUsage.clientAuth]),
        new x509.SubjectAlternativeNameExtension(names.map((value) => ({ type: "dns", value }))),
        await x509.SubjectKeyIdentifierExtension.create(publicKey),
        await x509.AuthorityKeyIdentifierExtension.create(this.cert.publicKey),
      ],
    });

    return {
      cert,
      pem: cert.toString("pem") + "\n",
      commonName: commonName || names[0],
      names,
      keyAlgorithm: describeKey(publicKey.algorithm),
    };
  }
}

function describeKey(alg) {
  if (alg.name === "ECDSA") return `EC ${alg.namedCurve}`;
  if (alg.modulusLength) return `RSA ${alg.modulusLength}`;
  return alg.name;
}

export class UserError extends Error {}
