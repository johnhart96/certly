import "reflect-metadata";
import { webcrypto, createPrivateKey, createPublicKey } from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import * as x509 from "@peculiar/x509";

x509.cryptoProvider.set(webcrypto);

const KEY_ALGS = {
  rsa: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) },
  ec: { name: "ECDSA", namedCurve: "P-256" },
};

// Builds a PEM CSR the same way `openssl req` would.
export async function makeCsr({ cn, sans = [], key = "rsa" } = {}) {
  const algorithm = KEY_ALGS[key];
  const keys = await webcrypto.subtle.generateKey(algorithm, true, ["sign", "verify"]);
  const csr = await x509.Pkcs10CertificateRequestGenerator.create({
    name: cn ? `CN=${cn}` : undefined,
    keys,
    signingAlgorithm: key === "ec" ? { name: "ECDSA", hash: "SHA-256" } : algorithm,
    extensions: sans.length
      ? [new x509.SubjectAlternativeNameExtension(sans.map((value) => ({ type: "dns", value })))]
      : [],
  });
  return csr.toString("pem");
}

export function tempDir() {
  return fs.mkdtemp(path.join(os.tmpdir(), "certly-test-"));
}

export function parseCert(pem) {
  return new x509.X509Certificate(pem);
}

export function sanNames(cert) {
  return cert.getExtension(x509.SubjectAlternativeNameExtension).names.items.map((n) => n.value);
}

// DER SubjectPublicKeyInfo derived from a PEM private key, for comparing against a certificate.
export function publicKeyOf(privateKeyPem) {
  return createPublicKey(createPrivateKey(privateKeyPem)).export({ format: "der", type: "spki" });
}

export { x509 };
