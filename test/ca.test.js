import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import { CertificateAuthority, UserError, KEY_TYPES, MAX_LEAF_DAYS } from "../src/ca.js";
import { makeCsr, tempDir, parseCert, sanNames, publicKeyOf, x509 } from "./helpers.js";

let dir;
let ca;
const allowName = (n) => n === "domain.com" || n.endsWith(".domain.com");

before(async () => {
  dir = await tempDir();
  ca = new CertificateAuthority(path.join(dir, "ca"));
  assert.equal(await ca.init({ commonName: "Test CA", organization: "Certly" }), true);
});

after(() => fs.rm(dir, { recursive: true, force: true }));

async function assertIssuedByCa(cert) {
  assert.equal(cert.issuer, ca.cert.subject);
  assert.ok(await cert.verify({ publicKey: ca.cert.publicKey, signatureOnly: true }));
}

test("root CA is a constrained CA certificate", async () => {
  const bc = ca.cert.getExtension(x509.BasicConstraintsExtension);
  assert.equal(bc.ca, true);
  assert.equal(bc.pathLength, 0);
  assert.equal(ca.cert.subject, "CN=Test CA, O=Certly");
  assert.ok(await ca.cert.isSelfSigned());
});

test("CA private key is written with owner-only permissions", async () => {
  const { mode } = await fs.stat(path.join(dir, "ca", "ca.key"));
  assert.equal(mode & 0o777, 0o600);
});

test("existing CA is reloaded rather than regenerated", async () => {
  const again = new CertificateAuthority(path.join(dir, "ca"));
  assert.equal(await again.init({ commonName: "Other" }), false);
  assert.equal(again.info.sha256, ca.info.sha256);

  const { cert } = await again.sign(await makeCsr({ cn: "domain.com" }), { allowName });
  await assertIssuedByCa(cert);
});

test("signs an RSA CSR and copies the CN into the SANs", async () => {
  const csr = await makeCsr({ cn: "app.domain.com", sans: ["*.app.domain.com"] });
  const result = await ca.sign(csr, { days: 30, allowName });

  assert.deepEqual(result.names, ["app.domain.com", "*.app.domain.com"]);
  assert.equal(result.keyAlgorithm, "RSA 2048");
  assert.deepEqual(sanNames(result.cert), ["app.domain.com", "*.app.domain.com"]);
  await assertIssuedByCa(result.cert);

  const usage = result.cert.getExtension(x509.KeyUsagesExtension).usages;
  assert.ok(usage & x509.KeyUsageFlags.keyEncipherment);
  assert.equal(result.cert.getExtension(x509.BasicConstraintsExtension).ca, false);
  const eku = result.cert.getExtension(x509.ExtendedKeyUsageExtension).usages;
  assert.ok(eku.includes(x509.ExtendedKeyUsage.serverAuth));
});

test("signs an EC CSR without keyEncipherment", async () => {
  const result = await ca.sign(await makeCsr({ cn: "domain.com", key: "ec" }), { allowName });
  assert.equal(result.keyAlgorithm, "EC P-256");
  const usage = result.cert.getExtension(x509.KeyUsagesExtension).usages;
  assert.equal(usage, x509.KeyUsageFlags.digitalSignature);
});

test("signs a CSR with SANs but no CN", async () => {
  const result = await ca.sign(await makeCsr({ sans: ["a.domain.com"] }), { allowName });
  assert.equal(result.commonName, "a.domain.com");
  assert.deepEqual(result.names, ["a.domain.com"]);
});

test("validity period follows the requested days", async () => {
  const { cert } = await ca.sign(await makeCsr({ cn: "domain.com" }), { days: 90, allowName });
  const days = (cert.notAfter - Date.now()) / 86_400_000;
  assert.ok(days > 89.9 && days <= 90, `expected ~90 days, got ${days}`);
});

test("rejects names outside the allowed scope", async () => {
  const csr = await makeCsr({ cn: "domain.com", sans: ["evil.com"] });
  await assert.rejects(ca.sign(csr, { allowName }), (err) => err instanceof UserError && /evil\.com/.test(err.message));
});

test("rejects invalid validity periods", async () => {
  const csr = await makeCsr({ cn: "domain.com" });
  for (const days of [0, -1, 1.5, MAX_LEAF_DAYS + 1, "abc"]) {
    await assert.rejects(ca.sign(csr, { days, allowName }), UserError, `days=${days}`);
  }
});

test("rejects malformed CSRs", async () => {
  const garbage = "-----BEGIN CERTIFICATE REQUEST-----\nabc\n-----END CERTIFICATE REQUEST-----";
  await assert.rejects(ca.sign(garbage, { allowName }), UserError);
});

for (const keyType of Object.keys(KEY_TYPES)) {
  test(`generates a ${keyType} key and matching certificate`, async () => {
    const result = await ca.generate({ names: ["App.Domain.com", "*.domain.com", "app.domain.com"], keyType, allowName });

    assert.deepEqual(result.names, ["app.domain.com", "*.domain.com"]);
    assert.match(result.keyPem, /^-----BEGIN PRIVATE KEY-----/);
    assert.deepEqual(publicKeyOf(result.keyPem), Buffer.from(result.cert.publicKey.rawData));
    assert.deepEqual(sanNames(parseCert(result.pem)), result.names);
    await assertIssuedByCa(result.cert);
  });
}

test("generate validates its input", async () => {
  await assert.rejects(ca.generate({ names: [], allowName }), /at least one hostname/);
  await assert.rejects(ca.generate({ names: ["x.domain.com"], keyType: "dsa", allowName }), /Unsupported key type/);
  await assert.rejects(ca.generate({ names: ["evil.com"], allowName }), /evil\.com/);
});
