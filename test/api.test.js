import { test, before, after, describe } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import { createApp, prereleaseOf } from "../src/app.js";
import { makeCsr, tempDir, parseCert, publicKeyOf } from "./helpers.js";

async function startServer(options = {}) {
  const dataDir = await tempDir();
  const { app } = await createApp({ dataDir, ...options });
  const server = await new Promise((resolve) => {
    const s = app.listen(0, "127.0.0.1", () => resolve(s));
  });
  const base = `http://127.0.0.1:${server.address().port}`;
  return {
    dataDir,
    base,
    async close() {
      await new Promise((resolve) => server.close(resolve));
      await fs.rm(dataDir, { recursive: true, force: true });
    },
  };
}

describe("API", () => {
  let srv;

  async function call(method, url, body) {
    const res = await fetch(srv.base + url, {
      method,
      headers: body ? { "Content-Type": "application/json" } : {},
      body: body ? JSON.stringify(body) : undefined,
    });
    const text = await res.text();
    let json;
    try {
      json = JSON.parse(text);
    } catch {}
    return { status: res.status, headers: res.headers, text, json };
  }

  async function addDomain(name) {
    const res = await call("POST", "/api/domains", { name });
    assert.equal(res.status, 201, res.text);
    return res.json;
  }

  before(async () => {
    srv = await startServer({ caName: "API Test CA" });
  });

  after(() => srv.close());

  test("serves the web UI", async () => {
    const res = await call("GET", "/");
    assert.equal(res.status, 200);
    assert.match(res.text, /<title>Certly<\/title>/);
  });

  test("reports the package.json version", async () => {
    const pkg = JSON.parse(await fs.readFile(new URL("../package.json", import.meta.url), "utf8"));
    const res = await call("GET", "/api/version");
    assert.equal(res.status, 200);
    assert.deepEqual(res.json, { version: pkg.version, prerelease: prereleaseOf(pkg.version) });
  });

  test("detects semver pre-release versions", () => {
    assert.equal(prereleaseOf("1.0.0"), null);
    assert.equal(prereleaseOf("1.0.0+build.5"), null);
    assert.equal(prereleaseOf("1.2.0-beta.1"), "beta.1");
    assert.equal(prereleaseOf("2.0.0-rc.2+sha.abc123"), "rc.2");
    assert.equal(prereleaseOf("1.0.0-alpha"), "alpha");
  });

  test("exposes CA details and downloads", async () => {
    const info = await call("GET", "/api/ca");
    assert.equal(info.json.subject, "CN=API Test CA, O=Certly");
    assert.match(info.json.sha256, /^([0-9A-F]{2}:){31}[0-9A-F]{2}$/);

    const pem = await call("GET", "/api/ca/download/pem");
    assert.match(pem.headers.get("content-disposition"), /filename="API-Test-CA\.crt"/);
    assert.equal(parseCert(pem.text).subject, info.json.subject);

    const der = await fetch(srv.base + "/api/ca/download/der");
    assert.equal(parseCert(Buffer.from(await der.arrayBuffer())).subject, info.json.subject);
  });

  test("never serves the CA private key", async () => {
    for (const url of ["/api/ca/download/key", "/ca.key", "/data/ca/ca.key", "/../data/ca/ca.key"]) {
      const res = await call("GET", url);
      assert.ok(!res.text.includes("PRIVATE KEY"), url);
    }
  });

  test("validates and normalises domains", async () => {
    const domain = await addDomain("Example.COM.");
    assert.equal(domain.name, "example.com");

    assert.equal((await call("POST", "/api/domains", { name: "example.com" })).status, 400);
    for (const name of ["", "bad_domain", "-foo.com", "*.foo.com", "a..b"]) {
      assert.equal((await call("POST", "/api/domains", { name })).status, 400, name);
    }
  });

  test("signs a CSR and serves the downloads", async () => {
    const domain = await addDomain("csr.test");
    const csr = await makeCsr({ cn: "www.csr.test", sans: ["*.csr.test"], key: "ec" });

    const issued = await call("POST", `/api/domains/${domain.id}/certificates`, { csr, days: 30 });
    assert.equal(issued.status, 201, issued.text);
    assert.equal(issued.json.source, "csr");
    assert.deepEqual(issued.json.names, ["www.csr.test", "*.csr.test"]);

    const cert = await call("GET", `/api/certificates/${issued.json.id}/download/cert`);
    assert.match(cert.headers.get("content-disposition"), /filename="www\.csr\.test\.crt"/);

    const chain = await call("GET", `/api/certificates/${issued.json.id}/download/fullchain`);
    assert.equal(chain.text.match(/BEGIN CERTIFICATE/g).length, 2);
    assert.ok(chain.text.startsWith(cert.text));

    const storedCsr = await call("GET", `/api/certificates/${issued.json.id}/download/csr`);
    assert.equal(storedCsr.text.trim(), csr.trim());

    const list = await call("GET", `/api/domains/${domain.id}/certificates`);
    assert.equal(list.json.length, 1);
  });

  test("rejects CSRs for names outside the domain", async () => {
    const domain = await addDomain("scope.test");
    const cases = ["evil.test", "scope.test.evil.test", "notscope.test"];
    for (const cn of cases) {
      const res = await call("POST", `/api/domains/${domain.id}/certificates`, { csr: await makeCsr({ cn }) });
      assert.equal(res.status, 400, cn);
    }
    const missing = await call("POST", `/api/domains/${domain.id}/certificates`, { csr: "hello" });
    assert.equal(missing.status, 400);
  });

  test("generates a key and certificate without storing the key", async () => {
    const domain = await addDomain("gen.test");
    const res = await call("POST", `/api/domains/${domain.id}/certificates/generate`, {
      names: ["gen.test", "*.gen.test"],
      keyType: "ec-p256",
      days: 10,
    });
    assert.equal(res.status, 201, res.text);
    assert.equal(res.json.source, "generated");

    const cert = parseCert(res.json.certificate);
    assert.deepEqual(publicKeyOf(res.json.privateKey), Buffer.from(cert.publicKey.rawData));
    assert.ok(res.json.chain.startsWith(res.json.certificate));

    const csr = await call("GET", `/api/certificates/${res.json.id}/download/csr`);
    assert.equal(csr.status, 404);

    const files = await fs.readdir(path.join(srv.dataDir, "certs"));
    for (const file of files) {
      const contents = await fs.readFile(path.join(srv.dataDir, "certs", file), "utf8");
      assert.ok(!contents.includes("PRIVATE KEY"), `${file} contains a private key`);
    }
    const db = await fs.readFile(path.join(srv.dataDir, "db.json"), "utf8");
    assert.ok(!db.includes("PRIVATE KEY"));
  });

  test("deleting a domain removes its certificates", async () => {
    const domain = await addDomain("delete.test");
    const issued = await call("POST", `/api/domains/${domain.id}/certificates/generate`, { names: ["delete.test"] });
    assert.equal(issued.status, 201);

    assert.equal((await call("DELETE", `/api/domains/${domain.id}`)).status, 204);
    assert.equal((await call("GET", `/api/domains/${domain.id}/certificates`)).status, 404);
    assert.equal((await call("GET", `/api/certificates/${issued.json.id}/download/cert`)).status, 404);
    await assert.rejects(fs.access(path.join(srv.dataDir, "certs", `${issued.json.id}.crt`)));
  });

  test("unknown API routes return JSON 404s", async () => {
    const res = await call("GET", "/api/nope");
    assert.equal(res.status, 404);
    assert.equal(res.json.error, "Not found");
  });
});

describe("basic auth", () => {
  let srv;

  before(async () => {
    srv = await startServer({ auth: { username: "admin", password: "s3cret" } });
  });

  after(() => srv.close());

  const get = (url, auth) =>
    fetch(srv.base + url, { headers: auth ? { Authorization: `Basic ${Buffer.from(auth).toString("base64")}` } : {} });

  test("rejects missing or wrong credentials", async () => {
    for (const auth of [undefined, "admin:wrong", "admin:s3cret2", "nobody:s3cret"]) {
      const res = await get("/api/ca", auth);
      assert.equal(res.status, 401, String(auth));
      assert.match(res.headers.get("www-authenticate"), /Basic/);
    }
    assert.equal((await get("/")).status, 401);
  });

  test("accepts the right credentials", async () => {
    assert.equal((await get("/api/ca", "admin:s3cret")).status, 200);
  });
});
