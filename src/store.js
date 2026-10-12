import fs from "node:fs/promises";
import path from "node:path";
import { randomUUID } from "node:crypto";

// Tiny JSON-file store. Everything is held in memory and flushed atomically on each change.
export class Store {
  constructor(dir) {
    this.dir = dir;
    this.dbPath = path.join(dir, "db.json");
    this.certDir = path.join(dir, "certs");
    this.data = { domains: [], certificates: [] };
    this.writing = Promise.resolve();
  }

  async init() {
    await fs.mkdir(this.certDir, { recursive: true });
    try {
      this.data = JSON.parse(await fs.readFile(this.dbPath, "utf8"));
    } catch (err) {
      if (err.code !== "ENOENT") throw err;
      await this.#flush();
    }
  }

  #flush() {
    const json = JSON.stringify(this.data, null, 2);
    this.writing = this.writing.then(async () => {
      const tmp = `${this.dbPath}.tmp`;
      await fs.writeFile(tmp, json);
      await fs.rename(tmp, this.dbPath);
    });
    return this.writing;
  }

  listDomains() {
    return this.data.domains.map((d) => ({
      ...d,
      certificateCount: this.data.certificates.filter((c) => c.domainId === d.id).length,
    }));
  }

  getDomain(id) {
    return this.data.domains.find((d) => d.id === id);
  }

  findDomainByName(name) {
    return this.data.domains.find((d) => d.name === name);
  }

  async addDomain(name) {
    const domain = { id: randomUUID(), name, createdAt: new Date().toISOString() };
    this.data.domains.push(domain);
    await this.#flush();
    return domain;
  }

  async deleteDomain(id) {
    const certs = this.listCertificates(id);
    this.data.domains = this.data.domains.filter((d) => d.id !== id);
    this.data.certificates = this.data.certificates.filter((c) => c.domainId !== id);
    await this.#flush();
    await Promise.all(certs.map((c) => this.#removeCertFiles(c.id)));
  }

  listCertificates(domainId) {
    return this.data.certificates
      .filter((c) => c.domainId === domainId)
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  }

  getCertificate(id) {
    return this.data.certificates.find((c) => c.id === id);
  }

  async addCertificate(meta, certPem, csrPem) {
    const record = { id: randomUUID(), createdAt: new Date().toISOString(), ...meta };
    await fs.writeFile(this.#certFile(record.id, "crt"), certPem);
    if (csrPem) await fs.writeFile(this.#certFile(record.id, "csr"), csrPem.trim() + "\n");
    this.data.certificates.push(record);
    await this.#flush();
    return record;
  }

  async deleteCertificate(id) {
    this.data.certificates = this.data.certificates.filter((c) => c.id !== id);
    await this.#flush();
    await this.#removeCertFiles(id);
  }

  readCertificatePem(id) {
    return fs.readFile(this.#certFile(id, "crt"), "utf8");
  }

  readCsrPem(id) {
    return fs.readFile(this.#certFile(id, "csr"), "utf8");
  }

  #certFile(id, ext) {
    return path.join(this.certDir, `${id}.${ext}`);
  }

  async #removeCertFiles(id) {
    await Promise.all(["crt", "csr"].map((ext) => fs.rm(this.#certFile(id, ext), { force: true })));
  }
}
