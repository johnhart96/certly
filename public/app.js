const $ = (sel) => document.querySelector(sel);

const state = {
  domains: [],
  current: null,
  defaultDays: 397,
};

// --- API -------------------------------------------------------------------

async function api(path, options = {}) {
  const res = await fetch(`api/${path}`, {
    ...options,
    headers: options.body ? { "Content-Type": "application/json" } : undefined,
    body: options.body ? JSON.stringify(options.body) : undefined,
  });
  if (res.status === 204) return null;
  const data = await res.json().catch(() => ({}));
  // Session expired or signed out elsewhere: go back through the identity provider.
  if (res.status === 401 && data.login) {
    location.href = data.login;
    return new Promise(() => {});
  }
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
  return data;
}

// --- Helpers ---------------------------------------------------------------

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}

function formatDate(iso) {
  return new Date(iso).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}

function expiryStatus(iso) {
  const days = Math.ceil((new Date(iso) - Date.now()) / 86_400_000);
  if (days <= 0) return { cls: "bad", label: "Expired" };
  if (days <= 30) return { cls: "warn", label: `${days}d left` };
  return { cls: "ok", label: `${days}d left` };
}

function toast(message, type = "info") {
  const el = document.createElement("div");
  el.className = `toast ${type}`;
  el.textContent = message;
  $("#toasts").append(el);
  setTimeout(() => el.remove(), type === "error" ? 6000 : 3500);
}

// --- CA --------------------------------------------------------------------

async function loadCa() {
  const ca = await api("ca");
  state.defaultDays = ca.defaultDays;
  for (const id of ["#csr-days", "#gen-days"]) {
    $(id).value = ca.defaultDays;
    $(id).max = ca.maxDays;
  }
  $("#ca-subject").textContent = ca.subject;
  $("#ca-expires").textContent = formatDate(ca.notAfter);
  $("#ca-fingerprint").textContent = ca.sha256;
  const status = expiryStatus(ca.notAfter);
  if (status.cls !== "ok") {
    $("#ca-status").className = `pill ${status.cls}`;
    $("#ca-status").textContent = status.label;
  }
}

// --- Domains ---------------------------------------------------------------

async function loadDomains() {
  state.domains = await api("domains");
  state.domains.sort((a, b) => a.name.localeCompare(b.name));
  renderDomains();
}

function renderDomains() {
  const currentId = state.current?.id;
  $("#domain-list").innerHTML = state.domains
    .map(
      (d) => `<li><a href="#/domains/${d.id}" class="${d.id === currentId ? "active" : ""}">
        <span class="name">${escapeHtml(d.name)}</span>
        <span class="count" title="Certificates issued">${d.certificateCount}</span>
      </a></li>`,
    )
    .join("");
  $("#domain-empty").hidden = state.domains.length > 0;
}

$("#add-domain").addEventListener("submit", async (e) => {
  e.preventDefault();
  const input = $("#domain-input");
  try {
    const domain = await api("domains", { method: "POST", body: { name: input.value } });
    input.value = "";
    await loadDomains();
    location.hash = `#/domains/${domain.id}`;
    toast(`Added ${domain.name}`);
  } catch (err) {
    toast(err.message, "error");
  }
});

$("#delete-domain").addEventListener("click", async () => {
  const domain = state.current;
  if (!domain) return;
  const n = domain.certificateCount;
  const extra = n ? ` and its ${n} certificate${n === 1 ? "" : "s"}` : "";
  if (!confirm(`Delete ${domain.name}${extra}? This cannot be undone.`)) return;
  try {
    await api(`domains/${domain.id}`, { method: "DELETE" });
    showGenerated(null);
    location.hash = "";
    await loadDomains();
    toast(`Deleted ${domain.name}`);
  } catch (err) {
    toast(err.message, "error");
  }
});

// --- Domain view -----------------------------------------------------------

async function showDomain(id) {
  const domain = state.domains.find((d) => d.id === id);
  state.current = domain || null;
  renderDomains();
  $("#welcome").hidden = !!domain;
  $("#domain-view").hidden = !domain;
  if (!domain) return;

  $("#domain-title").textContent = domain.name;
  $("#domain-scope").textContent = `Signs ${domain.name}, *.${domain.name} and any subdomain of ${domain.name}.`;
  $("#openssl-cmd").textContent = opensslCommand(domain.name);
  resetCsrForm();
  resetGenerateForm();
  await loadCertificates();
}

function opensslCommand(name) {
  return [
    "openssl req -new -newkey rsa:2048 -nodes \\",
    `  -keyout ${name}.key -out ${name}.csr \\`,
    `  -subj "/CN=${name}" \\`,
    `  -addext "subjectAltName=DNS:${name},DNS:*.${name}"`,
  ].join("\n");
}

async function loadCertificates() {
  const domain = state.current;
  const certs = await api(`domains/${domain.id}/certificates`);
  domain.certificateCount = certs.length;
  renderDomains();

  $("#cert-count").textContent = certs.length ? `${certs.length} issued` : "";
  $("#cert-empty").hidden = certs.length > 0;
  $(".certs").hidden = certs.length === 0;
  $("#cert-rows").innerHTML = certs
    .map((c) => {
      const status = expiryStatus(c.notAfter);
      const dl = (kind, label, title) =>
        `<a class="btn small" href="api/certificates/${c.id}/download/${kind}" download title="${title}">${label}</a>`;
      return `<tr>
        <td class="names">${c.names.map((n) => `<div>${escapeHtml(n)}</div>`).join("")}
          <div class="sub" title="Serial ${escapeHtml(c.serialNumber)}">Issued ${formatDate(c.createdAt)}${c.source === "generated" ? " · key generated by Certly" : ""}</div></td>
        <td>${escapeHtml(c.keyAlgorithm)}</td>
        <td>${formatDate(c.notAfter)}<br><span class="pill ${status.cls}">${status.label}</span></td>
        <td class="actions">
          ${dl("cert", "Certificate", "Leaf certificate only (.crt)")}
          ${dl("fullchain", "Full chain", "Certificate + root CA, for nginx / Caddy / Traefik")}
          ${c.source === "generated" ? "" : dl("csr", "CSR", "The original certificate request")}
          <button class="icon-btn" data-delete="${c.id}" title="Delete certificate" aria-label="Delete certificate">✕</button>
        </td>
      </tr>`;
    })
    .join("");
}

$("#cert-rows").addEventListener("click", async (e) => {
  const id = e.target.closest("[data-delete]")?.dataset.delete;
  if (!id || !confirm("Delete this certificate record? Copies already deployed will keep working until they expire.")) return;
  try {
    await api(`certificates/${id}`, { method: "DELETE" });
    await loadCertificates();
    toast("Certificate deleted");
  } catch (err) {
    toast(err.message, "error");
  }
});

// --- Tabs ------------------------------------------------------------------

document.querySelectorAll(".tab").forEach((tab) =>
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((t) => {
      t.classList.toggle("active", t === tab);
      t.setAttribute("aria-selected", t === tab);
    });
    document.querySelectorAll("[data-panel]").forEach((p) => (p.hidden = p.dataset.panel !== tab.dataset.tab));
  }),
);

// --- Generate key + certificate --------------------------------------------

// Holds the last generated bundle. The private key only ever lives here in the browser.
let generated = null;

function resetGenerateForm() {
  const name = state.current.name;
  $("#gen-names").value = `${name}, *.${name}`;
  $("#gen-days").value = state.defaultDays;
  showGenerated(null);
}

function showGenerated(bundle) {
  generated = bundle;
  $("#gen-result").hidden = !bundle;
  if (bundle) $("#gen-result-names").textContent = bundle.names.join(", ");
}

$("#gen-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const names = $("#gen-names").value.split(/[\s,]+/).filter(Boolean);
  const btn = $("#gen-btn");
  btn.disabled = true;
  btn.textContent = "Generating…";
  try {
    const result = await api(`domains/${state.current.id}/certificates/generate`, {
      method: "POST",
      body: { names, keyType: $("#gen-key").value, days: Number($("#gen-days").value) },
    });
    showGenerated({ ...result, keySaved: false });
    await loadCertificates();
  } catch (err) {
    toast(err.message, "error");
  } finally {
    btn.disabled = false;
    btn.textContent = "Generate certificate";
  }
});

$("#gen-result").addEventListener("click", (e) => {
  const kind = e.target.closest("[data-save]")?.dataset.save;
  if (!kind || !generated) return;
  const base = generated.commonName.replace(/^\*\./, "wildcard.");
  const files = {
    key: [`${base}.key`, generated.privateKey],
    cert: [`${base}.crt`, generated.certificate],
    chain: [`${base}.fullchain.pem`, generated.chain],
  };
  saveFile(...files[kind]);
  if (kind === "key") generated.keySaved = true;
});

$("#gen-dismiss").addEventListener("click", () => {
  if (generated && !generated.keySaved && !confirm("You haven't downloaded the private key. Discard it?")) return;
  showGenerated(null);
});

window.addEventListener("beforeunload", (e) => {
  if (generated && !generated.keySaved) e.preventDefault();
});

function saveFile(filename, contents) {
  const url = URL.createObjectURL(new Blob([contents], { type: "application/x-pem-file" }));
  const a = Object.assign(document.createElement("a"), { href: url, download: filename });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

// --- CSR upload ------------------------------------------------------------

function resetCsrForm() {
  $("#csr-text").value = "";
  $("#csr-file").value = "";
  $("#csr-filename").textContent = ".csr / .pem — RSA or ECDSA";
  $("#csr-days").value = state.defaultDays;
}

async function loadCsrFile(file) {
  if (!file) return;
  if (file.size > 32 * 1024) return toast("That file is too large to be a CSR.", "error");
  $("#csr-text").value = await file.text();
  $("#csr-filename").textContent = file.name;
}

$("#csr-file").addEventListener("change", (e) => loadCsrFile(e.target.files[0]));

const dropzone = $("#dropzone");
["dragenter", "dragover"].forEach((evt) =>
  dropzone.addEventListener(evt, (e) => {
    e.preventDefault();
    dropzone.classList.add("over");
  }),
);
["dragleave", "drop"].forEach((evt) => dropzone.addEventListener(evt, () => dropzone.classList.remove("over")));
dropzone.addEventListener("drop", (e) => {
  e.preventDefault();
  loadCsrFile(e.dataTransfer.files[0]);
});

$("#csr-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const csr = $("#csr-text").value.trim();
  if (!csr) return toast("Upload or paste a CSR first.", "error");
  const btn = $("#sign-btn");
  btn.disabled = true;
  try {
    const cert = await api(`domains/${state.current.id}/certificates`, {
      method: "POST",
      body: { csr, days: Number($("#csr-days").value) },
    });
    resetCsrForm();
    await loadCertificates();
    toast(`Issued certificate for ${cert.names.join(", ")}`);
  } catch (err) {
    toast(err.message, "error");
  } finally {
    btn.disabled = false;
  }
});

$("#copy-cmd").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText($("#openssl-cmd").textContent);
    toast("Command copied");
  } catch {
    toast("Couldn't access the clipboard — select the command and copy it manually.", "error");
  }
});

// --- Routing ---------------------------------------------------------------

let currentHash = location.hash;

function route() {
  if (generated && !generated.keySaved && location.hash !== currentHash) {
    if (!confirm("You haven't downloaded the private key. Leave and discard it?")) {
      history.replaceState(null, "", currentHash || location.pathname);
      return;
    }
  }
  currentHash = location.hash;
  const match = location.hash.match(/^#\/domains\/([\w-]+)$/);
  showDomain(match?.[1]).catch((err) => toast(err.message, "error"));
}

window.addEventListener("hashchange", route);

// The version badge is cosmetic, so a failure here shouldn't surface as an error.
api("version")
  .then(({ version, prerelease }) => {
    const badge = $("#app-version");
    badge.textContent = `v${version}`;
    badge.href = `https://github.com/johnhart/certly/releases/tag/v${encodeURIComponent(version)}`;
    badge.hidden = false;
    $("#app-prerelease").hidden = !prerelease;
  })
  .catch(() => {});

async function loadAccount() {
  const { user } = await api("me");
  if (user) {
    $("#account-name").textContent = user.name;
    $("#account-name").title = user.email || user.name;
    $("#account").hidden = false;
  }
}

loadAccount()
  .then(() => Promise.all([loadCa(), loadDomains()]))
  .then(route)
  .catch((err) => toast(err.message, "error"));
