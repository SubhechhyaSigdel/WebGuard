const state = {
  pollTimer: null,
  latestScanId: null,
};

const el = {
  form: document.getElementById("scanForm"),
  apiBase: document.getElementById("apiBase"),
  targetUrl: document.getElementById("targetUrl"),
  useAuth: document.getElementById("useAuth"),
  authFields: document.getElementById("authFields"),
  loginUrl: document.getElementById("loginUrl"),
  username: document.getElementById("username"),
  password: document.getElementById("password"),
  usernameField: document.getElementById("usernameField"),
  passwordField: document.getElementById("passwordField"),
  loginMethod: document.getElementById("loginMethod"),
  extraFields: document.getElementById("extraFields"),
  securityUrl: document.getElementById("securityUrl"),
  securityLevel: document.getElementById("securityLevel"),
  securityField: document.getElementById("securityField"),
  startBtn: document.getElementById("startBtn"),
  stopPollBtn: document.getElementById("stopPollBtn"),
  scanId: document.getElementById("scanId"),
  scanState: document.getElementById("scanState"),
  scanTarget: document.getElementById("scanTarget"),
  updatedAt: document.getElementById("updatedAt"),
  results: document.getElementById("results"),
  countAll: document.getElementById("countAll"),
  countHigh: document.getElementById("countHigh"),
  countMedium: document.getElementById("countMedium"),
  countLow: document.getElementById("countLow"),
};

function normalizeApiBase(base) {
  return base.trim().replace(/\/+$/, "");
}

function parseExtraFields(raw) {
  if (!raw.trim()) {
    return {};
  }

  try {
    const parsed = JSON.parse(raw);
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      throw new Error("Extra fields must be a JSON object.");
    }
    return parsed;
  } catch (error) {
    throw new Error(`Invalid Extra Fields JSON: ${error.message}`);
  }
}

function stopPolling() {
  if (state.pollTimer) {
    clearInterval(state.pollTimer);
    state.pollTimer = null;
  }
}

function setStatusBadge(statusText) {
  const status = String(statusText || "idle").toLowerCase();
  el.scanState.textContent = status;
  el.scanState.className = `value badge ${status}`;
}

function setMeta(scan) {
  el.scanId.textContent = scan.scan_id ?? state.latestScanId ?? "-";
  el.scanTarget.textContent = scan.target_url || el.targetUrl.value || "-";
  el.updatedAt.textContent = new Date().toLocaleString();
  setStatusBadge(scan.status || "idle");
}

function severityClass(severity) {
  const s = String(severity || "").toLowerCase();
  if (s === "high") return "high";
  if (s === "medium") return "medium";
  return "low";
}

function updateCounts(vulns) {
  const counts = { high: 0, medium: 0, low: 0 };
  for (const vuln of vulns) {
    const key = String(vuln.severity || "").toLowerCase();
    if (key in counts) counts[key] += 1;
  }

  el.countAll.textContent = `All: ${vulns.length}`;
  el.countHigh.textContent = `High: ${counts.high}`;
  el.countMedium.textContent = `Medium: ${counts.medium}`;
  el.countLow.textContent = `Low: ${counts.low}`;
}

function escapeHtml(text) {
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function renderFindings(vulns) {
  updateCounts(vulns);

  if (!vulns.length) {
    el.results.innerHTML = '<div class="results-empty">No vulnerabilities found in this run.</div>';
    return;
  }

  const cards = vulns.map((v) => {
    const sevClass = severityClass(v.severity);
    return `
      <article class="finding">
        <div class="finding-top">
          <h3>${escapeHtml(v.vuln_type || "Unknown")}</h3>
          <span class="sev ${sevClass}">${escapeHtml(v.severity || "LOW")}</span>
        </div>
        <p><strong>URL:</strong> ${escapeHtml(v.affected_url || "-")}</p>
        <p><strong>Parameter:</strong> <code>${escapeHtml(v.parameter || "-")}</code></p>
        <p><strong>Payload:</strong> <code>${escapeHtml(v.payload || "-")}</code></p>
        <p><strong>Evidence:</strong> ${escapeHtml(v.evidence || "-")}</p>
        <p><strong>Description:</strong> ${escapeHtml(v.description || "-")}</p>
      </article>
    `;
  });

  el.results.innerHTML = cards.join("\n");
}

async function fetchScanResult(apiBase, scanId) {
  const response = await fetch(`${apiBase}/scan/${scanId}`);
  if (!response.ok) {
    throw new Error(`Scan polling failed with status ${response.status}`);
  }
  return response.json();
}

async function pollScan(apiBase, scanId) {
  stopPolling();

  async function tick() {
    try {
      const result = await fetchScanResult(apiBase, scanId);
      setMeta(result);
      renderFindings(result.vulnerabilities || []);

      if (["completed", "failed"].includes(String(result.status).toLowerCase())) {
        stopPolling();
        el.startBtn.disabled = false;
      }
    } catch (error) {
      stopPolling();
      el.startBtn.disabled = false;
      setStatusBadge("failed");
      el.results.innerHTML = `<div class="results-empty">${escapeHtml(error.message)}</div>`;
    }
  }

  await tick();
  state.pollTimer = setInterval(tick, 3000);
}

function buildRequestPayload() {
  const payload = {
    url: el.targetUrl.value.trim(),
  };

  if (!el.useAuth.checked) {
    return payload;
  }

  const extraFields = parseExtraFields(el.extraFields.value);

  payload.auth = {
    login_url: el.loginUrl.value.trim(),
    username: el.username.value,
    password: el.password.value,
    username_field: el.usernameField.value.trim() || "username",
    password_field: el.passwordField.value.trim() || "password",
    method: el.loginMethod.value,
    extra_fields: extraFields,
    security_url: el.securityUrl.value.trim() || null,
    security_level: el.securityLevel.value.trim() || null,
    security_field: el.securityField.value.trim() || "security",
  };

  return payload;
}

async function startScan(event) {
  event.preventDefault();
  stopPolling();

  let payload;
  try {
    payload = buildRequestPayload();
  } catch (error) {
    setStatusBadge("failed");
    el.results.innerHTML = `<div class="results-empty">${escapeHtml(error.message)}</div>`;
    return;
  }

  const apiBase = normalizeApiBase(el.apiBase.value);
  el.startBtn.disabled = true;
  el.results.innerHTML = '<div class="results-empty">Starting scan...</div>';
  setStatusBadge("pending");

  try {
    const response = await fetch(`${apiBase}/scan`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      throw new Error(`Scan start failed with status ${response.status}`);
    }

    const data = await response.json();
    state.latestScanId = data.scan_id;
    el.scanId.textContent = data.scan_id;
    setStatusBadge(data.status || "pending");

    await pollScan(apiBase, data.scan_id);
  } catch (error) {
    el.startBtn.disabled = false;
    setStatusBadge("failed");
    el.results.innerHTML = `<div class="results-empty">${escapeHtml(error.message)}</div>`;
  }
}

el.useAuth.addEventListener("change", () => {
  el.authFields.style.display = el.useAuth.checked ? "grid" : "none";
});

el.form.addEventListener("submit", startScan);
el.stopPollBtn.addEventListener("click", () => {
  stopPolling();
  el.startBtn.disabled = false;
  setStatusBadge("pending");
});

setStatusBadge("idle");
