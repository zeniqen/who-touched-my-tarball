const API = "";

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function collectForm(form) {
  const fd = new FormData(form);
  const out = {};
  for (const [key, value] of fd.entries()) {
    const field = form.elements.namedItem(key);
    if (field && field.type === "checkbox") {
      out[key] = true;
    } else if (field && field.type === "number") {
      out[key] = value === "" ? undefined : Number(value);
    } else if (value !== "") {
      out[key] = value;
    }
  }
  return out;
}

let activeSource = null;

async function createJob(kind, params) {
  const response = await fetch(`${API}/api/jobs`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ kind, params }),
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.detail || "Unable to create job");
  return data;
}

async function renderResult(jobId, container) {
  const job = await fetch(`${API}/api/jobs/${jobId}`).then((r) => r.json());
  const data = job.result || {};
  let html = `<div class="card"><strong>Status:</strong> ${job.status} &nbsp; <strong>Exit code:</strong> ${job.exit_code ?? "-"}</div>`;

  const report = data["report.json"];
  if (report) html += reportCard(report, jobId, data.files || []);

  const verification = data["output.json"];
  if (verification) {
    html += `<div class="card"><h3>Verification result</h3><pre>${escapeHtml(JSON.stringify(verification, null, 2))}</pre></div>`;
  }

  const benchmark = data["benchmark.json"];
  if (benchmark) html += benchmarkCard(benchmark, jobId, data.files || []);

  if (data.files && data.files.length) {
    html += `<div class="card"><h3>Output files</h3><ul>${data.files
      .map((file) => `<li><a target="_blank" href="/api/files/${jobId}/${encodeURIComponent(file)}">${escapeHtml(file)}</a></li>`)
      .join("")}</ul></div>`;
  }
  container.innerHTML = html;
}

function severityClass(value) {
  const severity = String(value || "").toLowerCase();
  if (["critical", "high", "medium"].includes(severity)) return severity;
  return "info";
}

function reportCard(report, jobId, files) {
  let html = `<div class="card"><h3>${escapeHtml(report.verdict || "REPORT")} - ${report.risk_score ?? "-"} / 100</h3>`;
  if (report.summary) html += `<p>${escapeHtml(report.summary)}</p>`;
  if (report.stats) html += `<pre>${escapeHtml(JSON.stringify(report.stats, null, 2))}</pre>`;

  for (const finding of report.findings || []) {
    html += `<div style="border:1px solid var(--border); border-radius:.8rem; padding:.8rem; margin:.6rem 0;">
      <strong>${escapeHtml(finding.path)}</strong>
      <span class="badge ${severityClass(finding.severity)}">${escapeHtml(finding.severity || "info")}</span><br>
      <span>${escapeHtml(finding.reason || "")}</span>`;
    if (finding.signals && finding.signals.length) {
      html += `<pre>${escapeHtml(finding.signals.map((s) => `${s.rule} (line ${s.line})`).join("\n"))}</pre>`;
    }
    html += `</div>`;
  }

  if (report.notes && report.notes.length) {
    html += `<details><summary>Analyzer notes</summary><ul>${report.notes
      .map((note) => `<li>${escapeHtml(note)}</li>`)
      .join("")}</ul></details>`;
  }
  html += `</div>`;
  return html;
}

function benchmarkCard(benchmark, jobId, files) {
  let html = `<div class="card"><h3>Benchmark result</h3>
    <div class="grid">
      <div><strong>Precision</strong><br>${Number(benchmark.precision || 0).toFixed(3)}</div>
      <div><strong>Recall</strong><br>${Number(benchmark.recall || 0).toFixed(3)}</div>
      <div><strong>F1</strong><br>${Number(benchmark.f1 || 0).toFixed(3)}</div>
      <div><strong>FPR</strong><br>${Number(benchmark.fpr || 0).toFixed(3)}</div>
    </div>
    <p>Total: ${benchmark.total ?? "-"} | Malicious: ${benchmark.malicious ?? "-"} | Benign: ${benchmark.benign ?? "-"}</p>
    <p>TP: ${benchmark.tp ?? "-"} | TN: ${benchmark.tn ?? "-"} | FP: ${benchmark.fp ?? "-"} | FN: ${benchmark.fn ?? "-"}</p>`;
  if (files && files.length) {
    html += `<p>Raw JSON: <a target="_blank" href="/api/files/${jobId}/${encodeURIComponent(files.find((f) => f.endsWith(".json")) || files[0])}">download/open</a></p>`;
  }
  return html + `</div>`;
}

async function runJob(kind, params, logId, resultId) {
  const logEl = document.getElementById(logId);
  const resultEl = document.getElementById(resultId);
  logEl.textContent = "Creating job...\n";
  resultEl.innerHTML = "";

  try {
    const created = await createJob(kind, params);
    logEl.textContent += `Job ${created.job_id}\nCommand: ${created.command.join(" ")}\n`;
    if (activeSource) activeSource.close();
    activeSource = new EventSource(`/api/jobs/${created.job_id}/stream`);
    activeSource.onmessage = (event) => {
      const data = JSON.parse(event.data);
      logEl.textContent += `${data.line}\n`;
      logEl.scrollTop = logEl.scrollHeight;
    };
    activeSource.addEventListener("done", async () => {
      activeSource.close();
      await renderResult(created.job_id, resultEl);
    });
  } catch (error) {
    logEl.textContent += `Error: ${error.message}\n`;
  }
}

function handleForm(formId, kind, paramsBuilder, logId, resultId) {
  const form = document.getElementById(formId);
  if (!form) return;
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    await runJob(kind, paramsBuilder(form), logId, resultId);
  });
}

async function uploadFile(fileInputId, pathInputId) {
  const fileInput = document.getElementById(fileInputId);
  if (!fileInput || !fileInput.files.length) return;
  const fd = new FormData();
  fd.append("file", fileInput.files[0]);
  const response = await fetch("/api/uploads", { method: "POST", body: fd });
  const data = await response.json();
  if (response.ok) {
    document.getElementById(pathInputId).value = data.path;
  } else {
    alert(data.detail || "Upload failed");
  }
}

async function loadAttacks() {
  const response = await fetch("/api/attacks");
  const attacks = await response.json();
  const select = document.getElementById("rt_attack");
  if (!select) return;
  select.innerHTML = "";
  Object.entries(attacks).forEach(([key, value], index) => {
    const option = document.createElement("option");
    option.value = key;
    option.textContent = `${key} - ${value.title}`;
    select.appendChild(option);
    if (key === "wallet-hook") select.selectedIndex = index;
  });
}

async function loadDashboard() {
  const health = await fetch("/api/health").then((r) => r.json());
  document.getElementById("health").textContent = JSON.stringify(health, null, 2);
  const inventory = await fetch("/api/inventory").then((r) => r.json());
  document.getElementById("inventory").innerHTML = inventory.modules
    .map((item) => `<li>${escapeHtml(item)}</li>`)
    .join("");
}

async function refreshJobs() {
  const jobs = await fetch("/api/jobs").then((r) => r.json());
  const table = document.getElementById("jobs-table") || document.getElementById("jobs-summary");
  if (!table) return;
  table.innerHTML = `
    <table>
      <thead><tr><th>Job</th><th>Kind</th><th>Status</th><th>Exit</th><th>Outputs</th></tr></thead>
      <tbody>${jobs
        .map(
          (job) =>
            `<tr><td>${job.id}</td><td>${job.kind}</td><td>${job.status}</td><td>${job.exit_code ?? "-"}</td>
            <td>${(job.result.files || []).map((f) => `<a target="_blank" href="/api/files/${job.id}/${encodeURIComponent(f)}">${escapeHtml(f)}</a>`).join(", ")}</td></tr>`
        )
        .join("")}</tbody>
    </table>`;
}

function showTab(name) {
  document.querySelectorAll(".tab").forEach((tab) => tab.classList.remove("active"));
  document.querySelectorAll(".nav-item").forEach((item) => item.classList.remove("active"));
  document.getElementById(name).classList.add("active");
  document.querySelector(`.nav-item[data-tab="${name}"]`).classList.add("active");
}

async function resultForJob(jobId) {
  // Kept for future polling fallbacks.
  return fetch(`/api/jobs/${jobId}`).then((r) => r.json());
}

function simpleRunner(kind, params, resultId) {
  const resultEl = document.getElementById(resultId);
  resultEl.innerHTML = `<pre class="logs" id="${resultId}-log"></pre><div id="${resultId}-inner"></div>`;
  runJob(kind, params, `${resultId}-log`, `${resultId}-inner`);
}

window.runRedTeam = async function () {
  const form = document.getElementById("form-redteam");
  const params = collectForm(form);
  if (params.base && params.base !== undefined) {
    // no-op
  }
  const base = document.getElementById("rt_base_path").value;
  params.file = base;
  if (params.single === "no") delete params.attack;
  const resultEl = document.getElementById("out-redteam");
  resultEl.innerHTML = `<pre class="logs" id="redteam-log"></pre><div id="redteam-inner"></div>`;
  if (params.attack === "") delete params.attack;
  return runJob("redteam", params, "redteam-log", "redteam-inner");
};

window.submitMonitor = async function (kind) {
  const form = document.getElementById("form-monitor");
  const params = collectForm(form);
  if (kind === "watch-list") {
    const resultEl = document.getElementById("out-monitor");
    resultEl.innerHTML = `<pre class="logs" id="monitor-log"></pre><div id="monitor-inner"></div>`;
    return runJob("watch-list", {}, "monitor-log", "monitor-inner");
  }
  const resultEl = document.getElementById("out-monitor");
  resultEl.innerHTML = `<pre class="logs" id="monitor-log"></pre><div id="monitor-inner"></div>`;
  return runJob(kind, params, "monitor-log", "monitor-inner");
};

window.runTrust = async function (kind) {
  const form = document.getElementById("form-trust");
  const params = collectForm(form);
  const resultEl = document.getElementById("out-trust");
  resultEl.innerHTML = `<pre class="logs" id="trust-log"></pre><div id="trust-inner"></div>`;
  return runJob(kind, params, "trust-log", "trust-inner");
};

window.runTrustAction = async function (kind) {
  const form = document.getElementById("form-trust");
  const params = collectForm(form);
  if (!params.change_id) {
    alert("Enter a change ID first.");
    return;
  }
  const resultEl = document.getElementById("out-trust");
  resultEl.innerHTML = `<pre class="logs" id="trust-log"></pre><div id="trust-inner"></div>`;
  return runJob(kind, params, "trust-log", "trust-inner");
};

async function runTamperMode() {
  const form = document.getElementById("form-redteam");
  const params = collectForm(form);
  const base = document.getElementById("rt_base_path").value;
  params.file = base;
  if (params.single === "no") delete params.attack;
  const resultEl = document.getElementById("out-redteam");
  resultEl.innerHTML = `<pre class="logs" id="redteam-log"></pre><div id="redteam-inner"></div>`;
  return runJob("tamper", params, "redteam-log", "redteam-inner");
}

document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll(".nav-item").forEach((item) => {
    item.addEventListener("click", () => showTab(item.dataset.tab));
  });

  handleForm("form-check", "check", collectForm, "out-check-log", "out-check-inner");
  const checkOut = document.getElementById("out-check");
  checkOut.innerHTML = `<pre class="logs" id="out-check-log"></pre><div id="out-check-inner"></div>`;

  handleForm("form-diff", "diff", collectForm, "out-diff-log", "out-diff-inner");
  document.getElementById("out-diff").innerHTML = `<pre class="logs" id="out-diff-log"></pre><div id="out-diff-inner"></div>`;

  document.getElementById("form-redteam").addEventListener("submit", async (event) => {
    event.preventDefault();
    await runTamperMode();
  });
  document.getElementById("out-redteam").innerHTML = `<pre class="logs" id="redteam-log"></pre><div id="redteam-inner"></div>`;

  handleForm("form-build", "verify-build", collectForm, "out-build-log", "out-build-inner");
  document.getElementById("out-build").innerHTML = `<pre class="logs" id="out-build-log"></pre><div id="out-build-inner"></div>`;

  handleForm("form-provenance", "verify-provenance", collectForm, "out-provenance-log", "out-provenance-inner");
  document.getElementById("out-provenance").innerHTML = `<pre class="logs" id="out-provenance-log"></pre><div id="out-provenance-inner"></div>`;

  handleForm("form-monitor-run", "watch-run", collectForm, "monitor-log", "monitor-inner");
  document.getElementById("out-monitor").innerHTML = `<pre class="logs" id="monitor-log"></pre><div id="monitor-inner"></div>`;

  handleForm("form-benchmark-run", "benchmark-run", collectForm, "out-benchmark-log", "out-benchmark-inner");
  document.getElementById("out-benchmark").innerHTML = `<pre class="logs" id="out-benchmark-log"></pre><div id="out-benchmark-inner"></div>`;

  handleForm("form-benchmark-compare", "benchmark-compare", collectForm, "out-benchmark-log", "out-benchmark-inner");

  document.getElementById("form-advanced").addEventListener("submit", async (event) => {
    event.preventDefault();
    const params = JSON.parse(document.querySelector("#form-advanced textarea").value || "{}");
    const kind = document.getElementById("adv-kind").value;
    const resultEl = document.getElementById("out-console");
    resultEl.innerHTML = `<pre class="logs" id="console-log"></pre><div id="console-inner"></div>`;
    await runJob(kind, params, "console-log", "console-inner");
  });

  document.getElementById("adv-kind").innerHTML = [
    "check", "diff", "tamper", "redteam", "verify-build", "verify-provenance",
    "watch-add", "watch-remove", "watch-list", "watch-run",
    "trust-show", "trust-history", "trust-changes", "trust-baseline",
    "trust-approve", "trust-reject", "trust-acknowledge",
    "benchmark-run", "benchmark-list", "benchmark-compare", "version",
  ].map((kind) => `<option value="${kind}">${kind}</option>`).join("");

  bindUpload("diff_file", "diff_artifact_path");
  bindUpload("diff_previous_file", "diff_previous_path");
  bindUpload("rt_file", "rt_base_path");

  loadAttacks();
  loadDashboard();
  refreshJobs();
});
