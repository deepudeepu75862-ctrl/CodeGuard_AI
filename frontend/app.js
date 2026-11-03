const $ = (id) => document.getElementById(id);
let latestId = null;
$("zip").addEventListener("change", () => {
  $("file-label").textContent = $("zip").files[0]?.name || "Choose a project ZIP";
});
$("scan-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const file = $("zip").files[0];
  if (!file) return;
  const button = $("scan-btn");
  button.disabled = true; button.textContent = "Scanning project…";
  $("message").textContent = "Inspecting source files. Please wait.";
  try {
    const body = new FormData(); body.append("file", file);
    const response = await fetch("/api/scan", {method:"POST", body});
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || "Scan failed");
    render(data);
    $("message").textContent = `Completed: ${data.files_scanned} files inspected.`;
  } catch (error) {
    $("message").textContent = error.message;
  } finally {
    button.disabled = false; button.innerHTML = 'Run security scan <span>→</span>';
  }
});
function render(data) {
  latestId = data.id;
  $("risk").textContent = data.risk_score;
  $("risk-label").textContent = `${data.risk_level} risk · weighted heuristic`;
  $("files").textContent = data.files_scanned;
  $("total").textContent = data.finding_count;
  $("urgent").textContent = (data.severity_counts.High || 0) + (data.severity_counts.Critical || 0);
  ["Critical","High","Medium","Low"].forEach(s => $(s.toLowerCase()).textContent = data.severity_counts[s] || 0);
  $("report").href = `/api/scans/${data.id}/report`; $("report").classList.remove("disabled");
  const list = $("finding-list"); list.classList.remove("empty");
  if (!data.findings.length) { list.className = "finding-list empty"; list.textContent = "No findings from the enabled checks. This does not guarantee the project is secure."; return; }
  list.innerHTML = data.findings.map(f => `<article class="finding"><div class="finding-top"><div><h3>${escapeHtml(f.title)}</h3><p>${escapeHtml(f.file)} · line ${f.line} · ${escapeHtml(f.id)}</p></div><span class="tag ${escapeHtml(f.severity)}">${escapeHtml(f.severity)}</span></div><p class="evidence">${escapeHtml(f.evidence || "No source excerpt")}</p><p><b>Recommendation:</b> ${escapeHtml(f.recommendation)}</p></article>`).join("");
}
function escapeHtml(value) { return String(value).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c])); }
