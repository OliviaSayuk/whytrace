const state = {
  caseId: "night-shift",
  events: [],
  report: null,
  detections: [],
  selectedFinding: null,
  selectedEvent: null,
};

const $ = (id) => document.getElementById(id);

async function boot() {
  const health = await fetch("/api/health").then((r) => r.json());
  $("llm-status").textContent = health.llm
    ? `model · ${health.llm.name}`
    : "model · rules-only (no key needed)";

  const payload = await fetch(`/api/cases/${state.caseId}`).then((r) => r.json());
  $("case-title").textContent = payload.case.title;
  $("case-question").textContent = payload.case.question;
  state.events = payload.events;
  renderCounts(payload.source_counts);
  renderTimeline();
}

function renderCounts(counts) {
  $("source-counts").innerHTML = Object.entries(counts)
    .map(([k, v]) => `<div><dt>${k}</dt><dd>${v}</dd></div>`)
    .join("");
}

function renderTimeline(cited = new Set()) {
  const hitIds = new Set(state.detections.flatMap((d) => d.event_ids || []));
  $("timeline").innerHTML = state.events
    .filter((e) => e.source !== "identity")
    .map((e) => {
      const cls = [
        "evt",
        hitIds.has(e.id) ? "hit" : "",
        cited.has(e.id) ? "cited" : "",
        state.selectedEvent === e.id ? "active" : "",
      ].join(" ");
      const summary = e.command_line || e.object || e.src_ip || e.action;
      return `<div class="${cls}" data-id="${e.id}">
        <span class="ts">${e.ts.replace("T", " ").replace("Z", "")}</span>
        <span class="src">${e.source}</span>
        <span>${escapeHtml(summary)}</span>
      </div>`;
    })
    .join("");
  $("timeline").querySelectorAll(".evt").forEach((el) => {
    el.addEventListener("click", () => selectEvent(el.dataset.id));
  });
}

function selectEvent(id) {
  state.selectedEvent = id;
  const event = state.events.find((e) => e.id === id);
  const related = (state.report?.findings || []).filter((f) =>
    f.evidence.some((ev) => ev.event_id === id)
  );
  $("detail").classList.remove("empty");
  $("detail").innerHTML = `
    <p class="mitre">${event.id} · ${event.source} · ${event.action}</p>
    <p>${escapeHtml(event.command_line || event.object || event.action)}</p>
    <p>${[event.user, event.host, event.src_ip, event.dst_ip].filter(Boolean).join(" · ")}</p>
    ${
      related.length
        ? `<p><strong>Why this may be suspicious</strong></p>${related
            .map((f) => `<p>${escapeHtml(f.why)}</p>`)
            .join("")}`
        : `<p class="mitre">No finding currently cites this event. It may be baseline activity.</p>`
    }
  `;
  const cited = new Set(
    (state.selectedFinding
      ? state.report?.findings.find((f) => f.id === state.selectedFinding)?.evidence
      : []
    )?.map((e) => e.event_id) || []
  );
  renderTimeline(cited);
}

function selectFinding(id) {
  state.selectedFinding = id;
  const finding = state.report.findings.find((f) => f.id === id);
  $("detail").classList.remove("empty");
  $("detail").innerHTML = `
    <p class="sev ${finding.severity}">${finding.severity}</p>
    <h3>${escapeHtml(finding.title)}</h3>
    <p><strong>Hypothesis.</strong> ${escapeHtml(finding.hypothesis)}</p>
    <p><strong>Why.</strong> ${escapeHtml(finding.why)}</p>
    <p class="mitre">${finding.mitre.join(" · ")}</p>
    <div class="chips">
      ${finding.evidence
        .map(
          (ev) =>
            `<button type="button" data-eid="${ev.event_id}" title="${escapeHtml(ev.note)}">${ev.event_id}</button>`
        )
        .join("")}
    </div>
    <p><strong>Next.</strong> ${finding.next_steps.map(escapeHtml).join(" ")}</p>
  `;
  $("detail").querySelectorAll("button[data-eid]").forEach((btn) => {
    btn.addEventListener("click", () => {
      selectEvent(btn.dataset.eid);
      const row = document.querySelector(`.evt[data-id="${btn.dataset.eid}"]`);
      row?.scrollIntoView({ block: "center" });
    });
  });
  document.querySelectorAll(".findings li").forEach((li) => {
    li.classList.toggle("active", li.dataset.id === id);
  });
  renderTimeline(new Set(finding.evidence.map((e) => e.event_id)));
}

function renderReport(report) {
  state.report = report;
  if (!document.querySelector(".verdict")) {
    const v = document.createElement("div");
    v.className = "verdict";
    v.id = "verdict";
    $("stage").after(v);
  }
  $("verdict").innerHTML = `<strong>${report.confidence} confidence.</strong> ${escapeHtml(report.verdict)}<p>${escapeHtml(report.executive_summary)}</p>`;
  $("findings").innerHTML = report.findings
    .map(
      (f) => `<li data-id="${f.id}">
        <span class="sev ${f.severity}">${f.severity}</span>
        <h3>${escapeHtml(f.title)}</h3>
        <p>${f.evidence.length} cited events</p>
      </li>`
    )
    .join("");
  $("findings")
    .querySelectorAll("li")
    .forEach((li) => li.addEventListener("click", () => selectFinding(li.dataset.id)));
  $("narrative").innerHTML = report.narrative.map((n) => `<li>${escapeHtml(n)}</li>`).join("");
  $("unanswered").innerHTML = report.unanswered.map((n) => `<li>${escapeHtml(n)}</li>`).join("");
  if (report.findings[0]) selectFinding(report.findings[0].id);
}

async function runInvestigation() {
  $("run").disabled = true;
  $("stage").hidden = false;
  $("stage").textContent = "starting…";
  const res = await fetch(`/api/cases/${state.caseId}/investigate`, { method: "POST" });
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buf = "";
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buf += decoder.decode(value, { stream: true });
    const lines = buf.split("\n");
    buf = lines.pop();
    for (const line of lines) {
      if (!line.trim()) continue;
      const chunk = JSON.parse(line);
      $("stage").textContent = `${chunk.stage} · ${chunk.message}`;
      if (chunk.detections) state.detections = chunk.detections;
      if (chunk.stage === "detect") renderTimeline();
      if (chunk.report) renderReport(chunk.report);
    }
  }
  $("run").disabled = false;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

$("run").addEventListener("click", runInvestigation);
boot();
