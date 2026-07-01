(function () {
  "use strict";

  const dataEl = document.getElementById("rfcov-data");
  if (!dataEl) return;

  const data = JSON.parse(dataEl.textContent || "{}");
  const rows = data.rows || [];
  const rowById = new Map(rows.map((row) => [row.id, row]));
  const spans = Array.from(document.querySelectorAll(".rfcov"));
  const spansById = new Map();

  for (const span of spans) {
    const ids = (span.dataset.rfcovIds || "").split(",").filter(Boolean);
    for (const id of ids) {
      if (!spansById.has(id)) spansById.set(id, []);
      spansById.get(id).push(span);
    }
  }

  const panel = document.createElement("aside");
  panel.id = "rfcov-panel";
  panel.innerHTML = `
    <div class="rfcov-panel-head">
      <div>
        <h2>RFC-check Coverage</h2>
        <div class="rfcov-muted">RFC ${escapeHtml(data.rfc || "")}</div>
      </div>
      <button class="rfcov-close" type="button" aria-label="Close coverage panel">x</button>
    </div>
    <div class="rfcov-summary"></div>
    <div class="rfcov-controls">
      <label class="rfcov-search">Search
        <input type="search" data-rfcov-filter="search" placeholder="ID, section, source line, Maude ref">
      </label>
      <label>Status
        <select data-rfcov-filter="status">
          <option value="">All</option>
          <option value="Implemented">Implemented</option>
          <option value="Partial">Partial</option>
          <option value="Not implemented">Not implemented</option>
        </select>
      </label>
      <label>Class
        <select data-rfcov-filter="class">
          <option value="">All</option>
          <option value="syntax">Syntax</option>
          <option value="state">State</option>
          <option value="extension">Extension</option>
          <option value="negotiation">Negotiation</option>
          <option value="auth">Auth</option>
          <option value="ctx">Context</option>
          <option value="sess">Session</option>
        </select>
      </label>
    </div>
    <div class="rfcov-detail is-empty">Select a highlighted RFC line or a row below.</div>
    <div class="rfcov-list"></div>
  `;
  document.body.appendChild(panel);

  const summaryEl = panel.querySelector(".rfcov-summary");
  const detailEl = panel.querySelector(".rfcov-detail");
  const listEl = panel.querySelector(".rfcov-list");
  const searchEl = panel.querySelector('[data-rfcov-filter="search"]');
  const statusEl = panel.querySelector('[data-rfcov-filter="status"]');
  const classEl = panel.querySelector('[data-rfcov-filter="class"]');
  const closeEl = panel.querySelector(".rfcov-close");

  let selectedId = null;
  let filteredRows = rows.slice();

  renderSummary();
  renderList();
  bindEvents();
  openInitialHash();

  function renderSummary() {
    const counts = countStatuses(rows);
    summaryEl.innerHTML = `
      <div><strong>${rows.length}</strong><span>items</span></div>
      <div><strong>${counts.Implemented || 0}</strong><span>implemented</span></div>
      <div><strong>${counts.Partial || 0}</strong><span>partial</span></div>
      <div><strong>${counts["Not implemented"] || 0}</strong><span>not impl.</span></div>
    `;
  }

  function renderList() {
    listEl.innerHTML = "";
    for (const row of filteredRows) {
      const button = document.createElement("button");
      button.type = "button";
      button.dataset.rfcovRow = row.id;
      button.className = row.id === selectedId ? "is-selected" : "";
      button.innerHTML = `<code>${escapeHtml(row.id)}</code><span>${escapeHtml(row.status)} · ${escapeHtml(row.rfcSection)}</span>`;
      listEl.appendChild(button);
    }
  }

  function bindEvents() {
    for (const span of spans) {
      span.addEventListener("click", () => {
        const id = firstId(span);
        if (id) selectRow(id, true);
      });
      span.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          const id = firstId(span);
          if (id) selectRow(id, true);
        }
      });
    }

    listEl.addEventListener("click", (event) => {
      const button = event.target.closest("[data-rfcov-row]");
      if (button) selectRow(button.dataset.rfcovRow, true);
    });

    for (const input of [searchEl, statusEl, classEl]) {
      input.addEventListener("input", applyFilters);
      input.addEventListener("change", applyFilters);
    }

    closeEl.addEventListener("click", () => {
      panel.style.display = "none";
    });
  }

  function openInitialHash() {
    const hash = decodeURIComponent(window.location.hash.replace(/^#cov-/, ""));
    if (hash && rowById.has(hash)) selectRow(hash, true);
  }

  function selectRow(id, scroll) {
    const row = rowById.get(id);
    if (!row) return;
    selectedId = id;
    panel.style.display = "";

    for (const span of spans) span.classList.remove("is-active");
    const selectedSpans = spansById.get(id) || [];
    for (const span of selectedSpans) span.classList.add("is-active");

    detailEl.className = "rfcov-detail";
    detailEl.innerHTML = renderDetail(row);
    renderList();

    if (scroll && selectedSpans[0]) {
      selectedSpans[0].scrollIntoView({ block: "center", behavior: "smooth" });
      history.replaceState(null, "", `#cov-${id}`);
    }
  }

  function renderDetail(row) {
    const refs = (row.sourceRefs || []).map((ref) => `${ref.file}:${ref.start}${ref.end !== ref.start ? `-${ref.end}` : ""}`).join(", ");
    const maude = maudeRefs(row).map((ref) => `<code>${escapeHtml(ref)}</code>`).join("<br>") || "None";
    return `
      <h3>${escapeHtml(row.id)}</h3>
      <div class="rfcov-badges">
        <span class="rfcov-badge status-${escapeHtml(row.statusSlug)}">${escapeHtml(row.status)}</span>
        <span class="rfcov-badge">${escapeHtml(row.classLabel)}</span>
      </div>
      <dl>
        <dt>RFC section</dt><dd>${escapeHtml(row.rfcSection)}</dd>
        <dt>Source lines</dt><dd>${escapeHtml(refs)}</dd>
        <dt>Maude refs</dt><dd class="rfcov-maude-refs">${maude}</dd>
      </dl>
    `;
  }

  function applyFilters() {
    const query = searchEl.value.trim().toLowerCase();
    const status = statusEl.value;
    const cls = classEl.value;

    filteredRows = rows.filter((row) => {
      if (status && row.status !== status) return false;
      if (cls && row.class !== cls) return false;
      if (query) {
        const refs = (row.sourceRefs || []).map((ref) => `${ref.file}:${ref.start}${ref.end !== ref.start ? `-${ref.end}` : ""}`);
        const haystack = [
          row.id,
          row.rfcSection,
          row.classLabel,
          row.status,
          ...refs,
          ...maudeRefs(row),
        ].join(" ").toLowerCase();
        if (!haystack.includes(query)) return false;
      }
      return true;
    });

    const visibleIds = new Set(filteredRows.map((row) => row.id));
    for (const span of spans) {
      const ids = (span.dataset.rfcovIds || "").split(",").filter(Boolean);
      const visible = ids.some((id) => visibleIds.has(id));
      span.classList.toggle("is-hidden", !visible);
    }

    renderList();
  }

  function firstId(span) {
    return (span.dataset.rfcovIds || "").split(",").filter(Boolean)[0];
  }

  function countStatuses(items) {
    return items.reduce((acc, row) => {
      acc[row.status] = (acc[row.status] || 0) + 1;
      return acc;
    }, {});
  }

  function maudeRefs(row) {
    return row.maudeRefs || [];
  }

  function escapeHtml(value) {
    return String(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }
})();
