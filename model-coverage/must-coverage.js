(function () {
  "use strict";

  const dataEl = document.getElementById("mustcov-data");
  if (!dataEl) return;

  const data = JSON.parse(dataEl.textContent || "{}");
  const statements = data.statements || [];
  const classDefinitions = data.classDefinitions || {};
  const classOrder = data.classOrder || Object.keys(classDefinitions);
  const classOptionsHtml = classOrder
    .map((className) => `<option value="${escapeHtml(className)}">${escapeHtml(classDefinitions[className] || className)}</option>`)
    .join("");
  const byId = new Map(statements.map((item) => [item.id, item]));
  const spans = Array.from(document.querySelectorAll(".mustcov"));
  const spansById = new Map();

  for (const span of spans) {
    const ids = (span.dataset.mustcovIds || "").split(",").filter(Boolean);
    for (const id of ids) {
      if (!spansById.has(id)) spansById.set(id, []);
      spansById.get(id).push(span);
    }
  }

  const panel = document.createElement("aside");
  panel.id = "mustcov-panel";
  panel.innerHTML = `
    <div class="mustcov-panel-head">
      <div>
        <h2>MUST Coverage</h2>
        <div class="mustcov-muted">RFC ${escapeHtml(data.rfc || "")} · semantic class filter</div>
      </div>
      <button class="mustcov-close" type="button" aria-label="Close coverage panel">x</button>
    </div>
    <div class="mustcov-summary"></div>
    <div class="mustcov-controls">
      <label class="mustcov-search">Search
        <input type="search" data-mustcov-filter="search" placeholder="ID, statement, source line, Maude ref">
      </label>
      <label>Coverage
        <select data-mustcov-filter="coverage">
          <option value="">All</option>
          <option value="covered">Covered</option>
          <option value="uncovered">Uncovered</option>
          <option value="excluded">Excluded</option>
        </select>
      </label>
      <label>Keyword
        <select data-mustcov-filter="keyword">
          <option value="">All</option>
          <option value="MUST">MUST</option>
          <option value="MUST NOT">MUST NOT</option>
        </select>
      </label>
      <label>Class
        <select data-mustcov-filter="class">
          <option value="">All</option>
          ${classOptionsHtml}
        </select>
      </label>
    </div>
    <div class="mustcov-detail is-empty">Select a highlighted MUST/MUST NOT line or a row below.</div>
    <div class="mustcov-list"></div>
  `;
  document.body.appendChild(panel);

  const summaryEl = panel.querySelector(".mustcov-summary");
  const detailEl = panel.querySelector(".mustcov-detail");
  const listEl = panel.querySelector(".mustcov-list");
  const searchEl = panel.querySelector('[data-mustcov-filter="search"]');
  const coverageEl = panel.querySelector('[data-mustcov-filter="coverage"]');
  const keywordEl = panel.querySelector('[data-mustcov-filter="keyword"]');
  const classEl = panel.querySelector('[data-mustcov-filter="class"]');
  const closeEl = panel.querySelector(".mustcov-close");

  let selectedId = null;
  let filtered = statements.slice();

  renderSummary(filtered);
  renderList();
  bindEvents();
  openInitialHash();

  function renderSummary(items) {
    const included = items.filter((item) => item.extractionStatus !== "excluded");
    const counts = countCoverage(included);
    summaryEl.innerHTML = `
      <div><strong>${items.length}</strong><span>candidates</span></div>
      <div><strong>${included.length}</strong><span>included</span></div>
      <div><strong>${counts.covered || 0}</strong><span>covered</span></div>
      <div><strong>${counts.uncovered || 0}</strong><span>uncovered</span></div>
      <div><strong>${countExcluded(items)}</strong><span>excluded</span></div>
    `;
  }

  function renderList() {
    listEl.innerHTML = "";
    for (const item of filtered) {
      const button = document.createElement("button");
      button.type = "button";
      button.dataset.mustcovRow = item.id;
      button.className = item.id === selectedId ? "is-selected" : "";
      button.innerHTML = `<code>${escapeHtml(item.id)}</code><span>${escapeHtml(item.keyword)} · ${escapeHtml(classLabel(item))} · ${escapeHtml(sectionLabel(item))}</span>`;
      listEl.appendChild(button);
    }
  }

  function bindEvents() {
    for (const span of spans) {
      span.addEventListener("click", () => {
        const id = firstId(span);
        if (id) selectStatement(id, true);
      });
      span.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          const id = firstId(span);
          if (id) selectStatement(id, true);
        }
      });
    }

    listEl.addEventListener("click", (event) => {
      const button = event.target.closest("[data-mustcov-row]");
      if (button) selectStatement(button.dataset.mustcovRow, true);
    });

    for (const input of [searchEl, coverageEl, keywordEl, classEl]) {
      input.addEventListener("input", applyFilters);
      input.addEventListener("change", applyFilters);
    }

    closeEl.addEventListener("click", () => {
      panel.style.display = "none";
    });
  }

  function openInitialHash() {
    const hash = decodeURIComponent(window.location.hash.replace(/^#must-/, ""));
    if (hash && byId.has(hash)) selectStatement(hash, true);
  }

  function selectStatement(id, scroll) {
    const item = byId.get(id);
    if (!item) return;
    selectedId = id;
    panel.style.display = "";

    for (const span of spans) span.classList.remove("is-active");
    const selectedSpans = spansById.get(id) || [];
    for (const span of selectedSpans) span.classList.add("is-active");

    detailEl.className = "mustcov-detail";
    detailEl.innerHTML = renderDetail(item);
    renderList();

    if (scroll && selectedSpans[0]) {
      selectedSpans[0].scrollIntoView({ block: "center", behavior: "smooth" });
      history.replaceState(null, "", `#must-${id}`);
    }
  }

  function renderDetail(item) {
    const refs = (item.sourceRefs || []).map((ref) => `${ref.file}:${ref.start}${ref.end !== ref.start ? `-${ref.end}` : ""}`).join(", ");
    const maude = (item.maudeRefs || []).map((ref) => `<code>${escapeHtml(ref)}</code>`).join("<br>") || "None";
    const oldRows = (item.oldCoverageRows || []).map((id) => `<code>${escapeHtml(id)}</code>`).join(", ") || "None";
    return `
      <h3>${escapeHtml(item.id)}</h3>
      <div class="mustcov-badges">
        <span class="mustcov-badge coverage-${escapeHtml(item.coverage)}">${escapeHtml(item.coverage)}</span>
        <span class="mustcov-badge">${escapeHtml(item.status)}</span>
        <span class="mustcov-badge">${escapeHtml(item.keyword)}</span>
        <span class="mustcov-badge">${escapeHtml(classLabel(item))}</span>
      </div>
      <dl>
        <dt>Class</dt><dd>${escapeHtml(classLabel(item))}</dd>
        <dt>Section</dt><dd>${escapeHtml(sectionLabel(item))}</dd>
        <dt>Source lines</dt><dd>${escapeHtml(refs)}</dd>
        <dt>Statement</dt><dd>${escapeHtml(item.text)}</dd>
        <dt>Reason</dt><dd><code>${escapeHtml(item.reasonCode)}</code></dd>
        <dt>Extraction</dt><dd>${escapeHtml(item.extractionStatus)}${item.exclusionReason ? ` · <code>${escapeHtml(item.exclusionReason)}</code>` : ""}</dd>
        <dt>Old rows</dt><dd>${oldRows}</dd>
        <dt>Maude refs</dt><dd>${maude}</dd>
      </dl>
    `;
  }

  function applyFilters() {
    const query = searchEl.value.trim().toLowerCase();
    const coverage = coverageEl.value;
    const keyword = keywordEl.value;
    const className = classEl.value;

    filtered = statements.filter((item) => {
      if (coverage && item.coverage !== coverage) return false;
      if (keyword && item.keyword !== keyword) return false;
      if (className && item.class !== className) return false;
      if (query) {
        const refs = (item.sourceRefs || []).map((ref) => `${ref.file}:${ref.start}${ref.end !== ref.start ? `-${ref.end}` : ""}`);
        const haystack = [
          item.id,
          item.keyword,
          item.class,
          classLabel(item),
          item.text,
          sectionLabel(item),
          item.reasonCode,
          ...refs,
          ...(item.maudeRefs || []),
          ...(item.oldCoverageRows || []),
        ].join(" ").toLowerCase();
        if (!haystack.includes(query)) return false;
      }
      return true;
    });

    const visibleIds = new Set(filtered.map((item) => item.id));
    for (const span of spans) {
      const ids = (span.dataset.mustcovIds || "").split(",").filter(Boolean);
      const visible = ids.some((id) => visibleIds.has(id));
      span.classList.toggle("is-hidden", !visible);
    }

    renderSummary(filtered);
    renderList();
  }

  function firstId(span) {
    return (span.dataset.mustcovIds || "").split(",").filter(Boolean)[0];
  }

  function countCoverage(items) {
    return items.reduce((acc, item) => {
      acc[item.coverage] = (acc[item.coverage] || 0) + 1;
      return acc;
    }, {});
  }

  function countExcluded(items) {
    return items.filter((item) => item.extractionStatus === "excluded").length;
  }

  function sectionLabel(item) {
    const section = item.section || {};
    return `${section.id || ""} ${section.title || ""}`.trim();
  }

  function classLabel(item) {
    return item.classLabel || classDefinitions[item.class] || item.class || "";
  }

  function escapeHtml(value) {
    return String(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }
})();
