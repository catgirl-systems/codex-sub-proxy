(() => {
  "use strict";

  const MAX_RESPONSE_BYTES = 4 * 1024 * 1024;
  const csrf = document.querySelector('meta[name="csrf-token"]')?.content || "";
  const principalScopes = new Set((document.body.dataset.scopes || "").split(",").filter(Boolean));
  const contentScope = principalScopes.has("content");
  const state = { active: "overview", createdKey: null, createdKeyTimer: 0 };
  const root = document.getElementById("view");
  const status = document.getElementById("status");
  const nav = document.getElementById("navigation");

  function el(tag, text, attrs) {
    const node = document.createElement(tag);
    if (text !== undefined && text !== null) node.textContent = String(text);
    if (attrs) {
      for (const [name, value] of Object.entries(attrs)) {
        if (value === undefined || value === null) continue;
        if (name === "class") node.className = value;
        else if (name === "dataset") Object.assign(node.dataset, value);
        else node.setAttribute(name, String(value));
      }
    }
    return node;
  }

  function setStatus(message, error) {
    status.textContent = message || "";
    status.className = error ? "status error" : "status";
  }

  function clearCreatedKey() {
    state.createdKey = null;
    if (state.createdKeyTimer) window.clearTimeout(state.createdKeyTimer);
    state.createdKeyTimer = 0;
    const field = document.getElementById("created-key");
    if (field) field.remove();
  }

  function csrfFor(method) {
    return /^(GET|HEAD|OPTIONS|TRACE)$/i.test(method) ? "" : csrf;
  }

  async function readBounded(response) {
    const contentLength = Number(response.headers.get("content-length") || 0);
    if (Number.isFinite(contentLength) && contentLength > MAX_RESPONSE_BYTES) throw new Error("Response is too large.");
    const text = await response.text();
    if (new TextEncoder().encode(text).byteLength > MAX_RESPONSE_BYTES) throw new Error("Response is too large.");
    return text;
  }

  async function api(path, options) {
    const request = options ? { ...options } : {};
    const method = String(request.method || "GET").toUpperCase();
    if (!path.startsWith("/admin/")) throw new Error("Invalid admin path.");
    request.credentials = "same-origin";
    request.headers = new Headers(request.headers || {});
    request.headers.set("Accept", "application/json");
    const token = csrfFor(method);
    if (token) request.headers.set("X-CSRF-Token", token);
    const response = await fetch(path, request);
    const text = await readBounded(response);
    if (response.status === 204) return null;
    const type = response.headers.get("content-type") || "";
    if (!type.toLowerCase().includes("application/json")) throw new Error("The server returned an unexpected response.");
    let value;
    try { value = parseJSONValues(text); } catch (_) { throw new Error("The server returned invalid JSON."); }
    if (!response.ok) {
      const message = value && value.error && typeof value.error.message === "string" ? value.error.message : "Request failed.";
      throw new Error(message);
    }
    return value;
  }

  function parseJSONValues(text) {
    let index = 0;
    function skip() {
      while (index < text.length && /\s/.test(text[index])) index++;
    }
    function parseValue() {
      skip();
      const character = text[index];
      if (character === "{") {
        index++;
        const object = Object.create(null);
        skip();
        if (text[index] === "}") { index++; return object; }
        while (index < text.length) {
          skip();
          if (text[index] !== "\"") throw new Error("The server returned invalid JSON.");
          const key = parseString();
          skip();
          if (text[index++] !== ":") throw new Error("The server returned invalid JSON.");
          object[key] = parseValue();
          skip();
          if (text[index] === "}") { index++; return object; }
          if (text[index++] !== ",") throw new Error("The server returned invalid JSON.");
        }
      } else if (character === "[") {
        index++;
        const array = [];
        skip();
        if (text[index] === "]") { index++; return array; }
        while (index < text.length) {
          array.push(parseValue());
          skip();
          if (text[index] === "]") { index++; return array; }
          if (text[index++] !== ",") throw new Error("The server returned invalid JSON.");
        }
      } else if (character === "\"") {
        return parseString();
      } else if (text.startsWith("true", index)) {
        index += 4;
        return true;
      } else if (text.startsWith("false", index)) {
        index += 5;
        return false;
      } else if (text.startsWith("null", index)) {
        index += 4;
        return null;
      } else {
        const match = text.slice(index).match(/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/);
        if (!match) throw new Error("The server returned invalid JSON.");
        index += match[0].length;
        return match[0];
      }
      throw new Error("The server returned invalid JSON.");
    }
    function parseString() {
      const start = index;
      index++;
      while (index < text.length) {
        if (text[index] === "\\") index += 2;
        else if (text[index++] === "\"") return JSON.parse(text.slice(start, index));
      }
      throw new Error("The server returned invalid JSON.");
    }
    const value = parseValue();
    skip();
    if (index !== text.length) throw new Error("The server returned invalid JSON.");
    return value;
  }

  function formField(label, type, id, value) {
    const wrapper = el("div", undefined, { class: "field" });
    wrapper.append(el("label", label, { for: id }));
    const input = el(type === "select" ? "select" : "input", undefined, { id, name: id });
    if (type !== "select") input.type = type;
    if (value !== undefined) input.value = value;
    wrapper.append(input);
    return wrapper;
  }

  function table(headers, rows) {
    const wrap = el("div", undefined, { class: "table-wrap" });
    const tableNode = el("table");
    const head = el("thead");
    const headRow = el("tr");
    headers.forEach((header) => headRow.append(el("th", header, { scope: "col" })));
    head.append(headRow);
    tableNode.append(head);
    const body = el("tbody");
    if (!rows.length) {
      const row = el("tr");
      const cell = el("td", "No data.", { colspan: headers.length });
      row.append(cell);
      body.append(row);
    } else rows.forEach((values) => {
      const row = el("tr");
      values.forEach((value) => row.append(value instanceof Node ? value : el("td", value === null || value === undefined || value === "" ? "—" : value)));
      body.append(row);
    });
    tableNode.append(body);
    wrap.append(tableNode);
    return wrap;
  }

  function metric(label, value) {
    const dl = el("dl", undefined, { class: "card metric" });
    dl.append(el("dt", label));
    dl.append(el("dd", value === null || value === undefined ? "—" : value));
    return dl;
  }

  function isoValue(date) {
    return new Date(date).toISOString();
  }

  function dateControls() {
    const now = Date.now();
    const toolbar = el("form", undefined, { class: "toolbar" });
    const from = formField("From (UTC)", "datetime-local", "from");
    const to = formField("To (UTC)", "datetime-local", "to");
    from.querySelector("input").value = new Date(now - 24 * 60 * 60 * 1000).toISOString().slice(0, 16);
    to.querySelector("input").value = new Date(now).toISOString().slice(0, 16);
    const interval = formField("Interval", "select", "interval");
    const select = interval.querySelector("select");
    ["hour", "day", "month"].forEach((value) => select.append(el("option", value, { value })));
    select.value = "day";
    const submit = el("button", "Refresh", { class: "button primary", type: "submit" });
    toolbar.append(from, to, interval, submit);
    toolbar.addEventListener("submit", (event) => {
      event.preventDefault();
      loadOverview(from.querySelector("input").value, to.querySelector("input").value, select.value);
    });
    return toolbar;
  }

  function analyticsQuery(from, to, interval) {
    const fromDate = new Date(from);
    const toDate = new Date(to);
    if (!Number.isFinite(fromDate.getTime()) || !Number.isFinite(toDate.getTime()) || toDate <= fromDate) throw new Error("Choose a valid date range.");
    const query = new URLSearchParams({ from: isoValue(fromDate), to: isoValue(toDate) });
    if (interval) query.set("interval", interval);
    return query;
  }

  function appendRowsFromData(target, rows, mapper, headers) {
    target.append(table(headers, (rows || []).map(mapper)));
  }

  async function loadOverview(from, to, interval) {
    setStatus("Loading overview…");
    try {
      const rangeQuery = analyticsQuery(from, to);
      const costQuery = analyticsQuery(from, to, interval);
      const [overview, models, keys, errors, latency, quotas, costs] = await Promise.all([
        api(`/admin/v1/analytics/overview?${rangeQuery}`),
        api(`/admin/v1/analytics/models?${rangeQuery}`),
        api(`/admin/v1/analytics/keys?${rangeQuery}`),
        api(`/admin/v1/analytics/errors?${rangeQuery}`),
        api(`/admin/v1/analytics/latency?${rangeQuery}`),
        api(`/admin/v1/analytics/quotas?${rangeQuery}`),
        api(`/admin/v1/analytics/costs?${costQuery}`)
      ]);
      root.replaceChildren(dateControls());
      const cards = el("div", undefined, { class: "cards" });
      cards.append(
        metric("Requests", overview.requests?.count),
        metric("Input tokens", overview.usage?.input_tokens),
        metric("Output tokens", overview.usage?.output_tokens),
        metric("Images", overview.usage?.image_count),
        metric("Latency p95 (ms)", overview.latency?.p95_ms),
        metric("Quota-accounted cost", overview.costs?.quota_accounted_cost_microunits),
        metric("Estimated public cost", overview.costs?.estimated_public_cost_microunits),
        metric("Allocated subscription cost (provisional/final)", overview.costs?.allocated_subscription_cost_microunits)
      );
      root.append(cards);
      const sections = el("div", undefined, { class: "sections" });
      let section = el("section", undefined, { class: "card" });
      section.append(el("h2", "Requests"));
      appendRowsFromData(section, overview.states, (row) => [el("td", row.state), el("td", row.count)], ["State", "Count"]);
      sections.append(section);
      section = el("section", undefined, { class: "card" });
      section.append(el("h2", "Requested and resolved models"));
      appendRowsFromData(section, models?.data, (row) => [el("td", row.requested_model), el("td", row.resolved_model), el("td", row.request_count)], ["Requested model", "Resolved model", "Requests"]);
      sections.append(section);
      section = el("section", undefined, { class: "card" });
      section.append(el("h2", "Tokens and images"));
      appendRowsFromData(section, keys?.data, (row) => [el("td", row.api_key_id), el("td", row.request_count), el("td", row.total_tokens), el("td", row.image_count)], ["API key", "Requests", "Tokens", "Images"]);
      sections.append(section);
      section = el("section", undefined, { class: "card" });
      section.append(el("h2", "Errors"));
      appendRowsFromData(section, errors?.data, (row) => [el("td", row.error_class), el("td", row.error_code), el("td", row.request_count)], ["Class", "Code", "Requests"]);
      sections.append(section);
      section = el("section", undefined, { class: "card" });
      section.append(el("h2", "Latency and quota"));
      appendRowsFromData(section, [latency, quotas], (row) => [el("td", row === latency ? "Latency" : "Quota"), el("td", row.count ?? row.quota_accounted_requests), el("td", row.p95_ms ?? row.quota_accounted_cost_microunits)], ["Area", "Count", "Value"]);
      sections.append(section);
      section = el("section", undefined, { class: "card" });
      section.append(el("h2", "Cost intervals"));
      appendRowsFromData(section, costs?.data, (row) => [el("td", row.bucket), el("td", row.estimated_public_cost_microunits), el("td", row.allocated_subscription_cost_microunits), el("td", row.quota_accounted_cost_microunits), el("td", row.provisional)], ["Interval", "Estimated public", "Allocated subscription", "Quota accounted", "Provisional"]);
      sections.append(section);
      root.append(sections);
      setStatus("Overview loaded.");
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "Unable to load overview.", true);
    }
  }

  function actionButton(label, handler, disabled) {
    const button = el("button", label, { class: "button", type: "button" });
    button.disabled = Boolean(disabled);
    button.addEventListener("click", handler);
    return button;
  }

  function policyText(policy) {
    return JSON.stringify(policy || {}, null, 2);
  }

  function showCreatedKey(key) {
    clearCreatedKey();
    state.createdKey = key;
    const field = el("div", undefined, { class: "created-key", id: "created-key" });
    const label = el("label", "New key (shown once)", { for: "new-key-value" });
    const input = el("input", undefined, { id: "new-key-value", readonly: "readonly", autocomplete: "off" });
    input.value = key;
    const copy = actionButton("Copy", async () => {
      try { await navigator.clipboard.writeText(input.value); setStatus("Key copied. Clear it when done."); } catch (_) { setStatus("Copy failed. Use the visible field.", true); }
    });
    const clear = actionButton("Clear", clearCreatedKey);
    field.append(label, input, el("div", undefined, { class: "actions" }));
    field.lastChild.append(copy, clear);
    document.getElementById("keys-view")?.append(field);
    state.createdKeyTimer = window.setTimeout(clearCreatedKey, 60 * 1000);
  }

  async function loadKeys() {
    setStatus("Loading API keys…");
    try {
      const value = await api("/admin/v1/api-keys?limit=100");
      root.replaceChildren();
      const section = el("section", undefined, { class: "card", id: "keys-view" });
      section.append(el("h2", "API keys"));
      const issue = el("form", undefined, { class: "toolbar" });
      issue.append(formField("Name", "text", "issue-name"), formField("Owner", "text", "issue-owner"));
      const endpoints = formField("Allowed endpoints (comma separated)", "text", "issue-endpoints", "/v1/responses");
      const models = formField("Allowed models (comma separated)", "text", "issue-models");
      issue.append(endpoints, models);
      const policy = formField("Full policy JSON", "text", "issue-policy");
      const policyInput = policy.querySelector("input");
      policyInput.value = JSON.stringify({ allowed_endpoints: ["/v1/responses"], allowed_models: [], max_concurrent_requests: 1, rolling_request_count: 0, rolling_request_window: 0, period_request_limit: 0, period_token_limit: 0, period_image_limit: 0, period_cost_microunit_limit: 0, period_duration: 0, token_reservation_default: 0, token_reservation_ceiling: 0, image_reservation_default: 0, image_reservation_ceiling: 0, cost_microunit_reservation_default: 0, cost_microunit_reservation_ceiling: 0 });
      issue.append(policy);
      const submit = el("button", "Issue key", { class: "button primary", type: "submit" });
      issue.append(submit);
      issue.addEventListener("submit", async (event) => {
        event.preventDefault();
        submit.disabled = true;
        try {
          const parsed = JSON.parse(policyInput.value);
          parsed.allowed_endpoints = endpoints.querySelector("input").value.split(",").map((item) => item.trim()).filter(Boolean);
          parsed.allowed_models = models.querySelector("input").value.split(",").map((item) => item.trim()).filter(Boolean);
          const created = await api("/admin/v1/api-keys", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name: issue.querySelector("#issue-name").value, owner: issue.querySelector("#issue-owner").value, policy: parsed }) });
          setStatus("API key created.");
          await loadKeys();
          if (created?.key) showCreatedKey(created.key);
        } catch (error) { setStatus(error instanceof Error ? error.message : "Unable to issue key.", true); }
        finally { submit.disabled = false; }
      });
      section.append(issue);
      const rows = (value?.data || []).map((record) => {
        const actions = el("td");
        actions.append(actionButton("Detail", () => loadKeyDetail(record.id)), actionButton("Edit", () => editKey(record)), actionButton("Revoke", () => revokeKey(record.id, record.name)));
        return [el("td", record.name), el("td", record.owner), el("td", record.prefix), el("td", record.disabled ? "Disabled" : "Active"), actions];
      });
      section.append(table(["Name", "Owner", "Prefix", "State", "Actions"], rows));
      root.append(section);
      setStatus("API keys loaded.");
    } catch (error) { setStatus(error instanceof Error ? error.message : "Unable to load API keys.", true); }
  }

  async function loadKeyDetail(id) {
    try {
      const record = await api(`/admin/v1/api-keys/${encodeURIComponent(id)}`);
      const section = el("section", undefined, { class: "card" });
      section.append(el("h2", "API key detail"), el("p", `Name: ${record.name}`), el("p", `Owner: ${record.owner}`), el("pre", policyText(record.policy), { class: "output" }));
      const back = actionButton("Back to keys", loadKeys);
      section.append(back);
      root.replaceChildren(section);
      setStatus("API key detail loaded.");
    } catch (error) { setStatus(error instanceof Error ? error.message : "Unable to load API key detail.", true); }
  }

  async function editKey(record) {
    const section = el("section", undefined, { class: "card" });
    section.append(el("h2", "Edit API key policy"));
    const name = formField("Name", "text", "edit-name", record.name);
    const owner = formField("Owner", "text", "edit-owner", record.owner);
    const policy = formField("Full policy JSON", "text", "edit-policy", policyText(record.policy));
    const disabled = formField("Disabled", "select", "edit-disabled");
    disabled.querySelector("select").append(el("option", "No", { value: "false" }), el("option", "Yes", { value: "true" }));
    disabled.querySelector("select").value = record.disabled ? "true" : "false";
    const submit = el("button", "Save policy", { class: "button primary", type: "button" });
    submit.addEventListener("click", async () => {
      submit.disabled = true;
      try {
        const body = { name: name.querySelector("input").value, owner: owner.querySelector("input").value, disabled: disabled.querySelector("select").value === "true", policy: JSON.parse(policy.querySelector("input").value) };
        await api(`/admin/v1/api-keys/${encodeURIComponent(record.id)}`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
        await loadKeys();
      } catch (error) { setStatus(error instanceof Error ? error.message : "Unable to edit key.", true); submit.disabled = false; }
    });
    section.append(el("div", undefined, { class: "dialog-row" }), submit);
    section.querySelector(".dialog-row").append(name, owner, policy, disabled);
    root.replaceChildren(section);
  }

  async function revokeKey(id, name) {
    if (!window.confirm(`Revoke API key ${name || id}?`)) return;
    try { await api(`/admin/v1/api-keys/${encodeURIComponent(id)}`, { method: "DELETE" }); setStatus("API key revoked."); await loadKeys(); }
    catch (error) { setStatus(error instanceof Error ? error.message : "Unable to revoke key.", true); }
  }

  function lifecycleQuery() {
    const to = new Date();
    const from = new Date(to.getTime() - 24 * 60 * 60 * 1000);
    return new URLSearchParams({ from: from.toISOString(), to: to.toISOString(), limit: "50" });
  }

  async function loadLifecycle(kind) {
    setStatus(`Loading ${kind}…`);
    try {
      const value = await api(`/admin/v1/${kind}?${lifecycleQuery()}`);
      const section = el("section", undefined, { class: "card" });
      section.append(el("h2", kind === "requests" ? "Requests" : "Conversations"));
      const rows = (value?.data || []).map((record) => {
        const actions = el("td");
        actions.append(actionButton("Detail", () => loadLifecycleDetail(kind, record.id)));
        if (contentScope) actions.append(actionButton("Export", () => exportLifecycle(kind, record.id)));
        actions.append(actionButton("Delete", () => deleteLifecycle(kind, record.id)));
        return [el("td", record.id), el("td", record.state), el("td", record.created_at || record.accepted_at), el("td", record.request_count ?? record.endpoint), actions];
      });
      section.append(table(["ID", "State", "Created", "Count/endpoint", "Actions"], rows));
      root.replaceChildren(section);
      setStatus(`${kind} loaded.`);
    } catch (error) { setStatus(error instanceof Error ? error.message : `Unable to load ${kind}.`, true); }
  }

  async function loadLifecycleDetail(kind, id) {
    try {
      const value = await api(`/admin/v1/${kind}/${encodeURIComponent(id)}`);
      const section = el("section", undefined, { class: "card" });
      section.append(el("h2", `${kind} detail`), el("pre", JSON.stringify(value, null, 2), { class: "output" }), actionButton("Back", () => loadLifecycle(kind)));
      if (contentScope) section.append(actionButton("Export", () => exportLifecycle(kind, id)));
      root.replaceChildren(section);
      setStatus("Detail loaded.");
    } catch (error) { setStatus(error instanceof Error ? error.message : "Unable to load detail.", true); }
  }

  async function exportLifecycle(kind, id) {
    try {
      const response = await fetch(`/admin/v1/${kind}/${encodeURIComponent(id)}/export`, { credentials: "same-origin", headers: { Accept: "application/json" } });
      const text = await readBounded(response);
      if (!response.ok || !(response.headers.get("content-type") || "").toLowerCase().includes("application/json")) throw new Error("Export failed.");
      const blob = new Blob([text], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const link = el("a", "Download export", { href: url, download: `${kind}-${id}.json` });
      link.click();
      URL.revokeObjectURL(url);
      setStatus("Export downloaded.");
    } catch (error) { setStatus(error instanceof Error ? error.message : "Unable to export content.", true); }
  }

  async function deleteLifecycle(kind, id) {
    if (!window.confirm(`Delete ${kind.slice(0, -1)} ${id}?`)) return;
    try { await api(`/admin/v1/${kind}/${encodeURIComponent(id)}`, { method: "DELETE" }); setStatus("Deleted."); await loadLifecycle(kind); }
    catch (error) { setStatus(error instanceof Error ? error.message : "Unable to delete.", true); }
  }

  function buildNav() {
    nav.replaceChildren();
    [["overview", "Overview", () => loadOverview(new Date(Date.now() - 86400000), new Date(), "day")], ["keys", "API keys", loadKeys], ["requests", "Requests", () => loadLifecycle("requests")], ["conversations", "Conversations", () => loadLifecycle("conversations")]].forEach(([id, label, handler]) => {
      const button = el("button", label, { type: "button", "aria-current": id === state.active ? "page" : "false" });
      button.addEventListener("click", () => { clearCreatedKey(); state.active = id; buildNav(); handler(); });
      nav.append(button);
    });
    const logout = el("form", undefined, { action: "/admin/logout", method: "post" });
    const csrfField = el("input", undefined, { name: "csrf_token", value: csrf });
    csrfField.type = "hidden";
    const logoutButton = el("button", "Log out", { type: "submit" });
    logout.append(csrfField, logoutButton);
    nav.append(logout);
  }

  document.getElementById("logout-form")?.addEventListener("submit", () => clearCreatedKey());
  buildNav();
  loadOverview(new Date(Date.now() - 86400000), new Date(), "day");
})();
