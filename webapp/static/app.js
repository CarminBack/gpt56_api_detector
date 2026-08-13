const state = {
  preset: "low",
  currentId: null,
  logOffset: 0,
  startedAt: null,
  pollTimer: null,
  clockTimer: null,
  toastTimer: null,
};

const el = (id) => document.getElementById(id);

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
  });
  const contentType = response.headers.get("content-type") || "";
  const payload = contentType.includes("application/json") ? await response.json() : null;
  if (!response.ok) {
    throw new Error(payload?.detail || `请求失败：HTTP ${response.status}`);
  }
  return payload;
}

function showToast(message, isError = false) {
  const toast = el("toast");
  toast.textContent = message;
  toast.classList.toggle("is-error", isError);
  toast.classList.add("is-visible");
  window.clearTimeout(state.toastTimer);
  state.toastTimer = window.setTimeout(() => toast.classList.remove("is-visible"), 4500);
}

function setPreset(preset) {
  state.preset = preset;
  document.querySelectorAll("[data-preset]").forEach((button) => {
    const active = button.dataset.preset === preset;
    button.classList.toggle("is-active", active);
    button.setAttribute("aria-checked", String(active));
  });
}

function toggleSecret(inputId, button) {
  const input = el(inputId);
  const visible = input.type === "text";
  input.type = visible ? "password" : "text";
  button.querySelector("use").setAttribute("href", visible ? "#icon-eye" : "#icon-eye-off");
}

async function loadModels(kind, button) {
  const baseUrl = el(`${kind}-url`).value.trim();
  const apiKey = el(`${kind}-key`).value;
  if (!baseUrl || !apiKey) {
    showToast("请先填写 Base URL 和 API Key", true);
    return;
  }
  button.disabled = true;
  try {
    const result = await api("/api/models", {
      method: "POST",
      body: JSON.stringify({ base_url: baseUrl, api_key: apiKey }),
    });
    const select = el(`${kind}-model-select`);
    select.replaceChildren();
    const placeholder = document.createElement("option");
    placeholder.value = "";
    placeholder.textContent = result.models.length ? "选择已读取的模型" : "未读取到模型";
    select.append(placeholder);
    result.models.forEach((model) => {
      const option = document.createElement("option");
      option.value = model;
      option.textContent = model;
      select.append(option);
    });
    select.disabled = result.models.length === 0;
    const currentModel = el(`${kind}-request-model`).value.trim();
    select.value = result.models.includes(currentModel) ? currentModel : "";
    if (!select.disabled) select.focus();
    showToast(`读取到 ${result.models.length} 个模型`);
  } catch (error) {
    showToast(error.message, true);
  } finally {
    button.disabled = false;
  }
}

function jobPayload() {
  const payload = {
    preset: state.preset,
    retention_enabled: el("retention-enabled").checked,
    candidate: {
      base_url: el("candidate-url").value.trim(),
      claimed_model: el("candidate-claimed-model").value,
      request_model: el("candidate-request-model").value.trim(),
      api_key: el("candidate-key").value,
    },
  };
  return payload;
}

async function startJob(event) {
  event.preventDefault();
  const form = el("job-form");
  if (!form.reportValidity()) return;

  const button = el("start-button");
  button.disabled = true;
  try {
    const job = await api("/api/jobs", {
      method: "POST",
      body: JSON.stringify(jobPayload()),
    });
    selectJob(job.id, true);
    showToast("检测任务已启动");
  } catch (error) {
    showToast(error.message, true);
  } finally {
    button.disabled = false;
  }
}

function statusTone(job) {
  if (["failed", "stopped"].includes(job.status)) return "danger";
  if (["queued", "running", "stopping"].includes(job.status)) return "neutral";
  const status = job.summary?.combined_summary?.status || job.summary?.combined_verdict || "";
  if (/possible_non_gpt|mismatch/.test(status)) return "danger";
  if (/juice_pass_fingerprint_strong/.test(status)) return "success";
  return "warning";
}

function formatConfidence(value) {
  return { high: "高", medium: "中", low: "低", insufficient: "不足" }[value] || "—";
}

function formatStatus(value) {
  return {
    queued: "排队中",
    running: "检测中",
    stopping: "停止中",
    stopped: "已停止",
    completed: "已完成",
    failed: "失败",
  }[value] || value;
}

function renderJob(job) {
  el("empty-run").classList.add("is-hidden");
  el("run-content").classList.remove("is-hidden");
  const summary = job.summary?.combined_summary;
  const juice = job.summary?.juice_summary;
  const fingerprint = job.summary?.fingerprint_summary;
  const network = job.summary?.network_summary || {};
  const tone = statusTone(job);
  const band = el("verdict-band");
  band.className = `verdict-band tone-${tone}`;

  el("run-status").textContent = formatStatus(job.status);
  el("verdict-title").textContent = summary?.title_cn || (job.error ? "任务执行失败" : "检测正在运行");
  el("verdict-detail").textContent = summary?.explanation_cn || job.error || "检测器正在收集样本，请保持页面开启。";
  el("verdict-pass").textContent = summary?.passed_cn || (job.status === "failed" ? "失败" : "进行中");
  el("metric-model").textContent = fingerprint?.fingerprint_model || juice?.claimed_model || "—";
  el("metric-confidence").textContent = fingerprint?.fingerprint_status === "strong_match" ? "强指向" : (juice?.state || "—");
  el("metric-network").textContent = network.logical_tasks == null ? "—" : `${network.successful || 0} 成功 / ${network.final_errors || 0} 错误`;

  const running = ["queued", "running", "stopping"].includes(job.status);
  el("stop-button").disabled = !["queued", "running"].includes(job.status);
  el("start-button").disabled = running;
  setReportLinks(job);
  if (job.started_at) {
    state.startedAt = new Date(job.started_at);
    updateElapsed(job.finished_at ? new Date(job.finished_at) : null);
  }
}

function setReportLinks(job) {
  const html = el("html-report");
  const json = el("json-report");
  const retention = el("retention-download");
  [html, json].forEach((item) => item.classList.toggle("is-disabled", !job.has_report));
  html.href = job.has_report ? `/api/jobs/${job.id}/report.html` : "#";
  json.href = job.has_report ? `/api/jobs/${job.id}/report.json` : "#";
  retention.classList.toggle("is-disabled", !job.has_retention);
  retention.href = job.has_retention ? `/api/jobs/${job.id}/retention.zip` : "#";
}

async function loadVersion() {
  try {
    const result = await api("/api/version");
    el("app-version").textContent = `v${result.version}`;
  } catch {
    el("app-version").textContent = "v—";
  }
}

function updateElapsed(finishedAt = null) {
  if (!state.startedAt) {
    el("metric-time").textContent = "—";
    return;
  }
  const end = finishedAt || new Date();
  const seconds = Math.max(0, Math.floor((end - state.startedAt) / 1000));
  const hours = String(Math.floor(seconds / 3600)).padStart(2, "0");
  const minutes = String(Math.floor((seconds % 3600) / 60)).padStart(2, "0");
  const rest = String(seconds % 60).padStart(2, "0");
  el("metric-time").textContent = `${hours}:${minutes}:${rest}`;
}

async function pollCurrent() {
  if (!state.currentId) return;
  try {
    const [job, logs] = await Promise.all([
      api(`/api/jobs/${state.currentId}`),
      api(`/api/jobs/${state.currentId}/logs?offset=${state.logOffset}`),
    ]);
    renderJob(job);
    appendLogs(logs.lines, logs.next_offset);
    if (["queued", "running", "stopping"].includes(job.status)) {
      state.pollTimer = window.setTimeout(pollCurrent, 1000);
    } else {
      window.clearInterval(state.clockTimer);
      state.clockTimer = null;
      await refreshHistory();
    }
  } catch (error) {
    showToast(error.message, true);
    state.pollTimer = window.setTimeout(pollCurrent, 3000);
  }
}

function appendLogs(lines, nextOffset) {
  const output = el("log-output");
  if (state.logOffset === 0) output.textContent = "";
  if (lines.length) {
    const atBottom = output.scrollHeight - output.scrollTop - output.clientHeight < 48;
    output.textContent += `${lines.join("\n")}\n`;
    if (atBottom) output.scrollTop = output.scrollHeight;
  }
  if (!lines.length && nextOffset === 0) {
    output.textContent = "此任务没有可用的实时日志记录。";
  }
  state.logOffset = nextOffset;
  el("log-count").textContent = `${nextOffset} 行`;
}

function selectJob(jobId, active = false) {
  window.clearTimeout(state.pollTimer);
  window.clearInterval(state.clockTimer);
  state.currentId = jobId;
  state.logOffset = 0;
  state.startedAt = null;
  el("log-output").textContent = "正在加载…";
  pollCurrent();
  state.clockTimer = window.setInterval(() => updateElapsed(), 1000);
  if (active && window.innerWidth < 721) {
    el("run-title").scrollIntoView({ behavior: "smooth", block: "start" });
  }
}

function historyTone(job) {
  const tone = statusTone(job);
  return tone === "neutral" ? "warning" : tone;
}

function renderHistory(jobs) {
  const list = el("history-list");
  list.replaceChildren();
  if (!jobs.length) {
    const empty = document.createElement("p");
    empty.className = "history-empty";
    empty.textContent = "暂无历史报告";
    list.append(empty);
    return;
  }
  jobs.forEach((job) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "history-item";
    button.addEventListener("click", () => selectJob(job.id));

    const main = document.createElement("span");
    main.className = "history-main";
    const title = document.createElement("span");
    title.className = "history-title-row";
    const model = document.createElement("strong");
    const claimedModel = job.config.candidate_claimed_model || job.config.candidate_model;
    const requestModel = job.config.candidate_request_model || claimedModel;
    model.textContent = requestModel && requestModel !== claimedModel
      ? `${claimedModel} → ${requestModel}`
      : (claimedModel || "未知模型");
    const mode = document.createElement("span");
    mode.className = "history-mode";
    mode.textContent = {low: "低档", medium: "中档", high: "高档"}[job.config.preset] || "旧版";
    title.append(model, mode);

    const endpoints = document.createElement("span");
    endpoints.className = "history-endpoints";
    endpoints.append(historyEndpoint(
      "待测",
      job.config.candidate_base_url,
      job.config.candidate_api_key_hint,
    ));
    if (job.config.trusted_base_url) {
      endpoints.append(historyEndpoint(
        "参照",
        job.config.trusted_base_url,
        job.config.trusted_api_key_hint,
      ));
    }
    main.append(title, endpoints);

    const result = document.createElement("span");
    result.className = "history-result";
    const verdict = document.createElement("span");
    verdict.className = `history-verdict ${historyTone(job)}`;
    verdict.textContent = job.summary?.combined_summary?.title_cn || formatStatus(job.status);
    const time = document.createElement("time");
    time.dateTime = job.created_at;
    time.textContent = new Intl.DateTimeFormat("zh-CN", {
      month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false,
    }).format(new Date(job.created_at));
    result.append(verdict, time);

    button.append(main, result);
    list.append(button);
  });
}

function historyEndpoint(labelText, urlText, keyHint) {
  const endpoint = document.createElement("span");
  endpoint.className = "history-endpoint";
  const label = document.createElement("span");
  label.className = "history-endpoint-label";
  label.textContent = labelText;
  const url = document.createElement("span");
  url.className = "history-url";
  url.textContent = urlText || "—";
  const key = document.createElement("code");
  key.className = "history-key";
  key.textContent = `Key ${keyHint || "—"}`;
  endpoint.append(label, url, key);
  return endpoint;
}

async function refreshHistory() {
  try {
    const result = await api("/api/jobs");
    renderHistory(result.jobs);
    if (result.active_id && !state.currentId) selectJob(result.active_id);
  } catch (error) {
    showToast(error.message, true);
  }
}

async function stopJob() {
  if (!state.currentId) return;
  el("stop-button").disabled = true;
  try {
    await api(`/api/jobs/${state.currentId}/stop`, { method: "POST" });
    showToast("正在停止任务");
  } catch (error) {
    showToast(error.message, true);
  }
}

document.querySelectorAll("[data-preset]").forEach((button) => {
  button.addEventListener("click", () => setPreset(button.dataset.preset));
});

document.querySelectorAll("[data-toggle-secret]").forEach((button) => {
  button.addEventListener("click", () => toggleSecret(button.dataset.toggleSecret, button));
});

document.querySelectorAll("[data-load-models]").forEach((button) => {
  button.addEventListener("click", () => loadModels(button.dataset.loadModels, button));
});

document.querySelectorAll("[data-model-select]").forEach((select) => {
  select.addEventListener("change", () => {
    if (select.value) el(`${select.dataset.modelSelect}-request-model`).value = select.value;
  });
});

el("candidate-claimed-model").addEventListener("change", (event) => {
  el("candidate-request-model").value = event.target.value;
  el("candidate-model-select").value = "";
});

el("job-form").addEventListener("submit", startJob);
el("stop-button").addEventListener("click", stopJob);
el("refresh-history").addEventListener("click", refreshHistory);
setPreset("low");
loadVersion();
refreshHistory();
