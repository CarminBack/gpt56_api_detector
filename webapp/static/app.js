const state = {
  mode: "juice",
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

function setMode(mode) {
  state.mode = mode;
  document.querySelectorAll("[data-mode]").forEach((button) => {
    const active = button.dataset.mode === mode;
    button.classList.toggle("is-active", active);
    button.setAttribute("aria-checked", String(active));
  });
  const cot = mode === "cot";
  el("trusted-fields").classList.toggle("is-hidden", !cot);
  el("trials").classList.toggle("is-hidden", !cot);
  el("trials-label").classList.toggle("is-hidden", !cot);
  ["trusted-url", "trusted-model", "trusted-key"].forEach((id) => {
    el(id).required = cot;
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
    const datalist = el(`${kind}-models`);
    datalist.replaceChildren();
    result.models.forEach((model) => {
      const option = document.createElement("option");
      option.value = model;
      datalist.append(option);
    });
    showToast(`读取到 ${result.models.length} 个模型`);
  } catch (error) {
    showToast(error.message, true);
  } finally {
    button.disabled = false;
  }
}

function jobPayload() {
  const payload = {
    mode: state.mode,
    candidate: {
      base_url: el("candidate-url").value.trim(),
      model: el("candidate-model").value.trim(),
      api_key: el("candidate-key").value,
    },
    workers: Number(el("workers").value),
    trials: Number(el("trials").value),
    juice_repeats: Number(el("juice-repeats").value),
  };
  if (state.mode === "cot") {
    payload.trusted = {
      base_url: el("trusted-url").value.trim(),
      model: el("trusted-model").value.trim(),
      api_key: el("trusted-key").value,
    };
  }
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
    el("candidate-key").value = "";
    el("trusted-key").value = "";
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
  if (/mismatch|mixed|invalid|conflict|rewrite|not_compatible/.test(status)) return "danger";
  if (/consistent|compatible_and/.test(status)) return "success";
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
  const network = job.summary?.network_summary || summary?.network_summary;
  const tone = statusTone(job);
  const band = el("verdict-band");
  band.className = `verdict-band tone-${tone}`;

  el("run-status").textContent = formatStatus(job.status);
  el("verdict-title").textContent = summary?.title_cn || (job.error ? "任务执行失败" : "检测正在运行");
  el("verdict-detail").textContent = summary?.explanation_cn || job.error || "检测器正在收集样本，请保持页面开启。";
  el("verdict-pass").textContent = summary?.passed_cn || (job.status === "failed" ? "失败" : "进行中");
  el("metric-model").textContent = juice?.likely_model_cn || "—";
  el("metric-confidence").textContent = formatConfidence(juice?.confidence || summary?.juice_confidence);
  el("metric-network").textContent = network?.title_cn || "—";

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
  [html, json].forEach((item) => item.classList.toggle("is-disabled", !job.has_report));
  html.href = job.has_report ? `/api/jobs/${job.id}/report.html` : "#";
  json.href = job.has_report ? `/api/jobs/${job.id}/report.json` : "#";
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

    const model = document.createElement("strong");
    model.textContent = job.config.candidate_model || "未知模型";
    const mode = document.createElement("span");
    mode.className = "history-mode";
    mode.textContent = job.config.mode === "juice" || job.config.mode === "juice_only" ? "Juice" : "COT 综合";
    const verdict = document.createElement("span");
    verdict.className = `history-verdict ${historyTone(job)}`;
    verdict.textContent = job.summary?.combined_summary?.title_cn || formatStatus(job.status);
    const time = document.createElement("time");
    time.dateTime = job.created_at;
    time.textContent = new Intl.DateTimeFormat("zh-CN", {
      month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false,
    }).format(new Date(job.created_at));

    button.append(model, mode, verdict, time);
    list.append(button);
  });
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

document.querySelectorAll("[data-mode]").forEach((button) => {
  button.addEventListener("click", () => setMode(button.dataset.mode));
});

document.querySelectorAll("[data-toggle-secret]").forEach((button) => {
  button.addEventListener("click", () => toggleSecret(button.dataset.toggleSecret, button));
});

document.querySelectorAll("[data-load-models]").forEach((button) => {
  button.addEventListener("click", () => loadModels(button.dataset.loadModels, button));
});

el("workers").addEventListener("input", (event) => {
  el("workers-value").value = event.target.value;
  el("workers-value").textContent = event.target.value;
});
el("job-form").addEventListener("submit", startJob);
el("stop-button").addEventListener("click", stopJob);
el("refresh-history").addEventListener("click", refreshHistory);

setMode("juice");
refreshHistory();
