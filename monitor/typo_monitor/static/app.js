"use strict";

const runProgress = document.querySelector("[data-run-progress]");

if (runProgress) {
  const stageLabels = {
    queued: "Waiting to start", discovery: "Finding subdomains",
    generation: "Generating typo candidates", dns: "Checking DNS",
    pipeline: "Checking DNS and capturing websites",
    parking: "Checking parking signals", websites: "Checking website responses",
    screenshots: "Capturing websites", comparison: "Comparing images",
    publishing: "Saving results", completed: "Completed",
    partial: "Completed with gaps", cancelled: "Stopped", failed: "Failed"
  };
  const statusLabels = {
    running: "Scan in progress", completed: "Completed", partial: "Completed with gaps",
    cancelled: "Stopped", failed: "Failed"
  };
  const select = (selector) => runProgress.querySelector(selector);
  const text = (value) => value == null ? "" : typeof value === "object" ? JSON.stringify(value) : String(value);
  const label = (value) => Object.hasOwn(stageLabels, value) ? stageLabels[value] : text(value).replaceAll("_", " ").replace(/^./, (letter) => letter.toUpperCase());
  const timestamp = (value) => {
    if (!value) return "—";
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? text(value) : date.toISOString().replace("T", " · ").slice(0, 21) + " UTC";
  };
  const tools = new Map(Array.from(select("[data-tool-outputs]").children, (node) => [node.dataset.outputName, node]));
  let stopped = runProgress.dataset.runStatus !== "running";
  let inFlight = false;
  let pollTimer;

  // Preserve a reader's position. Follow new lines only when already at the bottom.
  function preserveScroll(element, update) {
    const top = element.scrollTop;
    const atBottom = element.clientHeight > 0 && element.scrollHeight - top - element.clientHeight <= 24;
    update();
    element.scrollTop = atBottom ? element.scrollHeight : top;
  }

  function updateActivity(entries) {
    const log = select("[data-activity-log]");
    const messages = Array.isArray(entries) ? entries.filter((entry) => entry && typeof entry === "object") : [];
    preserveScroll(log, () => {
      log.replaceChildren(...messages.map((entry) => {
        const row = document.createElement("li");
        const time = document.createElement("time");
        time.dateTime = text(entry.time);
        time.textContent = timestamp(entry.time);
        const level = document.createElement("span");
        level.className = "activity-level";
        level.textContent = text(entry.level);
        const message = document.createElement("span");
        message.textContent = text(entry.message);
        row.append(time, level, message);
        if (entry.stage) {
          const stage = document.createElement("small");
          stage.textContent = label(entry.stage);
          row.append(stage);
        }
        return row;
      }));
    });
    log.hidden = messages.length === 0;
    select("[data-activity-empty]").hidden = messages.length > 0;
  }

  function updateOutputs(outputs) {
    const present = new Set();
    for (const output of Array.isArray(outputs) ? outputs : []) {
      if (!output || typeof output.name !== "string") continue;
      present.add(output.name);
      let tool = tools.get(output.name);
      if (!tool) {
        tool = document.createElement("details");
        tool.className = "tool-output";
        tool.dataset.outputName = output.name;
        const summary = document.createElement("summary");
        const name = document.createElement("strong");
        name.textContent = output.name;
        const truncation = document.createElement("span");
        truncation.dataset.outputTruncated = "";
        summary.append(name, truncation);
        const body = document.createElement("pre");
        body.tabIndex = 0;
        tool.append(summary, body);
        select("[data-tool-outputs]").append(tool);
        tools.set(output.name, tool);
      }
      tool.querySelector("[data-output-truncated]").textContent = output.truncated ? "Latest output · truncated" : "Recorded output";
      let description = tool.querySelector("[data-output-description]");
      if (!description) {
        description = document.createElement("p");
        description.className = "source-detail";
        description.dataset.outputDescription = "";
        tool.querySelector("summary").after(description);
      }
      description.textContent = text(output.description);
      description.hidden = !output.description;
      const body = tool.querySelector("pre");
      preserveScroll(body, () => { body.textContent = text(output.text); });
    }
    for (const [name, tool] of tools) {
      if (!present.has(name)) {
        tool.remove();
        tools.delete(name);
      }
    }
    select("[data-tool-output-empty]").hidden = present.size > 0;
  }

  function updateProgress(snapshot, status) {
    const progress = snapshot && typeof snapshot === "object" ? snapshot : {};
    const terminal = status !== "running";
    select("[data-progress-stage]").textContent = terminal ? (statusLabels[status] || "Finished") : progress.available ? (label(progress.stage) || "Progress recorded") : "Detailed progress unavailable";
    select("[data-progress-message]").textContent = !progress.available ? "Detailed progress was not recorded for this scan by this version." : terminal ? "This scan has ended. Counts and output below are the last recorded activity." : (text(progress.message) || "No activity message recorded.");
    const count = select("[data-progress-count]");
    count.hidden = !progress.available || progress.current == null;
    select("[data-progress-count-label]").textContent = terminal ? "Last recorded count" : "Current stage count";
    select("[data-progress-count-value]").textContent = text(progress.current) + (progress.total == null ? "" : " / " + text(progress.total));
    const recorded = select("[data-progress-recorded]");
    recorded.hidden = !terminal || !progress.available;
    recorded.textContent = "Last recorded stage: " + (label(progress.stage) || "Not recorded") + "." + (progress.message ? " " + text(progress.message) : "");
    const metrics = progress.metrics && typeof progress.metrics === "object" && !Array.isArray(progress.metrics) ? Object.entries(progress.metrics) : [];
    const metricsNode = select("[data-progress-metrics]");
    metricsNode.hidden = metrics.length === 0;
    metricsNode.replaceChildren(...metrics.map(([name, value]) => {
      const item = document.createElement("div");
      const title = document.createElement("span");
      title.textContent = label(name);
      const result = document.createElement("strong");
      result.textContent = text(value);
      item.append(title, result);
      return item;
    }));
    select("[data-progress-updated]").textContent = timestamp(progress.updated_at);
    updateActivity(progress.logs);
  }

  function finish(status) {
    stopped = true;
    window.clearTimeout(pollTimer);
    document.body.dataset.refresh = "false";
    runProgress.dataset.runStatus = status;
    select(".progress-stage .context-label").textContent = "SCAN STATUS";
    select("[data-progress-poll-status]").textContent = "Scan ended. Live updates have stopped.";
    select("[data-progress-finished]").hidden = false;
    select("[data-progress-finished-message]").textContent = (statusLabels[status] || "Scan finished") + ". Open the saved scan results to load the final findings and source health.";
    document.querySelector("[data-run-heading]").textContent = status === "cancelled" ? "Scan stopped." : "Scan details";
    const badge = document.querySelector("[data-run-status] .badge");
    badge.textContent = statusLabels[status] || "Finished";
    badge.className = "badge " + (Object.hasOwn(statusLabels, status) ? status : "partial");
    for (const element of document.querySelectorAll("[data-live-stop], [data-running-notice]")) element.hidden = true;
    const pendingSource = document.querySelector(".source-grid .simple-empty");
    if (pendingSource) pendingSource.textContent = "Open the saved scan results for final source health.";
    const pendingChanges = document.querySelector(".history-panel .small-empty");
    if (pendingChanges) {
      pendingChanges.querySelector("h3").textContent = "The scan has ended.";
      pendingChanges.querySelector("p").textContent = "Open the saved scan results for the final comparison details.";
    }
    // Keep every open output panel and its scroll position intact.
  }

  function schedule() {
    if (!stopped) pollTimer = window.setTimeout(poll, 4000);
  }

  async function poll() {
    if (stopped || inFlight) return;
    if (document.hidden) { schedule(); return; }
    inFlight = true;
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), 10000);
    try {
      const response = await fetch(runProgress.dataset.progressUrl, {cache: "no-store", credentials: "same-origin", headers: {Accept: "application/json"}, signal: controller.signal});
      if (!response.ok) throw new Error("Progress request failed");
      const data = await response.json();
      updateProgress(data.progress, data.status);
      updateOutputs(data.outputs);
      if (data.status !== "running") finish(data.status);
      else select("[data-progress-poll-status]").textContent = "Live updates every four seconds, including while output is open.";
    } catch (error) {
      select("[data-progress-poll-status]").textContent = "Live updates interrupted. Retrying; the last recorded output remains below.";
    } finally {
      window.clearTimeout(timeout);
      inFlight = false;
      schedule();
    }
  }

  document.addEventListener("visibilitychange", () => {
    if (!document.hidden && !stopped) {
      window.clearTimeout(pollTimer);
      poll();
    }
  });
  schedule();
} else {
  // Preserve the existing refresh behavior outside the scan activity view.
  if (document.body.dataset.refresh === "true" && !document.hidden) {
    window.setTimeout(() => {
      if (!document.hidden && !document.querySelector("details[open]")) window.location.reload();
    }, 5000);
  }
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden && document.body.dataset.refresh === "true") window.location.reload();
  });
}

// Preset selection changes the form only; it never starts Docker or contacts Tor.
for (const stage of document.querySelectorAll("[data-proxy-stage]")) {
  const source = stage.querySelector("[data-proxy-source]");
  if (!source) continue;
  const custom = stage.querySelector("[data-proxy-custom]");
  const help = stage.querySelector("[data-proxy-tor-help]");
  const input = custom.querySelector("input");
  const readOnly = input.disabled;
  const update = () => {
    const tor = source.value === "tor";
    custom.hidden = tor;
    input.disabled = readOnly || tor;
    help.hidden = !tor;
  };
  source.addEventListener("change", update);
  update();
}
