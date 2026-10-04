"use strict";

const singleTab = document.querySelector("#single-tab");
const batchTab = document.querySelector("#batch-tab");
const singlePanel = document.querySelector("#single-panel");
const batchPanel = document.querySelector("#batch-panel");
const resultArea = document.querySelector("#result-area");
const batchResultArea = document.querySelector("#batch-result-area");

function setMode(mode) {
  const single = mode === "single";
  singleTab.classList.toggle("active", single);
  batchTab.classList.toggle("active", !single);
  singleTab.setAttribute("aria-selected", String(single));
  batchTab.setAttribute("aria-selected", String(!single));
  singlePanel.classList.toggle("hidden", !single);
  batchPanel.classList.toggle("hidden", single);
  singlePanel.setAttribute("aria-hidden", String(!single));
  batchPanel.setAttribute("aria-hidden", String(single));
  resultArea.classList.add("hidden");
  batchResultArea.classList.add("hidden");
}

singleTab.addEventListener("click", () => setMode("single"));
batchTab.addEventListener("click", () => setMode("batch"));

function setError(element, message) {
  element.textContent = message;
}

async function postJson(path, payload) {
  const response = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || "The scan could not be completed.");
  return data;
}

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function renderSingle(result) {
  resultArea.replaceChildren();
  resultArea.classList.remove("hidden");
  const content = element("div", "result-content");
  const scoreCard = element("div", "score-card");
  scoreCard.classList.add(result.level);
  scoreCard.append(element("span", "score-caption", "URL pattern score"));
  const ring = element("div", "score-ring");
  const number = element("span", "score-number");
  number.append(document.createTextNode(String(result.score)));
  number.append(element("small", "", " / 100"));
  ring.append(number);
  scoreCard.append(ring);
  scoreCard.append(element("span", `risk-badge ${result.level}`, result.level + " pattern risk"));
  scoreCard.append(element("p", "score-summary", result.summary));

  const details = element("div", "result-details");
  details.append(element("span", "result-label", "DESTINATION HOST"));
  details.append(element("p", "result-host", result.hostname));
  details.append(renderModelAssessment(result));
  const heading = element("div", "findings-heading");
  heading.append(element("h3", "", "What stood out"));
  heading.append(element("span", "result-label", `${result.findings.length} SIGNAL${result.findings.length === 1 ? "" : "S"}`));
  details.append(heading);
  if (result.findings.length) {
    for (const finding of result.findings) {
      const row = element("div", "finding");
      row.append(element("strong", "", finding.title));
      row.append(element("p", "", finding.detail));
      row.append(element("span", "finding-points", `+${finding.points}`));
      details.append(row);
    }
  } else {
    details.append(element("p", "no-findings", "No listed URL-pattern signals were found. Be cautious with unexpected links anyway."));
  }
  details.append(element("p", "result-notice", result.notice));
  const actions = element("div", "result-actions");
  const copyButton = element("button", "secondary-button", "Copy scan summary");
  copyButton.type = "button";
  copyButton.addEventListener("click", async () => {
    const text = [
      `LinkLens pattern score: ${result.score}/100 (${result.level})`,
      `Host: ${result.hostname}`,
      result.summary,
      ...result.findings.map((finding) => `- ${finding.title} (+${finding.points}): ${finding.detail}`),
      result.model?.status === "available"
        ? `ML model score: ${result.model.score}/100 (${result.model.label}; uncalibrated).`
        : `ML model: ${result.model?.message || "unavailable"}`,
      result.notice,
    ].join("\n");
    try {
      await navigator.clipboard.writeText(text);
      copyButton.textContent = "Copied";
    } catch {
      copyButton.textContent = "Copy unavailable";
    }
  });
  actions.append(copyButton);
  const inspectButton = element("button", "secondary-button", "Check another");
  inspectButton.type = "button";
  inspectButton.addEventListener("click", () => document.querySelector("#url-input").focus());
  actions.append(inspectButton);
  details.append(actions);
  content.append(scoreCard, details);
  resultArea.append(content);
}

function renderModelAssessment(result) {
  const panel = element("section", "model-panel");
  const header = element("div", "model-panel-header");
  const title = element("div");
  title.append(element("span", "result-label", "SECOND OPINION"));
  title.append(element("h3", "", "Trained URL model"));
  header.append(title);

  if (!result.model || result.model.status !== "available") {
    const message = result.model?.message || "Model assessment was not returned.";
    panel.append(header, element("p", "model-unavailable", `Model unavailable: ${message}`));
    return panel;
  }

  const model = result.model;
  header.append(element("span", `risk-badge ${model.score >= 50 ? "high" : "lower"}`, model.label));
  panel.append(header);

  const scoreLine = element("p", "model-score-line");
  scoreLine.append(element("strong", "", `Model pattern score: ${model.score}/100`));
  scoreLine.append(
    element(
      "span",
      "",
      `${model.training_samples.toLocaleString()} training URLs · uncalibrated score, not a probability`,
    ),
  );
  panel.append(scoreLine);

  const heuristicFlags = result.score >= 25;
  const modelFlags = model.score >= 50;
  let alignment;
  let alignmentClass;
  if (heuristicFlags && modelFlags) {
    alignment = "Both checks flag potential risk. Avoid entering sensitive information.";
    alignmentClass = "aligned-risk";
  } else if (!heuristicFlags && !modelFlags) {
    alignment = "Neither check raised a strong flag. This still does not establish that the site is safe.";
    alignmentClass = "aligned-lower";
  } else if (heuristicFlags) {
    alignment = "The checks disagree: URL heuristics found warning signs, while the model score is lower. Treat the link cautiously.";
    alignmentClass = "disagreement";
  } else {
    alignment = "The checks disagree: the model flags a phishing-like pattern, though URL heuristics found fewer warning signs. Treat the link cautiously.";
    alignmentClass = "disagreement";
  }
  panel.append(element("p", `model-alignment ${alignmentClass}`, alignment));
  return panel;
}

const scanButton = document.querySelector("#scan-button");
const urlInput = document.querySelector("#url-input");
const inputError = document.querySelector("#input-error");

async function scanSingle() {
  setError(inputError, "");
  scanButton.disabled = true;
  scanButton.querySelector("span").textContent = "Checking…";
  try {
    const result = await postJson("/api/analyze", { url: urlInput.value });
    renderSingle(result);
    resultArea.scrollIntoView({ behavior: "smooth", block: "nearest" });
  } catch (error) {
    setError(inputError, error.message);
    resultArea.classList.add("hidden");
  } finally {
    scanButton.disabled = false;
    scanButton.querySelector("span").textContent = "Scan link";
  }
}

scanButton.addEventListener("click", scanSingle);
urlInput.addEventListener("keydown", (event) => {
  if (event.key === "Enter") scanSingle();
});

function downloadCsv(results) {
  const quote = (value) => `"${String(value ?? "").replaceAll('"', '""')}"`;
  const rows = [["row", "url", "hostname", "score", "risk_level", "summary", "findings"]];
  for (const result of results) {
    rows.push([
      result.row,
      result.url,
      result.hostname || "",
      result.score ?? "",
      result.level || "",
      result.summary || result.error || "",
      (result.findings || []).map((finding) => finding.title).join("; "),
    ]);
  }
  const csv = rows.map((row) => row.map(quote).join(",")).join("\r\n");
  const link = document.createElement("a");
  link.href = URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8" }));
  link.download = "linklens-results.csv";
  link.click();
  URL.revokeObjectURL(link.href);
}

function renderBatch(results) {
  batchResultArea.replaceChildren();
  batchResultArea.classList.remove("hidden");
  const wrap = element("div", "batch-table-wrap");
  const toolbar = element("div", "batch-toolbar");
  const validCount = results.filter((item) => !item.error).length;
  toolbar.append(element("p", "", `${validCount} of ${results.length} links analyzed`));
  const exportButton = element("button", "secondary-button", "Export CSV");
  exportButton.type = "button";
  exportButton.addEventListener("click", () => downloadCsv(results));
  toolbar.append(exportButton);
  wrap.append(toolbar);

  const table = element("table");
  const head = document.createElement("thead");
  const headerRow = document.createElement("tr");
  for (const title of ["#", "Destination", "Score", "Pattern risk", "Result"]) {
    headerRow.append(element("th", "", title));
  }
  head.append(headerRow);
  table.append(head);
  const body = document.createElement("tbody");
  for (const item of results) {
    const row = document.createElement("tr");
    row.append(element("td", "", String(item.row)));
    row.append(element("td", "", item.hostname || item.url));
    row.append(element("td", "", item.score === undefined ? "—" : `${item.score}/100`));
    row.append(element("td", ""));
    if (item.level) row.lastChild.append(element("span", `batch-level ${item.level}`, item.level));
    else row.lastChild.textContent = "—";
    row.append(element("td", "", item.summary || item.error));
    body.append(row);
  }
  table.append(body);
  wrap.append(table);
  batchResultArea.append(wrap);
}

const batchButton = document.querySelector("#batch-button");
const batchInput = document.querySelector("#batch-input");
const batchError = document.querySelector("#batch-error");
batchButton.addEventListener("click", async () => {
  setError(batchError, "");
  const urls = batchInput.value.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  if (!urls.length) {
    setError(batchError, "Paste at least one URL to continue.");
    return;
  }
  batchButton.disabled = true;
  batchButton.querySelector("span").textContent = "Checking…";
  try {
    const data = await postJson("/api/batch", { urls });
    renderBatch(data.results);
    batchResultArea.scrollIntoView({ behavior: "smooth", block: "nearest" });
  } catch (error) {
    setError(batchError, error.message);
    batchResultArea.classList.add("hidden");
  } finally {
    batchButton.disabled = false;
    batchButton.querySelector("span").textContent = "Check links";
  }
});
