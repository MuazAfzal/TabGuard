let aiModelReady = false;
let localAIEnabled = true;
let cloudAIEnabled = true;

// =====================
// Hugging Face API
// =====================
const HF_API_TOKEN = "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";  // <-- Replace locally
const HF_MODEL = "facebook/bart-large-mnli";

async function getHFSuggestion(url) {
  if (!HF_API_TOKEN || !cloudAIEnabled) return null;

  try {
    const response = await fetch(
      `https://api-inference.huggingface.co/models/${HF_MODEL}?wait_for_model=true`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${HF_API_TOKEN}`
        },
        body: JSON.stringify({
          inputs: `Classify the security risk of this URL: ${url}`,
          parameters: {
            candidate_labels: ["safe", "suspicious", "phishing"],
            multi_label: false
          }
        })
      }
    );

    if (!response.ok) {
      console.warn("HF API error:", response.status);
      return null;
    }

    const raw = await response.json();
    const data = Array.isArray(raw) ? raw[0] : raw;

    if (!data || !data.labels || !data.scores) {
      console.warn("HF API unexpected response:", data);
      return null;
    }

    return {
      label: data.labels[0],
      scorePercent: Math.round(data.scores[0] * 100)
    };
  } catch (err) {
    console.error("HF error:", err);
    return null;
  }
}

// =====================
// DOM LOADED
// =====================
document.addEventListener("DOMContentLoaded", async () => {
  const scanBtn = document.getElementById("scanBtn");
  const localAiToggleBtn = document.getElementById("localAiToggleBtn");
  const cloudAiToggleBtn = document.getElementById("cloudAiToggleBtn");
  const aiReloadBtn = document.getElementById("aiReloadBtn");

  // NEW info buttons:
  const localAiInfoBtn = document.getElementById("localAiInfoBtn");
  const cloudAiInfoBtn = document.getElementById("cloudAiInfoBtn");

  scanBtn.addEventListener("click", startScan);

  localAiToggleBtn.addEventListener("click", () => {
    if (!aiModelReady) return; // can't toggle if local model never loaded
    localAIEnabled = !localAIEnabled;
    updateAIIndicator();
  });

  cloudAiToggleBtn.addEventListener("click", () => {
    cloudAIEnabled = !cloudAIEnabled;
    updateAIIndicator();
  });

  aiReloadBtn.addEventListener("click", async () => {
    aiReloadBtn.disabled = true;
    aiReloadBtn.textContent = "♻️ Reloading…";
    aiModelReady = false;
    updateAIIndicator();
    await initAI();
    aiReloadBtn.disabled = false;
    aiReloadBtn.textContent = "♻️ Reload Local AI";
  });

  // Info button: Local AI
  if (localAiInfoBtn) {
    localAiInfoBtn.addEventListener("click", () => {
      alert(
        "Local AI\n\n" +
        "- Custom neural network trained on 14,000 URLs (7k phishing, 7k legitimate).\n" +
        "- Uses 40+ engineered features (length, digits, special chars, TLD, entropy, keywords, etc.).\n" +
        "- Runs entirely in your browser using TensorFlow.js (no data leaves your device)."
      );
    });
  }

  // Info button: Cloud AI (Hugging Face)
  if (cloudAiInfoBtn) {
    cloudAiInfoBtn.addEventListener("click", () => {
      alert(
        "Cloud AI (Hugging Face)\n\n" +
        "- Uses the zero-shot model facebook/bart-large-mnli.\n" +
        "- Given a URL, it classifies it into: safe, suspicious, or phishing.\n" +
        "- Works as an extra 'second opinion' combined with TabGuard’s rules and local model."
      );
    });
  }

  await initAI();

  // Load last 5 scans
  chrome.storage.local.get(["recentScans"], (data) => {
    const list = document.getElementById("recentScansList");
    if (!list) return;

    list.innerHTML = "";
    (data.recentScans || []).forEach((ts) => {
      const item = document.createElement("div");
      item.className = "tg-scan-entry";
      item.textContent = new Date(ts).toLocaleString();
      list.appendChild(item);
    });
  });
});

// =====================
// INIT LOCAL AI
// =====================
async function initAI() {
  const indicator = document.getElementById("aiIndicator");
  indicator.textContent = "Mode: Initialising…";

  await new Promise(r => setTimeout(r, 200));

  try {
    if (typeof tf === "undefined") throw new Error("TensorFlow.js missing");
    if (typeof loadAIModel !== "function") throw new Error("ai_integration.js missing");

    aiModelReady = await loadAIModel();
  } catch (err) {
    console.error("AI init error:", err);
    aiModelReady = false;
  }

  updateAIIndicator();
}

// =====================
// UPDATE MODE DISPLAY
// =====================
function updateAIIndicator() {
  const indicator = document.getElementById("aiIndicator");
  const localBtn = document.getElementById("localAiToggleBtn");
  const cloudBtn = document.getElementById("cloudAiToggleBtn");
  const note = document.getElementById("aiNote");

  // Local AI button (your trained model)
  if (aiModelReady) {
    localBtn.disabled = false;
    localBtn.textContent = localAIEnabled ? "🧠 Local AI: On" : "🧠 Local AI: Off";
  } else {
    localBtn.disabled = true;
    localBtn.textContent = "🧠 Local AI: Off";
  }

  // Cloud AI (Hugging Face) button
  cloudBtn.textContent = cloudAIEnabled ? "☁️ Cloud AI: On" : "☁️ Cloud AI: Off";

  // Which engines are actually active?
  const localActive = aiModelReady && localAIEnabled;
  const cloudActive = !!HF_API_TOKEN && cloudAIEnabled;

  const modes = ["Rules"];
  if (localActive) modes.push("Local AI");
  if (cloudActive) modes.push("Cloud AI");

  indicator.textContent = "Mode: " + modes.join(" + ");
  indicator.className = "tg-ai-indicator tg-ai-ready";

  // Description under the chip
  let desc;

  if (localActive && cloudActive) {
    // Both ON
    desc =
      "Local AI: custom neural network trained on 14,000 URLs (7k phishing, 7k legitimate, 40+ features) plus cloud-based suggestions from Hugging Face.";
  } else if (localActive && !cloudActive) {
    // Only local AI ON
    desc =
      "Local AI: neural network trained on 14,000 phishing and legitimate URLs using 40+ URL features. All detection runs inside your browser.";
  } else if (!localActive && cloudActive) {
    // Only cloud AI ON
    desc =
      "Cloud AI: Hugging Face model classifies each URL as safe, suspicious, or phishing, combined with TabGuard’s rule-based checks.";
  } else {
    // Both OFF
    desc =
      "Using TabGuard’s rule-based URL checks only (no AI engine currently active).";
  }

  if (note) note.textContent = desc;
}


// =====================
// START SCAN
// =====================
function startScan() {
  const scanBtn = document.getElementById("scanBtn");
  const scanStatus = document.getElementById("scanStatus");
  const resultsDiv = document.getElementById("results");
  const summary = document.getElementById("summary");

  scanBtn.disabled = true;
  scanBtn.textContent = "⏳ Scanning…";
  scanStatus.textContent = "Collecting tabs…";
  resultsDiv.innerHTML = "";
  summary.classList.add("tg-hidden");

  chrome.tabs.query({}, async (tabs) => {
    if (!tabs || tabs.length === 0) {
      scanStatus.textContent = "No tabs found.";
      scanBtn.disabled = false;
      scanBtn.textContent = "🔍 Scan All Open Tabs";
      return;
    }

    const results = [];
    for (const tab of tabs) {
      results.push(await scanSingleTab(tab));
    }

    let safe = 0, warn = 0, danger = 0;

    results.forEach((r) => {
      if (r.riskLevel === "safe") safe++;
      else if (r.riskLevel === "warning") warn++;
      else danger++;
    });

    resultsDiv.innerHTML = "";
    results.forEach((r) => resultsDiv.appendChild(renderTabCard(r)));

    document.getElementById("safeCount").textContent = safe;
    document.getElementById("warningCount").textContent = warn;
    document.getElementById("dangerCount").textContent = danger;
    summary.classList.remove("tg-hidden");

    const now = Date.now();
    chrome.storage.local.get(["recentScans"], (data) => {
      let scans = data.recentScans || [];
      scans.unshift(now);
      scans = scans.slice(0, 5);
      chrome.storage.local.set({ recentScans: scans });
    });

    scanBtn.disabled = false;
    scanBtn.textContent = "🔍 Scan All Open Tabs";
    scanStatus.textContent = "";
  });
}

// =====================
// SCAN SINGLE TAB
// =====================
async function scanSingleTab(tab) {
  const issues = [];
  let riskLevel = "safe";

  if (
    !tab.url ||
    tab.url.startsWith("chrome://") ||
    tab.url.startsWith("chrome-extension://") ||
    tab.url.startsWith("edge://") ||
    tab.url.startsWith("about:")
  ) {
    return {
      tab,
      riskLevel,
      issues: [
        {
          icon: "ℹ️",
          message: "Internal browser page – no scan needed"
        }
      ]
    };
  }

  try {
    const urlObj = new URL(tab.url);
    const hostname = urlObj.hostname.toLowerCase();
    const protocol = urlObj.protocol;
    const fullUrl = tab.url.toLowerCase();

    // -------- Pattern checks --------
    if (protocol === "http:") {
      issues.push({ icon: "⚠️", message: "Insecure HTTP connection" });
      riskLevel = "warning";
    }

    const riskyTLDs = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top"];
    if (riskyTLDs.some((t) => hostname.endsWith(t))) {
      issues.push({ icon: "⚠️", message: "Suspicious TLD detected" });
      if (riskLevel === "safe") riskLevel = "warning";
    }

    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
      issues.push({
        icon: "⚠️",
        message: "Using raw IP address instead of domain"
      });
      if (riskLevel === "safe") riskLevel = "warning";
    }

    if (tab.url.length > 200) {
      issues.push({ icon: "⚠️", message: "Unusually long URL" });
      if (riskLevel === "safe") riskLevel = "warning";
    }

    if (hostname.split(".").length > 4) {
      issues.push({
        icon: "⚠️",
        message: "Multiple subdomains – possible obfuscation"
      });
      if (riskLevel === "safe") riskLevel = "warning";
    }

    if (tab.url.includes("@")) {
      issues.push({
        icon: "🚨",
        message: "URL contains @ symbol – classic phishing trick"
      });
      riskLevel = "danger";
    }

    const keywords = ["login", "password", "bank", "paypal", "verify"];
    const found = keywords.filter((k) => fullUrl.includes(k));
    if (found.length > 0 && protocol === "http:") {
      issues.push({
        icon: "🚨",
        message: `Sensitive keywords over HTTP: ${found.join(", ")}`
      });
      riskLevel = "danger";
    }

    if (/[а-яіїєґ]/i.test(hostname)) {
      issues.push({
        icon: "🚨",
        message: "Potential homograph attack (lookalike characters)"
      });
      riskLevel = "danger";
    }

    if ((hostname.match(/-/g) || []).length >= 3) {
      issues.push({
        icon: "⚠️",
        message: "Multiple hyphens – possible typosquatting"
      });
      if (riskLevel === "safe") riskLevel = "warning";
    }

    // -------- Local AI (TensorFlow.js) --------
    if (aiModelReady && localAIEnabled && typeof predictWithAI === "function") {
      try {
        const aiResult = await predictWithAI(tab.url);
        if (aiResult) {
          if (aiResult.isPhishing) {
            issues.push({
              icon: "🤖",
              message: `Local AI: Threat detected (${aiResult.score}% confidence)`
            });
            if (aiResult.score >= 80) {
              riskLevel = "danger";
            } else if (aiResult.score >= 60 && riskLevel === "safe") {
              riskLevel = "warning";
            }
          } else {
            issues.push({
              icon: "🤖",
              message: `Local AI: Appears safe (${100 - aiResult.score}% confidence)`
            });
          }
        }
      } catch (err) {
        console.warn("Local AI prediction failed:", err);
      }
    } else if (aiModelReady && !localAIEnabled) {
      issues.push({
        icon: "🤖",
        message: "Local AI is turned off (rules only)"
      });
    }

    // -------- Cloud AI (Hugging Face) --------
    if (HF_API_TOKEN && cloudAIEnabled && riskLevel !== "safe") {
      const hf = await getHFSuggestion(tab.url);
      if (hf) {
        issues.push({
          icon: "💬",
          message: `Cloud AI: ${hf.label.toUpperCase()} (${hf.scorePercent}% confidence)`
        });

        if (hf.label.toLowerCase() === "phishing" && hf.scorePercent >= 80) {
          riskLevel = "danger";
        }
      }
    }

    if (issues.length === 0) {
      issues.push({ icon: "✅", message: "No security issues detected" });
    }
  } catch (err) {
    issues.push({
      icon: "ℹ️",
      message: "Could not analyse URL: " + err.message
    });
  }

  return { tab, riskLevel, issues };
}

// =====================
// RENDER TAB RESULT CARD
// =====================
function renderTabCard(result) {
  const card = document.createElement("div");
  card.className = `tg-tab-card ${result.riskLevel}`;

  const header = document.createElement("div");
  header.className = "tg-tab-header";

  const badge = document.createElement("span");
  badge.className = `tg-risk-badge ${result.riskLevel}`;
  badge.textContent = result.riskLevel.toUpperCase();

  const title = document.createElement("div");
  title.className = "tg-tab-title";
  title.textContent = result.tab.title || result.tab.url;

  header.appendChild(badge);
  header.appendChild(title);

  const urlDiv = document.createElement("div");
  urlDiv.className = "tg-tab-url";
  urlDiv.textContent = result.tab.url;

  const issuesDiv = document.createElement("div");
  issuesDiv.className = "tg-issues";

  result.issues.forEach(issue => {
    const line = document.createElement("div");
    line.className = "tg-issue";
    line.innerHTML = `<span class="tg-issue-icon">${issue.icon}</span><span>${issue.message}</span>`;
    issuesDiv.appendChild(line);
  });

  card.appendChild(header);
  card.appendChild(urlDiv);
  card.appendChild(issuesDiv);

  return card;
}
