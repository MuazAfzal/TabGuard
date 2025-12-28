// TabGuard Auto-Block (Manifest V3-safe)
// Blocks by redirecting to an extension "blocked" page when risk is high.
// This background script also listens for popup toggles (auto-block/rules/block level).

const DEFAULT_SETTINGS = {
  autoBlockEnabled: true,
  blockLevel: "danger", // "warning" or "danger"
  rulesEnabled: true
};

// Avoid redirect loops
const BLOCK_PAGE = chrome.runtime.getURL("blocked.html");

// -------------------------
// Rule-based URL checks
// -------------------------
function ruleScan(url) {
  const issues = [];
  let riskLevel = "safe";

  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname.toLowerCase();
    const protocol = urlObj.protocol;
    const fullUrl = url.toLowerCase();

    // HTTP
    if (protocol === "http:") {
      issues.push("Insecure HTTP connection");
      riskLevel = "warning";
    }

    // Risky TLDs
    const riskyTLDs = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top"]; 
    if (riskyTLDs.some((t) => hostname.endsWith(t))) {
      issues.push("Suspicious TLD detected");
      if (riskLevel === "safe") riskLevel = "warning";
    }

    // IP address host
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
      issues.push("Using raw IP address instead of domain");
      if (riskLevel === "safe") riskLevel = "warning";
    }

    // Long URL
    if (url.length > 200) {
      issues.push("Unusually long URL");
      if (riskLevel === "safe") riskLevel = "warning";
    }

    // Multiple subdomains
    if (hostname.split(".").length > 4) {
      issues.push("Multiple subdomains – possible obfuscation");
      if (riskLevel === "safe") riskLevel = "warning";
    }

    // @ trick
    if (url.includes("@")) {
      issues.push("URL contains @ symbol – classic phishing trick");
      riskLevel = "danger";
    }

    // Keywords over HTTP
    const keywords = ["login", "password", "bank", "paypal", "verify"]; 
    const found = keywords.filter((k) => fullUrl.includes(k));
    if (found.length > 0 && protocol === "http:") {
      issues.push(`Sensitive keywords over HTTP: ${found.join(", ")}`);
      riskLevel = "danger";
    }

    // Homograph-ish (simple Cyrillic range)
    if (/[а-яіїєґ]/i.test(hostname)) {
      issues.push("Potential homograph attack (lookalike characters)");
      riskLevel = "danger";
    }

    // Too many hyphens
    if ((hostname.match(/-/g) || []).length >= 3) {
      issues.push("Multiple hyphens – possible typosquatting");
      if (riskLevel === "safe") riskLevel = "warning";
    }
  } catch (e) {
    // If URL parsing fails, don't block
    return { riskLevel: "safe", issues: ["URL parse failed"] };
  }

  return { riskLevel, issues };
}

function shouldBlock(riskLevel, blockLevel) {
  if (blockLevel === "warning") {
    return riskLevel === "warning" || riskLevel === "danger";
  }
  return riskLevel === "danger";
}

// Keep a tiny cache to prevent re-processing same tab rapidly
const tabLastUrl = new Map();

async function getSettings() {
  const stored = await chrome.storage.local.get([
    "autoBlockEnabled",
    "blockLevel",
    "rulesEnabled"
  ]);

  return {
    autoBlockEnabled:
      stored.autoBlockEnabled ?? DEFAULT_SETTINGS.autoBlockEnabled,
    blockLevel: stored.blockLevel ?? DEFAULT_SETTINGS.blockLevel,
    rulesEnabled: stored.rulesEnabled ?? DEFAULT_SETTINGS.rulesEnabled
  };
}

async function setSettings(partial) {
  const allowed = {};

  if (typeof partial.autoBlockEnabled === "boolean") {
    allowed.autoBlockEnabled = partial.autoBlockEnabled;
  }

  if (partial.blockLevel === "warning" || partial.blockLevel === "danger") {
    allowed.blockLevel = partial.blockLevel;
  }

  if (typeof partial.rulesEnabled === "boolean") {
    allowed.rulesEnabled = partial.rulesEnabled;
  }

  if (Object.keys(allowed).length > 0) {
    await chrome.storage.local.set(allowed);
  }

  return getSettings();
}

// -------------------------
// Listen for popup messages
// -------------------------
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  (async () => {
    try {
      if (!msg || !msg.type) {
        sendResponse({ ok: false, error: "Missing message type" });
        return;
      }

      // Get current settings for UI initial state
      if (msg.type === "GET_SETTINGS") {
        const settings = await getSettings();
        sendResponse({ ok: true, settings });
        return;
      }

      // Update settings from popup
      if (msg.type === "SET_SETTINGS") {
        const settings = await setSettings(msg.settings || {});
        sendResponse({ ok: true, settings });
        return;
      }

      // Convenience toggles (optional)
      if (msg.type === "SET_AUTOBLOCK_ENABLED") {
        const settings = await setSettings({ autoBlockEnabled: !!msg.enabled });
        sendResponse({ ok: true, settings });
        return;
      }

      if (msg.type === "SET_RULES_ENABLED") {
        const settings = await setSettings({ rulesEnabled: !!msg.enabled });
        sendResponse({ ok: true, settings });
        return;
      }

      if (msg.type === "SET_BLOCK_LEVEL") {
        const settings = await setSettings({ blockLevel: msg.blockLevel });
        sendResponse({ ok: true, settings });
        return;
      }

      sendResponse({ ok: false, error: "Unknown message type" });
    } catch (e) {
      sendResponse({ ok: false, error: String(e?.message || e) });
    }
  })();

  return true; // keep the message channel open
});

// -------------------------
// Auto-block on navigation
// -------------------------
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  // Only react on URL changes or when loading begins
  if (!changeInfo.url && changeInfo.status !== "loading") return;
  if (!tab?.url) return;

  const url = tab.url;

  // Never block internal pages or our own blocked page
  if (
    url.startsWith("chrome://") ||
    url.startsWith("chrome-extension://") ||
    url.startsWith("edge://") ||
    url.startsWith("about:") ||
    url.startsWith(BLOCK_PAGE)
  ) {
    return;
  }

  // Prevent repeated loops on same URL
  const last = tabLastUrl.get(tabId);
  if (last === url) return;
  tabLastUrl.set(tabId, url);

  const settings = await getSettings();
  if (!settings.autoBlockEnabled) return;
  if (!settings.rulesEnabled) return; // background auto-block is rules-driven

  const scan = ruleScan(url);

  if (shouldBlock(scan.riskLevel, settings.blockLevel)) {
    // Save details so blocked page can show the reason
    await chrome.storage.local.set({
      lastBlocked: {
        time: Date.now(),
        originalUrl: url,
        riskLevel: scan.riskLevel,
        issues: scan.issues
      }
    });

    // Redirect to the blocked page
    await chrome.tabs.update(tabId, {
      url: BLOCK_PAGE
    });
  }
});

// Clear cache when tab closes
chrome.tabs.onRemoved.addListener((tabId) => {
  tabLastUrl.delete(tabId);
});