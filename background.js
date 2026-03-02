// TabGuard Auto-Block (Manifest V3-safe)
// Blocks by redirecting to an extension "blocked" page when risk is high.
// This background script also listens for popup toggles (auto-block/rules/block level).

const DEFAULT_SETTINGS = {
  autoBlockEnabled: false,
  blockLevel: "danger", // "warning" or "danger"
  rulesEnabled: true
};

function normalizeBool(value) {
  if (typeof value === "boolean") return value;
  if (typeof value === "string") {
    const v = value.trim().toLowerCase();
    if (v === "true") return true;
    if (v === "false") return false;
  }
  if (typeof value === "number") {
    if (value === 1) return true;
    if (value === 0) return false;
  }
  return undefined;
}

// Avoid redirect loops
const BLOCK_PAGE = chrome.runtime.getURL("blocked.html");

// Allow users to bypass a specific URL temporarily after a block.
// Stored as: { [url]: expiresAtEpochMs }
const BYPASS_TTL_MS = 5 * 60 * 1000; // 5 minutes

async function getBypassMap() {
  const { bypassMap } = await chrome.storage.local.get(["bypassMap"]);
  return bypassMap && typeof bypassMap === "object" ? bypassMap : {};
}

async function setBypass(url) {
  const bypassMap = await getBypassMap();
  bypassMap[url] = Date.now() + BYPASS_TTL_MS;
  await chrome.storage.local.set({ bypassMap });
}

async function isBypassed(url) {
  const bypassMap = await getBypassMap();
  const exp = bypassMap[url];
  if (!exp) return false;
  if (Date.now() > exp) {
    delete bypassMap[url];
    await chrome.storage.local.set({ bypassMap });
    return false;
  }
  return true;
}

// Ensure settings exist on first install/update
chrome.runtime.onInstalled.addListener(async () => {
  try {
    const existing = await chrome.storage.local.get([
      "autoBlockEnabled",
      "blockLevel",
      "rulesEnabled"
    ]);

    const toSet = {};
    if (typeof existing.autoBlockEnabled !== "boolean") {
      toSet.autoBlockEnabled = DEFAULT_SETTINGS.autoBlockEnabled;
    }
    if (existing.blockLevel !== "warning" && existing.blockLevel !== "danger") {
      toSet.blockLevel = DEFAULT_SETTINGS.blockLevel;
    }
    if (typeof existing.rulesEnabled !== "boolean") {
      toSet.rulesEnabled = DEFAULT_SETTINGS.rulesEnabled;
    }

    if (Object.keys(toSet).length) {
      await chrome.storage.local.set(toSet);
    }
  } catch (e) {
    // If storage fails, keep running with DEFAULT_SETTINGS
    console.warn("[TabGuard] onInstalled settings init failed:", e);
  }
});

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

  const ab = normalizeBool(partial.autoBlockEnabled);
  if (typeof ab === "boolean") {
    allowed.autoBlockEnabled = ab;
  }

  if (partial.blockLevel === "warning" || partial.blockLevel === "danger") {
    allowed.blockLevel = partial.blockLevel;
  }

  const rb = normalizeBool(partial.rulesEnabled);
  if (typeof rb === "boolean") {
    allowed.rulesEnabled = rb;
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
        const enabled = normalizeBool(msg.enabled);
        const settings = await setSettings({
          autoBlockEnabled: typeof enabled === "boolean" ? enabled : DEFAULT_SETTINGS.autoBlockEnabled
        });
        sendResponse({ ok: true, settings });
        return;
      }

      // Back-compat: some popup versions send these message types
      if (msg.type === "GET_AUTOBLOCK") {
        const settings = await getSettings();
        sendResponse({ ok: true, autoBlockEnabled: settings.autoBlockEnabled, settings });
        return;
      }

      if (msg.type === "SET_AUTOBLOCK") {
        const enabled = normalizeBool(msg.enabled);
        const fallback = normalizeBool(msg.autoBlockEnabled);
        const settings = await setSettings({
          autoBlockEnabled: typeof enabled === "boolean" ? enabled : (typeof fallback === "boolean" ? fallback : DEFAULT_SETTINGS.autoBlockEnabled)
        });
        sendResponse({ ok: true, autoBlockEnabled: settings.autoBlockEnabled, settings });
        return;
      }

      if (msg.type === "SET_RULES_ENABLED") {
        const enabled = normalizeBool(msg.enabled);
        const settings = await setSettings({
          rulesEnabled: typeof enabled === "boolean" ? enabled : DEFAULT_SETTINGS.rulesEnabled
        });
        sendResponse({ ok: true, settings });
        return;
      }

      // Back-compat: alternate naming
      if (msg.type === "GET_RULES") {
        const settings = await getSettings();
        sendResponse({ ok: true, rulesEnabled: settings.rulesEnabled, settings });
        return;
      }

      if (msg.type === "SET_RULES") {
        const settings = await setSettings({
          rulesEnabled: typeof msg.enabled === "boolean" ? msg.enabled : !!msg.rulesEnabled
        });
        sendResponse({ ok: true, rulesEnabled: settings.rulesEnabled, settings });
        return;
      }

      if (msg.type === "SET_BLOCK_LEVEL") {
        const settings = await setSettings({ blockLevel: msg.blockLevel });
        sendResponse({ ok: true, settings });
        return;
      }

      // Toggle auto-block (some popup versions send a single toggle message)
      if (msg.type === "TOGGLE_AUTOBLOCK") {
        const current = await getSettings();
        const settings = await setSettings({ autoBlockEnabled: !current.autoBlockEnabled });
        sendResponse({ ok: true, settings });
        return;
      }

      // Block page: allow the user to proceed to the original URL (temporary bypass)
      if (msg.type === "BYPASS_ONCE") {
        const originalUrl = msg.originalUrl;
        if (typeof originalUrl !== "string" || !/^https?:/i.test(originalUrl)) {
          sendResponse({ ok: false, error: "Invalid originalUrl" });
          return;
        }
        await setBypass(originalUrl);
        sendResponse({ ok: true });
        return;
      }

      // Block page: fetch last blocked details to display
      if (msg.type === "GET_LAST_BLOCKED") {
        const { lastBlocked } = await chrome.storage.local.get(["lastBlocked"]);
        sendResponse({ ok: true, lastBlocked: lastBlocked || null });
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
  if (!tab || !tab.url) return;

  // Ignore non-http(s) schemes (prevents noise + avoids accidental blocking)
  if (!/^https?:/i.test(tab.url)) return;

  const url = tab.url;

  // If user has bypassed this URL recently, do not block it.
  if (await isBypassed(url)) return;

  // Never block internal pages or our own blocked page
  if (
    url.startsWith("chrome://") ||
    url.startsWith("chrome-extension://") ||
    url.startsWith("edge://") ||
    url.startsWith("about:")
  ) {
    return;
  }

  // (blocked page is an extension URL; it won't reach this point due to the https? scheme check above)

  // Prevent repeated loops on the same URL during a single navigation
  const last = tabLastUrl.get(tabId);
  if (last === url && changeInfo.status !== "loading") return;
  tabLastUrl.set(tabId, url);

  // When navigation completes, allow future re-scans on the same URL
  if (changeInfo.status === "complete") {
    // Keep a short-lived cache entry only
    setTimeout(() => tabLastUrl.delete(tabId), 2000);
  }

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