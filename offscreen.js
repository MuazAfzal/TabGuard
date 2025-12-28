let model = null;
let scalerParams = null;
let featureNames = null;

const FALLBACK_FEATURE_ORDER = [
  "url_length","domain_length","path_length","query_length",
  "num_dots","num_hyphens","num_underscores","num_slashes","num_questionmarks","num_equals",
  "num_at","num_ampersands","num_percent","num_digits","num_letters",
  "digit_letter_ratio","special_char_ratio",
  "has_https","has_http","has_ip",
  "has_port","port_number","unusual_port",
  "subdomain_count","has_www","suspicious_tld","common_tld",
  "phishing_keywords","brand_keywords",
  "url_entropy","domain_entropy",
  "double_slash","hex_chars","multiple_at",
  "path_depth","suspicious_extension","num_query_params",
  "repeating_chars","domain_has_digits"
];

function tgGetUrl(path) {
  return chrome.runtime.getURL(path);
}

async function initTfBackend() {
  // Force WASM backend (more MV3-friendly than webgl in many cases)
  try {
    await tf.setBackend("wasm");
    await tf.ready();
  } catch (e) {
    // If wasm fails, fallback to default backend
    await tf.ready();
  }
}

async function loadAIModel() {
  await initTfBackend();

  const modelUrl  = tgGetUrl("tfjs_model/model.json");
  const scalerUrl = tgGetUrl("tfjs_model/scaler.json");
  const configUrl = tgGetUrl("tfjs_model/config.json");

  model = await tf.loadLayersModel(modelUrl);

  // scaler
  try {
    const scalerRes = await fetch(scalerUrl);
    scalerParams = await scalerRes.json();
  } catch {
    scalerParams = null;
  }

  // feature names
  try {
    const configRes = await fetch(configUrl);
    const config = await configRes.json();
    featureNames = config?.features?.names || config?.feature_names || null;
  } catch {
    featureNames = null;
  }

  return true;
}

function calculateEntropy(str) {
  const len = str.length || 1;
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;

  let entropy = 0;
  for (const ch in freq) {
    const p = freq[ch] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function extractFeaturesJS(url) {
  const features = {};
  const urlObj = new URL(url);
  const lower = url.toLowerCase();

  features.url_length = url.length;
  features.domain_length = urlObj.hostname.length;
  features.path_length = urlObj.pathname.length;
  features.query_length = urlObj.search.length;

  features.num_dots = (url.match(/\./g) || []).length;
  features.num_hyphens = (url.match(/-/g) || []).length;
  features.num_underscores = (url.match(/_/g) || []).length;
  features.num_slashes = (url.match(/\//g) || []).length;
  features.num_questionmarks = (url.match(/\?/g) || []).length;
  features.num_equals = (url.match(/=/g) || []).length;
  features.num_at = (url.match(/@/g) || []).length;
  features.num_ampersands = (url.match(/&/g) || []).length;
  features.num_percent = (url.match(/%/g) || []).length;
  features.num_digits = (url.match(/\d/g) || []).length;
  features.num_letters = (url.match(/[a-zA-Z]/g) || []).length;

  const urlLen = url.length || 1;
  features.digit_letter_ratio = features.num_digits / urlLen;
  features.special_char_ratio = (features.num_hyphens + features.num_underscores) / urlLen;

  features.has_https = urlObj.protocol === "https:" ? 1 : 0;
  features.has_http = urlObj.protocol === "http:" ? 1 : 0;

  const ipPattern = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/;
  features.has_ip = ipPattern.test(urlObj.hostname) ? 1 : 0;

  features.has_port = urlObj.port ? 1 : 0;
  features.port_number = urlObj.port ? parseInt(urlObj.port) : 0;
  const unusualPorts = [8080, 8888, 3000, 4000, 5000, 8000];
  features.unusual_port = unusualPorts.includes(parseInt(urlObj.port)) ? 1 : 0;

  const parts = urlObj.hostname.split(".");
  features.subdomain_count = Math.max(0, parts.length - 2);
  features.has_www = urlObj.hostname.includes("www") ? 1 : 0;

  const suspiciousTlds = [".tk",".ml",".ga",".cf",".gq",".xyz",".top",".cc",".pw"];
  features.suspicious_tld = suspiciousTlds.some(tld => lower.endsWith(tld)) ? 1 : 0;

  const commonTlds = [".com",".org",".net",".edu",".gov"];
  features.common_tld = commonTlds.some(tld => lower.endsWith(tld)) ? 1 : 0;

  const phishingKeywords = [
    "login","verify","account","update","secure","banking","paypal","ebay",
    "confirm","signin","password","credential","suspended","locked"
  ];
  features.phishing_keywords = phishingKeywords.filter(k => lower.includes(k)).length;

  const brandKeywords = ["google","facebook","amazon","microsoft","apple","paypal","netflix","instagram","twitter","bank"];
  features.brand_keywords = brandKeywords.filter(k => lower.includes(k)).length;

  features.url_entropy = calculateEntropy(url);
  features.domain_entropy = calculateEntropy(urlObj.hostname);

  features.double_slash = urlObj.pathname.includes("//") ? 1 : 0;
  features.hex_chars = (url.match(/%[0-9A-Fa-f]{2}/g) || []).length;
  features.multiple_at = url.split("@").length > 2 ? 1 : 0;

  const pathParts = urlObj.pathname.split("/").filter(Boolean);
  features.path_depth = pathParts.length;

  const suspiciousExt = [".exe",".zip",".rar",".apk",".bat"];
  features.suspicious_extension = suspiciousExt.some(ext => lower.includes(ext)) ? 1 : 0;

  features.num_query_params = urlObj.search
    ? urlObj.search.replace(/^\?/, "").split("&").filter(Boolean).length
    : 0;

  const hostLower = urlObj.hostname.toLowerCase();
  const runs = [];
  let current = 1;
  for (let i = 1; i < hostLower.length; i++) {
    if (hostLower[i] === hostLower[i - 1]) current++;
    else { runs.push(current); current = 1; }
  }
  runs.push(current);

  features.repeating_chars = Math.max(...runs);
  features.domain_has_digits = /\d/.test(urlObj.hostname) ? 1 : 0;

  return features;
}

function scaleFeatures(features) {
  const scaled = {};
  featureNames.forEach((name, idx) => {
    const value = features[name] ?? 0;
    scaled[name] = (value - scalerParams.mean[idx]) / scalerParams.scale[idx];
  });
  return scaled;
}

async function predictWithAI(url) {
  if (!model) return null;

  const features = extractFeaturesJS(url);

  let vector;
  if (scalerParams && featureNames?.length) {
    const scaled = scaleFeatures(features);
    vector = featureNames.map(n => scaled[n] ?? 0);
  } else {
    vector = FALLBACK_FEATURE_ORDER.map(n => features[n] ?? 0);
  }

  const input = tf.tensor2d([vector]);
  const pred = model.predict(input);
  const data = await pred.data();
  const score = data[0];

  input.dispose();
  pred.dispose();

  let riskLevel = "safe";
  if (score > 0.6) riskLevel = "danger";
  else if (score > 0.3) riskLevel = "warning";

  return {
    score: Math.round(score * 100),
    confidence: score,
    isPhishing: score > 0.5,
    riskLevel
  };
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    try {
      if (msg?.type === "OFFSCREEN_INIT") {
        if (!model) await loadAIModel();
        sendResponse({ ok: true, ready: true });
        return;
      }

      if (msg?.type === "OFFSCREEN_PREDICT") {
        if (!model) await loadAIModel();
        const result = await predictWithAI(msg.url);
        sendResponse({ ok: true, result });
        return;
      }

      sendResponse({ ok: false, error: "Unknown message type" });
    } catch (e) {
      sendResponse({ ok: false, error: e?.message || String(e) });
    }
  })();

  return true;
});