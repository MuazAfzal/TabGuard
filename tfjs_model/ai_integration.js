// TabGuard AI - Model Integration

console.log("[TabGuard AI] ai_integration.js loaded");

let model = null;
let scalerParams = null;
let featureNames = null;
let modelInputSize = null;

// Fallback order for features (based on extractFeaturesJS)
const FALLBACK_FEATURE_ORDER = [
  "url_length",
  "domain_length",
  "path_length",
  "query_length",
  "num_dots",
  "num_hyphens",
  "num_underscores",
  "num_slashes",
  "num_questionmarks",
  "num_equals",
  "num_at",
  "num_ampersands",
  "num_percent",
  "num_digits",
  "num_letters",
  "digit_letter_ratio",
  "special_char_ratio",
  "has_https",
  "has_http",
  "has_ip",
  "has_port",
  "port_number",
  "unusual_port",
  "subdomain_count",
  "has_www",
  "suspicious_tld",
  "common_tld",
  "phishing_keywords",
  "brand_keywords",
  "url_entropy",
  "domain_entropy",
  "double_slash",
  "hex_chars",
  "multiple_at",
  "path_depth",
  "suspicious_extension",
  "num_query_params",
  "repeating_chars",
  "domain_has_digits"
];

// Helper: build correct URL inside an extension
function tgGetUrl(path) {
  if (
    typeof chrome !== "undefined" &&
    chrome.runtime &&
    typeof chrome.runtime.getURL === "function"
  ) {
    return chrome.runtime.getURL(path);
  }
  return path; // fallback for non-extension environments
}

// Load the AI model (local TensorFlow.js model)
async function loadAIModel() {
  try {
    console.log("[TabGuard AI] Loading local model...");

    const modelUrl = tgGetUrl("tfjs_model/model.json");
    const scalerUrl = tgGetUrl("tfjs_model/scaler.json");
    const configUrl = tgGetUrl("tfjs_model/config.json");

    // 1) Load neural network
    model = await tf.loadLayersModel(modelUrl);
    console.log("[TabGuard AI] Model loaded from", modelUrl);

    if (model && model.inputs && model.inputs[0].shape) {
      modelInputSize = model.inputs[0].shape[1] || null;
      console.log("[TabGuard AI] Model input size:", modelInputSize);
    }

    // 2) Try to load scaler parameters (non-fatal if missing)
    try {
      const scalerRes = await fetch(scalerUrl);
      if (!scalerRes.ok) {
        throw new Error("HTTP " + scalerRes.status);
      }
      scalerParams = await scalerRes.json();
      if (!scalerParams.mean || !scalerParams.scale) {
        throw new Error("scaler.json missing mean/scale arrays");
      }
      console.log(
        "[TabGuard AI] Scaler loaded. Features in scaler:",
        scalerParams.mean.length
      );
    } catch (scalerErr) {
      console.warn("[TabGuard AI] Could not fully load scaler.json:", scalerErr);
      scalerParams = null; // fallback to unscaled mode
    }

    // 3) Try to load config / feature names (non-fatal if missing)
    try {
      const configRes = await fetch(configUrl);
      if (!configRes.ok) {
        throw new Error("HTTP " + configRes.status);
      }
      const config = await configRes.json();

      if (config.features && Array.isArray(config.features.names)) {
        featureNames = config.features.names;
      } else if (Array.isArray(config.feature_names)) {
        featureNames = config.feature_names;
      } else {
        throw new Error("No feature names array found in config.json");
      }

      console.log(
        "[TabGuard AI] Config loaded. Feature count:",
        featureNames.length
      );
    } catch (configErr) {
      console.warn(
        "[TabGuard AI] Could not fully load config.json (feature names):",
        configErr
      );
      featureNames = null; // fallback to hardcoded order
    }

    console.log("[TabGuard AI] Local AI ready.");
    return true;
  } catch (err) {
    console.error("[TabGuard AI] AI model load failed:", err);
    model = null;
    scalerParams = null;
    featureNames = null;
    modelInputSize = null;
    return false;
  }
}

function extractFeaturesJS(url) {
  const features = {};

  try {
    const urlObj = new URL(url);

    // Length features
    features.url_length = url.length;
    features.domain_length = urlObj.hostname.length;
    features.path_length = urlObj.pathname.length;
    features.query_length = urlObj.search.length;

    // Count features
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
    features.special_char_ratio =
      (features.num_hyphens + features.num_underscores) / urlLen;

    // Protocol
    features.has_https = urlObj.protocol === "https:" ? 1 : 0;
    features.has_http = urlObj.protocol === "http:" ? 1 : 0;

    // IP address
    const ipPattern = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/;
    features.has_ip = ipPattern.test(urlObj.hostname) ? 1 : 0;

    // Port
    features.has_port = urlObj.port ? 1 : 0;
    features.port_number = urlObj.port ? parseInt(urlObj.port) : 0;
    const unusualPorts = [8080, 8888, 3000, 4000, 5000, 8000];
    features.unusual_port = unusualPorts.includes(parseInt(urlObj.port)) ? 1 : 0;

    // Subdomains + TLDs
    const parts = urlObj.hostname.split(".");
    features.subdomain_count = Math.max(0, parts.length - 2);
    features.has_www = urlObj.hostname.includes("www") ? 1 : 0;

    const suspiciousTlds = [
      ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".cc", ".pw"
    ];
    features.suspicious_tld =
      suspiciousTlds.some(tld => url.toLowerCase().endsWith(tld)) ? 1 : 0;

    const commonTlds = [".com", ".org", ".net", ".edu", ".gov"];
    features.common_tld =
      commonTlds.some(tld => url.toLowerCase().endsWith(tld)) ? 1 : 0;

    // Keywords
    const lower = url.toLowerCase();
    const phishingKeywords = [
      "login", "verify", "account", "update", "secure",
      "banking", "paypal", "ebay", "confirm", "signin",
      "password", "credential", "suspended", "locked"
    ];
    features.phishing_keywords =
      phishingKeywords.filter(k => lower.includes(k)).length;

    const brandKeywords = [
      "google", "facebook", "amazon", "microsoft", "apple",
      "paypal", "netflix", "instagram", "twitter", "bank"
    ];
    features.brand_keywords =
      brandKeywords.filter(k => lower.includes(k)).length;

    // Entropy
    features.url_entropy = calculateEntropy(url);
    features.domain_entropy = calculateEntropy(urlObj.hostname);

    // Patterns
    features.double_slash = urlObj.pathname.includes("//") ? 1 : 0;
    features.hex_chars = (url.match(/%[0-9A-Fa-f]{2}/g) || []).length;
    features.multiple_at = url.split("@").length > 2 ? 1 : 0;

    // Path depth & extensions
    const pathParts = urlObj.pathname.split("/").filter(Boolean);
    features.path_depth = pathParts.length;

    const suspiciousExt = [".exe", ".zip", ".rar", ".apk", ".bat"];
    features.suspicious_extension =
      suspiciousExt.some(ext => lower.includes(ext)) ? 1 : 0;

    // Query params
    features.num_query_params = urlObj.search
      ? urlObj.search.replace(/^\?/, "").split("&").filter(Boolean).length
      : 0;

    // Domain patterns
    const hostLower = urlObj.hostname.toLowerCase();
    const runs = [];
    let current = 1;
    for (let i = 1; i < hostLower.length; i++) {
      if (hostLower[i] === hostLower[i - 1]) current++;
      else {
        runs.push(current);
        current = 1;
      }
    }
    runs.push(current);
    features.repeating_chars = Math.max(...runs);
    features.domain_has_digits = /\d/.test(urlObj.hostname) ? 1 : 0;
  } catch (err) {
    console.error("Feature extraction error:", err);
    return null;
  }

  return features;
}

function calculateEntropy(str) {
  const len = str.length || 1;
  const freq = {};
  for (const ch of str) {
    freq[ch] = (freq[ch] || 0) + 1;
  }
  let entropy = 0;
  for (const ch in freq) {
    const p = freq[ch] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

// Optional_scaling when scaler + featureNames present
function scaleFeatures(features) {
  const scaled = {};
  featureNames.forEach((name, idx) => {
    const value = features[name] ?? 0;
    scaled[name] = (value - scalerParams.mean[idx]) / scalerParams.scale[idx];
  });
  return scaled;
}

async function predictWithAI(url) {
  if (!model) {
    console.warn("AI model not ready (no model instance)");
    return null;
  }

  try {
    const features = extractFeaturesJS(url);
    if (!features) return null;

    let array;

    // Preferred path: use scaler + config featureNames if both are loaded
    if (scalerParams && featureNames && featureNames.length > 0) {
      const scaled = scaleFeatures(features);
      array = featureNames.map(name => scaled[name] ?? 0);
      console.log("[TabGuard AI] Using scaled features from config.json");
    } else {
      // Fallback: unscaled features in our known JS order
      array = FALLBACK_FEATURE_ORDER.map(name => features[name] ?? 0);
      console.log("[TabGuard AI] Using fallback feature order (unscaled).");
    }

    // Make sure input length matches model input size
    if (!modelInputSize && model.inputs && model.inputs[0].shape) {
      modelInputSize = model.inputs[0].shape[1] || null;
    }

    if (modelInputSize && array.length !== modelInputSize) {
      if (array.length < modelInputSize) {
        // pad with zeros
        while (array.length < modelInputSize) array.push(0);
      } else if (array.length > modelInputSize) {
        // truncate
        array = array.slice(0, modelInputSize);
      }
      console.log(
        "[TabGuard AI] Adjusted feature vector length to match model input size:",
        modelInputSize
      );
    }

    const input = tf.tensor2d([array]);
    const prediction = model.predict(input);
    const data = await prediction.data();
    const score = data[0];

    input.dispose();
    prediction.dispose();

    let riskLevel = "safe";
    if (score > 0.6) riskLevel = "danger";
    else if (score > 0.3) riskLevel = "warning";

    return {
      isPhishing: score > 0.5,
      confidence: score,
      riskLevel,
      score: Math.round(score * 100)
    };
  } catch (err) {
    console.error("AI prediction error:", err);
    return null;
  }
}
