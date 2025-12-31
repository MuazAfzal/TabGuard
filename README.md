# TabGuard — AI-Powered Browser Security Scanner (Chrome/Edge Extension)

TabGuard is a lightweight browser extension that helps you spot risky links before you click them. It scans open tabs and flags common phishing and URL-based threats using a mix of:

* **Rule-based checks** (fast, offline, explainable)
* **Local AI** (your trained model, runs on-device via MV3 offscreen)
* **Cloud AI** (optional “second opinion” using Hugging Face)

It also includes an **Auto-Blocker** mode that can redirect **warning/danger** pages to a safe block screen (with a bypass option).

---

## Key Features

### ✅ Tab Scanning

* **Scan all open tabs** in one click
* **Color-coded risk levels:** Safe / Warning / Danger
* **Readable explanations** for each finding (not just a score)

### ✅ Rule-Based Security Checks

TabGuard inspects URLs for common phishing and obfuscation patterns, including:

* HTTP vs HTTPS detection
* risky TLDs (`.tk`, `.ml`, `.xyz`, etc.)
* raw IP address URLs
* very long URLs and excessive subdomains
* `@` symbol trick
* sensitive keywords on HTTP (login/password/bank/paypal/verify)
* potential homograph patterns (lookalike characters)
* multiple hyphens as a typosquatting indicator

### ✅ Local AI (On-Device)

* Uses a **custom trained neural network** on URL-engineered features
* Runs locally via an **MV3 offscreen document** (needed because MV3 blocks `unsafe-eval`)
* No webpage content is uploaded for local inference

### ✅ Cloud AI (Optional)

* Uses Hugging Face inference to classify URLs as **safe / suspicious / phishing**
* Works as a “second opinion” when enabled
* Requires an API token + internet

### ✅ Auto-Blocker (Optional)

* When enabled, TabGuard can **block/redirect “warning” and “danger” pages**
* Includes a **bypass option** so the user can still proceed

### ✅ Quality-of-life

* “Last 5 scans” history
* Light/Dark mode
* Toggles for Rules, Local AI, Cloud AI, Auto-Block

---

## Tech Stack

* **Chrome Extension Manifest V3**
* **JavaScript (Vanilla)**
* **Chrome APIs:** `tabs`, `storage`, `activeTab`, `offscreen`
* **Local AI:** TensorFlow.js model (executed via offscreen page)
* **Cloud AI:** Hugging Face inference API (token-based)
* **UI:** HTML + CSS (custom theme)

---

## Installation (Load Unpacked)

1. Download/clone this repo.
2. Open Chrome (or Edge) → go to:

   * `chrome://extensions/` (Chrome)
   * `edge://extensions/` (Edge)
3. Enable **Developer mode**.
4. Click **Load unpacked**.
5. Select the project folder (e.g. `browser-security-scanner`).
6. Pin TabGuard from the extensions toolbar.

---

## Setup (Cloud AI Token)

Cloud AI is optional. If you want it:

1. Create a Hugging Face token (Settings → Access Tokens).
2. Open `popup.js`
3. Replace:

   ```js
   const HF_API_TOKEN = "hf_...";
   ```
4. Reload the extension in `chrome://extensions/`.

**Important:** Do not commit real tokens to GitHub.

---

## How to Use

1. Click the **TabGuard** icon in the browser toolbar.
2. Use toggles (Rules / Local AI / Cloud AI / Auto-Block) depending on what you want active.
3. Click **Scan All Open Tabs**.
4. Review:

   * Risk badge per tab (SAFE / WARNING / DANGER)
   * Explanations for what triggered the result
   * Optional AI notes (Local/Cloud)

---

## Settings & Persistence

TabGuard stores your toggle choices (Rules, Local AI, Cloud AI, Auto-Block, Theme) using `chrome.storage.local`, so your settings remain the same after closing/reopening the popup.

---

## Local AI Notes (Why Offscreen)

Chrome Manifest V3 enforces a strict Content Security Policy that blocks patterns like `unsafe-eval`. Some TFJS builds can trigger this restriction inside the popup context.

To keep local inference MV3-compatible, TabGuard loads and runs the local model through an **offscreen document**, then returns predictions back to the popup using `chrome.runtime.sendMessage`.

---

## Folder Structure (Typical)

You may have something similar to:

```
browser-security-scanner/
  manifest.json
  popup.html
  popup.js
  styles.css
  background.js
  blocked.html
  icon.png

  tfjs_model/
    model.json
    scaler.json
    config.json
    *.bin
    ai_integration.js

  lib/ (optional)
    tfjs/...
```

---

## Permissions Explained

* **tabs**: read open tab URLs/titles for scanning
* **activeTab**: access the current tab when needed
* **storage**: save settings + scan history
* **offscreen**: run local AI safely under MV3 restrictions
* **host_permissions (HF)**: allows calling Hugging Face inference endpoint

---

## Limitations (Current)

* URL analysis only (no deep page content/HTML/JS scanning yet)
* No network packet monitoring (browser security restrictions)
* Cloud AI requires token + internet + can hit rate limits
* Auto-block only applies based on URL risk (not file malware scanning)
* Best supported on Chrome/Edge desktop

---

## Troubleshooting

### Local AI shows “Not ready”

* Confirm the offscreen workflow is correctly wired in `background.js`
* Ensure TFJS model files exist inside `tfjs_model/`
* Reload the extension from `chrome://extensions/`

### Cloud AI errors (examples)

* **HF 401/403**: token invalid or missing
* **HF 429**: rate limit (try later or reduce scans)
* **HF 503**: model loading/busy (retry after a moment)
* **HF 410**: model endpoint unavailable (switch model or check Hugging Face availability)

### Extension won’t load

* `manifest.json` must be valid JSON (no trailing commas, no extra text)

---

## Future Improvements

* Page content scanning (forms/redirects/scripts indicators)
* Real-time background monitoring (with user controls)
* Safe Browsing / reputation checks integration
* Stronger auto-block logic using combined rules + AI confidence
* Mobile browser support (long-term)

---

## License

Copyright (c) 2025 TabGuard Project

Permission is hereby granted to use, view, and modify this software **for educational, academic, and personal demonstration purposes only**, subject to the following conditions:

1. **Non-Commercial Use Only**
   This software may not be sold, sublicensed, monetised, or used in any commercial product or service.

2. **No Redistribution**
   Redistribution of this software, in original or modified form, is not permitted without explicit written permission from the author.

3. **Attribution Required**
   Any academic submission, demonstration, or presentation using this software must clearly acknowledge the TabGuard project and its author.

4. **No Warranty**
   This software is provided “as is”, without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, or non-infringement.

5. **Limitation of Liability**
   In no event shall the author be liable for any claim, damages, or other liability arising from the use of this software.

6. **Security Disclaimer**
   This software is intended for research and educational purposes only and must not be relied upon as a complete or guaranteed security solution.

---

## Credits / References

* Hugging Face Inference API (Cloud AI)
* TensorFlow.js (Local AI)

