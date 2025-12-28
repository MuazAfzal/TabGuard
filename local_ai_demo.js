const statusEl = document.getElementById("status");
const outEl = document.getElementById("out");
const urlInput = document.getElementById("urlInput");
const predictBtn = document.getElementById("predictBtn");

(async () => {
  try {
    // quick sanity checks
    if (typeof tf === "undefined") throw new Error("TensorFlow.js (tf) not loaded");
    if (typeof loadAIModel !== "function") throw new Error("loadAIModel() not found");

    const ok = await loadAIModel();

    if (ok) {
      statusEl.innerHTML = `<span class="ok">Status: Model loaded ✅</span>`;
      predictBtn.disabled = false;
    } else {
      statusEl.innerHTML = `<span class="bad">Status: Model failed to load ❌ (check console)</span>`;
    }
  } catch (e) {
    statusEl.innerHTML = `<span class="bad">Status: ${e.message}</span>`;
    console.error(e);
  }
})();

predictBtn.addEventListener("click", async () => {
  const url = urlInput.value.trim();
  outEl.textContent = "Predicting…";

  try {
    const res = await predictWithAI(url);
    outEl.textContent = res ? JSON.stringify(res, null, 2) : "Prediction failed. Check console.";
  } catch (e) {
    outEl.textContent = "Error during prediction. Check console.";
    console.error(e);
  }
});