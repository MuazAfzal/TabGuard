async function loadBlockedInfo() {
    const { lastBlocked } = await chrome.storage.local.get(["lastBlocked"]);
    const urlEl = document.getElementById("blockedUrl");
    const list = document.getElementById("reasons");
  
    if (!lastBlocked) {
      urlEl.textContent = "Unknown (no stored block info)";
      return;
    }
  
    urlEl.textContent = lastBlocked.originalUrl || "Unknown URL";
  
    list.innerHTML = "";
    (lastBlocked.issues || ["High-risk detected"]).forEach((msg) => {
      const li = document.createElement("li");
      li.textContent = msg;
      list.appendChild(li);
    });
  
    // Buttons
    document.getElementById("goBack").addEventListener("click", () => history.back());
  
    document.getElementById("proceed").addEventListener("click", async () => {
      // If user proceeds, open original URL again.
      // (It may get blocked again if Auto-Block is still enabled.)
      if (lastBlocked.originalUrl) {
        location.href = lastBlocked.originalUrl;
      }
    });
  }
  
  document.addEventListener("DOMContentLoaded", loadBlockedInfo);