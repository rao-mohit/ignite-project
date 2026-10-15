const API_ENDPOINT = "http://127.0.0.1:8000/api/analyze-url";
let bypassedUrls = new Set();

document.addEventListener("click", async (e) => {
  const anchor = e.target.closest("a");
  if (!anchor || !anchor.href) return;

  const targetUrl = anchor.href;

  // Ignore internal hashes, javascript: or previously bypassed links
  if (targetUrl.startsWith("#") || targetUrl.startsWith("javascript:") || bypassedUrls.has(targetUrl)) {
    return;
  }

  // Intercept click
  e.preventDefault();
  e.stopPropagation();

  try {
    const res = await fetch(API_ENDPOINT, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: targetUrl })
    });

    if (!res.ok) throw new Error("API check failed");
    const data = await res.json();

    if (data.risk_score >= 50 || data.risk_level === "HIGH" || data.risk_level === "CRITICAL") {
      showWarningModal(targetUrl, data);
    } else {
      // Low/Medium risk: proceed safely
      window.location.href = targetUrl;
    }
  } catch (err) {
    console.warn("ThreatGuard Extension: API check timed out or unavailable. Proceeding safely.");
    window.location.href = targetUrl;
  }
}, true);

function showWarningModal(targetUrl, data) {
  const existing = document.getElementById("tg-threat-modal");
  if (existing) existing.remove();

  const modal = document.createElement("div");
  modal.id = "tg-threat-modal";
  modal.style.cssText = `
    position: fixed; top: 0; left: 0; width: 100vw; height: 100vh;
    background: rgba(11, 19, 43, 0.92); backdrop-filter: blur(10px);
    display: flex; align-items: center; justify-content: center;
    z-index: 9999999; font-family: system-ui, -apple-system, sans-serif;
  `;

  modal.innerHTML = `
    <div style="
      background: #1c2541; border: 2px solid #ef4444; border-radius: 16px;
      padding: 2rem; max-width: 500px; width: 90%; color: #f8fafc;
      box-shadow: 0 20px 50px rgba(239, 68, 68, 0.3); text-align: left;
    ">
      <div style="display:flex; align-items:center; gap:0.75rem; margin-bottom:1rem">
        <div style="font-size:2rem">⚠️</div>
        <div>
          <h2 style="margin:0; font-size:1.25rem; color:#ef4444">High-Risk Link Warning</h2>
          <span style="font-size:0.8rem; color:#94a3b8">ThreatGuard AI Protection Intercept</span>
        </div>
      </div>

      <div style="background:#0b132b; padding:0.75rem; border-radius:8px; font-family:monospace; font-size:0.85rem; word-break:break-all; margin-bottom:1rem; border:1px solid #2b3a67">
        ${targetUrl}
      </div>

      <div style="margin-bottom:1rem; font-size:0.9rem">
        <strong>Risk Rating:</strong> <span style="color:#ef4444; font-weight:700">${data.risk_level} (${data.risk_score}/100)</span>
      </div>

      <div style="font-size:0.85rem; color:#94a3b8; margin-bottom:1.5rem">
        ${data.recommendation}
      </div>

      <div style="display:flex; gap:1rem; justify-content:flex-end">
        <button id="tg-btn-back" style="
          background:#2b3a67; color:#fff; border:none; padding:0.65rem 1.25rem;
          border-radius:8px; cursor:pointer; font-weight:600; font-size:0.85rem;
        ">Go Back (Safe)</button>

        <button id="tg-btn-continue" style="
          background:transparent; color:#ef4444; border:1px solid #ef4444;
          padding:0.65rem 1.25rem; border-radius:8px; cursor:pointer; font-size:0.85rem;
        ">Continue Anyway</button>
      </div>
    </div>
  `;

  document.body.appendChild(modal);

  document.getElementById("tg-btn-back").addEventListener("click", () => {
    modal.remove();
  });

  document.getElementById("tg-btn-continue").addEventListener("click", () => {
    bypassedUrls.add(targetUrl);
    modal.remove();
    window.location.href = targetUrl;
  });
}

// WhatsApp Web Active Shield Indicator
if (window.location.hostname.includes("whatsapp.com")) {
  const badge = document.createElement("div");
  badge.id = "tg-wa-shield-badge";
  badge.style.cssText = `
    position: fixed; bottom: 16px; left: 16px; z-index: 99999;
    background: #064e3b; color: #a7f3d0; border: 1px solid #10b981;
    border-radius: 9999px; padding: 6px 14px; font-size: 11px; font-weight: 700;
    font-family: system-ui, sans-serif; display: flex; align-items: center; gap: 6px;
    box-shadow: 0 4px 14px rgba(0,0,0,0.25);
  `;
  badge.innerHTML = `<span style="width:7px; height:7px; border-radius:50%; background:#34d399; display:inline-block;"></span> ThreatGuard AI: WhatsApp Phishing Protection Active`;
  document.body.appendChild(badge);
}
