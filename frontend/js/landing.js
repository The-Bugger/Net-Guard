// landing.js — Start Demo button handler for landing.html
// Requirements: 13.1, 13.2
async function startDemo() {
  const errEl = document.getElementById("error-msg");
  errEl.hidden = true;
  try {
    const r = await fetch("/api/v1/demo/start", { method: "POST" });
    if (r.ok || r.status === 409) {
      // 409 = demo already running — either way, go to dashboard
      window.location.href = "/";
    } else {
      const body = await r.json().catch(() => ({}));
      errEl.textContent = "Demo start failed: " + (body.message || r.statusText);
      errEl.hidden = false;
    }
  } catch (e) {
    errEl.textContent = "Could not reach server. Is NetGuard running?";
    errEl.hidden = false;
  }
}
