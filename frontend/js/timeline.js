/**
 * timeline.js — Fetch and render the incident timeline for a single event.
 *
 * Reads ?event_id=<uuid> from URL, calls GET /api/v1/timeline/{event_id},
 * renders a vertical timeline using the ::before border trick in timeline.html.
 *
 * Requirements: 4.6
 */

(function () {
  "use strict";

  const STATUS_CLASSES = {
    completed: "tl-status-completed",
    pending:   "tl-status-pending",
    skipped:   "tl-status-skipped",
  };

  const STATUS_LABELS = {
    completed: "Completed",
    pending:   "Pending",
    skipped:   "Skipped",
  };

  // Circle icon per step
  const STEP_ICONS = {
    "Detected":   "🔍",
    "Analyzed":   "🧠",
    "Blocked":    "🛡",
    "Notified":   "🔔",
    "Reported":   "📄",
  };

  function fmtTimestamp(ts) {
    if (!ts) return "—";
    try {
      return new Date(ts).toLocaleString(undefined, {
        year: "numeric", month: "short", day: "2-digit",
        hour: "2-digit", minute: "2-digit", second: "2-digit",
      });
    } catch (_) { return ts; }
  }

  function showError(msg) {
    document.getElementById("tl-loading").hidden = true;
    const el = document.getElementById("tl-error");
    // Preserve the static "Back to Dashboard" link — insert message before it
    el.innerHTML =
      '<p>' + escHtml(msg) + '</p>' +
      '<a href="/" class="tl-error-back">← Back to Dashboard</a>';
    el.hidden = false;
  }

  function renderTimeline(entries) {
    document.getElementById("tl-loading").hidden = true;
    const container = document.getElementById("tl-container");
    container.hidden = false;

    const list = document.getElementById("tl-list");
    list.innerHTML = "";

    entries.forEach(function (entry) {
      const statusClass = STATUS_CLASSES[entry.status] || STATUS_CLASSES.skipped;
      const statusLabel = STATUS_LABELS[entry.status] || entry.status;
      const icon = STEP_ICONS[entry.step_name] || "•";

      const li = document.createElement("li");
      li.className = "tl-item " + statusClass;
      li.innerHTML =
        '<div class="tl-icon">' + icon + '</div>' +
        '<div class="tl-body">' +
          '<div class="tl-header">' +
            '<span class="tl-step-name">' + escHtml(entry.step_name) + '</span>' +
            '<span class="tl-badge tl-badge-' + escHtml(entry.status) + '">' + escHtml(statusLabel) + '</span>' +
          '</div>' +
          '<div class="tl-ts">' + fmtTimestamp(entry.timestamp) + '</div>' +
          '<div class="tl-desc">' + escHtml(entry.description) + '</div>' +
        '</div>';
      list.appendChild(li);
    });
  }

  function escHtml(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function init() {
    const params = new URLSearchParams(window.location.search);
    const eventId = params.get("event_id");

    if (!eventId) {
      showError("No event_id provided. Usage: /timeline?event_id=<uuid>");
      return;
    }

    document.getElementById("tl-event-id").textContent = eventId;

    fetch("/api/v1/timeline/" + encodeURIComponent(eventId))
      .then(function (r) {
        if (r.status === 404) throw new Error("Event not found (404). The event_id may be incorrect or the event may have been deleted.");
        if (!r.ok) throw new Error("Server error: HTTP " + r.status);
        return r.json();
      })
      .then(function (body) {
        if (!body.success || !body.data || !Array.isArray(body.data.timeline)) {
          throw new Error("Unexpected response shape from server.");
        }
        renderTimeline(body.data.timeline);
      })
      .catch(function (err) {
        showError(err.message);
      });
  }

  document.addEventListener("DOMContentLoaded", init);
}());
