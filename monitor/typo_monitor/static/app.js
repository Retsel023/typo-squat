"use strict";

// Work continues on the server; navigation does not cancel a scan.
if (document.body.dataset.refresh === "true" && !document.hidden) {
  window.setTimeout(() => {
    if (!document.hidden && !document.querySelector("details[open]")) window.location.reload();
  }, 5000);
}

document.addEventListener("visibilitychange", () => {
  if (!document.hidden && document.body.dataset.refresh === "true") window.location.reload();
});
