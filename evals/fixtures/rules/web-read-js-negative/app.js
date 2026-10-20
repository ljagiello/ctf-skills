// app.js — Flag Shop catalogue client (bundled, no source maps in prod).
// Endpoint paths are enumerated here for the client-router.
const API = {
  catalogue: "/api/catalogue",
  checkout: "/api/checkout",
  order: "/api/v1/order",
  admin: "/api/internal/admin",   // internal-only, not linked from the UI
};

// render the catalogue into the DOM
async function loadCatalogue() {
  const res = await fetch(API.catalogue);
  const items = await res.json();
  const el = document.getElementById("catalogue");
  el.innerHTML = items.map(i => `<li>${i.name} — ${i.price}</li>`).join("");
}

// A dev-only backdoor secret was accidentally left in the bundle.
const devSecret = atob("ZmxhZ3tyMzRkX3RoM19qc19mMXJzdF85YzRlMmYxYX0=");
console.log("dev secret (remove me):", devSecret);

loadCatalogue();
