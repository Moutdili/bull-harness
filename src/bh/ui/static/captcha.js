// /captcha/: the screen of bh-browser (noVNC client from the container, WebSocket relayed by the UI), for Mio to
// solve a human challenge by hand. Rendering is textContent only; nothing from the page is trusted.
import RFB from "/captcha/novnc/core/rfb.js";

const $ = (id) => document.getElementById(id);

function setTag(el, text, cls) {
  el.textContent = text;
  el.className = "tag" + (cls ? " " + cls : "");
}

let rfb = null;
// Spectator: after "J'ai fini" with no challenge left, the screen only shows (no mouse, no keys reach the agent's
// browser) and the agent goes on. A new challenge gives the hand back. The controller decides (human_watching).
let watching = false;
function setWatching(on) {
  watching = on;
  if (rfb) rfb.viewOnly = on;
  setTag($("mode"), on ? "spectateur : l'agent travaille" : "main : à toi", on ? "ok" : "warn");
}

function connect() {
  const scheme = location.protocol === "https:" ? "wss" : "ws";
  rfb = new RFB($("screen"), `${scheme}://${location.host}/captcha/ws`, { wsProtocols: ["binary"] });
  rfb.scaleViewport = true;
  rfb.resizeSession = false;
  rfb.viewOnly = watching;
  rfb.addEventListener("connect", () => setTag($("link"), "écran : connecté", "ok"));
  rfb.addEventListener("disconnect", () => {
    setTag($("link"), "écran : coupé, reconnexion…", "warn");
    setTimeout(connect, 3000);
  });
}

async function poll() {
  try {
    const r = await fetch("/api/captcha/status", { credentials: "same-origin" });
    const s = await r.json();
    if (s.code !== 200) {
      $("where").textContent = "navigateur : " + (s.error || "indisponible");
    } else {
      $("where").textContent = `navigateur : ${s.title || ""} — ${s.url || ""}`;
      const ch = s.challenge || {};
      if (ch.pending) setTag($("challenge"), "challenge : en attente (" + (ch.reason || "?") + ")", "warn");
      else setTag($("challenge"), "challenge : aucun", "ok");
      if (Boolean(s.human_watching) !== watching) setWatching(Boolean(s.human_watching));
    }
  } catch (e) {
    $("where").textContent = "navigateur : statut illisible";
  }
}

$("done").addEventListener("click", async () => {
  $("done").disabled = true;
  try {
    const r = await fetch("/api/captcha/done", {
      method: "POST",
      credentials: "same-origin",
      headers: { "X-BH": "1", "Content-Type": "application/json" },
      body: "{}",
    });
    const s = await r.json();
    if (s.ok && s.challenge_pending) $("done").textContent = "Le challenge est encore là";
    else $("done").textContent = s.ok ? "Noté ✓" : "Échec";
    if (s.ok) setWatching(Boolean(s.watching));
  } catch (e) {
    $("done").textContent = "Échec";
  }
  setTimeout(() => { $("done").disabled = false; $("done").textContent = "J'ai fini"; }, 4000);
  poll();
});

setWatching(false);
connect();
poll();
setInterval(poll, 5000);
