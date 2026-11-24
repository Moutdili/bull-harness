// bull-harness UI. Everything coming from the agent or a target is untrusted:
// it is only ever rendered through textContent (see el()). Never use innerHTML with data.
"use strict";

const $ = (s) => document.querySelector(s);
function el(tag, attrs, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") n.className = v;
    else if (k === "style") n.style.cssText = v; // CSSOM: allowed by the strict CSP, unlike a style attribute
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else n.setAttribute(k, v === true ? "" : String(v));
  }
  for (const k of kids.flat()) {
    if (k === null || k === undefined || k === false) continue;
    n.append(k instanceof Node ? k : document.createTextNode(String(k)));
  }
  return n;
}
const fill = (node, ...kids) => { node.replaceChildren(...kids.flat().filter((k) => k != null && k !== false)); return node; };
const ago = (ts) => { if (!ts) return "—"; const s = Date.now() / 1000 - ts; if (s < 60) return `${s | 0}s`; if (s < 3600) return `${(s / 60) | 0} min`; if (s < 86400) return `${(s / 3600) | 0} h`; return `${(s / 86400) | 0} j`; };
const time = (ts) => ts ? new Date(ts * 1000).toLocaleString("fr-CH") : "—";
const sev = (s) => el("span", { class: `badge sev-${s || "info"}` }, s || "?");

async function api(path, body) {
  const opt = body === undefined ? {} : { method: "POST", headers: { "Content-Type": "application/json", "X-BH": "1" }, body: JSON.stringify(body) };
  const r = await fetch(path, opt);
  if (r.status === 401) { document.body.replaceChildren(el("p", { class: "empty" }, "Session expirée : recharge la page et colle le token (secrets/ui.token)")); throw new Error("401"); }
  const j = await r.json();
  if (!r.ok || j.error) throw new Error(j.error || r.status);
  return j;
}
function toast(msg) { const t = $("#toast"); t.textContent = msg; t.classList.remove("hidden"); clearTimeout(toast.t); toast.t = setTimeout(() => t.classList.add("hidden"), 3500); }
function drawer(...content) { fill($("#drawer-body"), ...content); $("#drawer").classList.remove("hidden"); }
$("#drawer-x").addEventListener("click", () => $("#drawer").classList.add("hidden"));
$("#drawer").addEventListener("click", (e) => { if (e.target.id === "drawer") $("#drawer").classList.add("hidden"); });

// ------------------------------------------------------------------ tabs
let current = "dash";
document.querySelectorAll("#tabs button").forEach((b) => b.addEventListener("click", () => show(b.dataset.tab)));
function show(tab) {
  current = tab;
  $("#drawer").classList.add("hidden");
  document.querySelectorAll("#tabs button").forEach((b) => b.classList.toggle("on", b.dataset.tab === tab));
  document.querySelectorAll(".tab").forEach((s) => s.classList.toggle("on", s.id === tab));
  location.hash = tab;
  refresh();
}
const views = {};

// ------------------------------------------------------------------ header / status
let status = null;
async function loadStatus() {
  status = await api("/api/status");
  const c = status.containers;
  fill($("#stack"),
    ...Object.entries(c).map(([k, v]) => el("span", {}, el("i", { class: `dot ${v ? "up" : ""}` }), k)),
    el("span", {}, status.active_scope ? `scope: ${status.active_scope.program}` : "pas de scope actif"),
    status.running ? el("span", { style: "color:var(--accent)" }, `● run ${status.running.id}`) : null);
  $("#n-find").textContent = status.findings_to_review || "";
  $("#n-todo").textContent = status.open_todos || "";
}

// ------------------------------------------------------------------ dashboard
views.dash = async () => {
  const [runs, todos, findings] = await Promise.all([api("/api/runs"), api("/api/todos"), api("/api/findings")]);
  const s = status.severity;
  fill($("#dash"),
    el("h2", {}, "Findings par sévérité"),
    el("div", { class: "grid" }, ...Object.keys(s).map((k) =>
      el("div", { class: `card kpi ${k === "critical" ? "crit" : k}` }, el("div", { class: "v" }, s[k]), el("div", { class: "k" }, k)))),
    el("div", { class: "grid", style: "margin-top:12px" },
      kpi("À relire", status.findings_to_review), kpi("Todo humaine", status.open_todos),
      kpi("Faits sur le board", status.facts), kpi("Runs", status.runs)),
    el("div", { class: "two" },
      el("div", {}, el("h2", {}, "Todo humaine (bloque l'agent)"),
        todos.length ? todoTable(todos.slice(0, 8)) : el("div", { class: "empty" }, "Rien ne bloque l'agent.")),
      el("div", {}, el("h2", {}, "Derniers findings"),
        findings.length ? findingTable(findings.slice(0, 8)) : el("div", { class: "empty" }, "Pas encore de finding."))),
    el("h2", {}, "Derniers runs"), runTable(runs.slice(0, 10)));
};
const kpi = (k, v) => el("div", { class: "card kpi" }, el("div", { class: "v" }, v ?? "—"), el("div", { class: "k" }, k));

function runTable(runs) {
  if (!runs.length) return el("div", { class: "empty" }, "Aucun run. Lance-en un depuis Programmes.");
  const tools = (r) => r.arsenal_calls == null ? "—" : `${r.arsenal_calls} / ${r.manual_calls} / ${r.locked_calls}`;
  return el("table", {}, el("tr", {}, ...["#", "programme", "statut", "modèle", "tours", "arsenal / manuel / 🔒", "coût éq.", "début", "note"].map((h) => el("th", {}, h))),
    ...runs.map((r) => el("tr", { class: "click", onclick: () => { liveRun = r.id; liveRunId = null; show("live"); } },
      el("td", {}, r.id), el("td", {}, r.program), el("td", {}, el("span", { class: "badge" }, r.status)), el("td", {}, r.model),
      el("td", {}, r.turns ?? "—"), el("td", { class: "small" }, tools(r)), el("td", {}, r.cost_usd ? `$${r.cost_usd.toFixed(2)}` : "—"),
      el("td", { class: "small" }, time(r.started)), el("td", { class: "small muted" }, (r.note || "").slice(0, 120)))));
}

// ------------------------------------------------------------------ live transcript
let liveRun = "latest", liveRunId = null, liveNext = 0;
views.live = async () => {
  const sec = $("#live");
  let data = await api(`/api/runs/${liveRun}/events?after=${liveRunId === null ? 0 : liveNext}`);
  if (!data.run) { fill(sec, el("div", { class: "empty" }, "Aucun run pour l'instant.")); liveRunId = null; return; }
  if (data.run.id !== liveRunId || !sec.querySelector(".feed")) {
    if (liveRunId !== null && data.run.id !== liveRunId) data = await api(`/api/runs/${data.run.id}/events?after=0`);
    liveRunId = data.run.id; liveNext = 0;
    const r = data.run;
    fill(sec,
      el("div", { class: "row" },
        el("b", {}, `Run ${r.id} · ${r.program}`), el("span", { class: "badge", id: "live-status" }, r.status), el("span", { class: "muted small" }, `${r.model} · début ${time(r.started)}`),
        liveRun !== "latest" ? el("button", { class: "btn", onclick: () => { liveRun = "latest"; liveRunId = null; views.live(); } }, "Suivre le dernier") : null,
        el("label", { class: "small muted" }, el("input", { type: "checkbox", id: "autoscroll", checked: true }), " auto-scroll")),
      el("div", { class: "feed" }));
  }
  const st = $("#live-status"); if (st) st.textContent = data.run.status;
  const feed = sec.querySelector(".feed");
  for (const e of data.events) feed.append(renderEvent(e));
  liveNext = data.next;
  if (data.events.length && $("#autoscroll")?.checked) window.scrollTo(0, document.body.scrollHeight);
};
function renderEvent(e) {
  if (e.kind === "text") return el("div", { class: "ev text" }, el("div", { class: "h" }, "agent"), e.body);
  if (e.kind === "tool_use") return el("div", { class: "ev tool_use" }, el("div", { class: "h" }, `⚙ ${e.tool}`), el("pre", {}, e.body));
  if (e.kind === "tool_result") return el("div", { class: `ev tool_result ${e.error ? "err" : ""}` }, el("div", { class: "h" }, e.error ? "résultat (erreur)" : "résultat"), el("pre", {}, e.body));
  return el("div", { class: "ev result" }, el("div", { class: "h" }, `fin · ${e.turns ?? "?"} tours${e.cost ? ` · $${e.cost.toFixed(2)} éq.` : ""}`), e.body);
}

// ------------------------------------------------------------------ findings
views.findings = async () => {
  const f = await api("/api/findings");
  fill($("#findings"), el("h2", {}, "Findings"), f.length ? findingTable(f) : el("div", { class: "empty" }, "Pas encore de finding."));
};
function findingTable(f) {
  return el("table", {}, el("tr", {}, ...["#", "sévérité", "titre", "classe", "programme", "statut", "url"].map((h) => el("th", {}, h))),
    ...f.map((x) => el("tr", { class: "click", onclick: () => openFinding(x.id) },
      el("td", {}, `F${x.id}`), el("td", {}, sev(x.severity)), el("td", {}, x.title), el("td", {}, x.vuln_class || "—"),
      el("td", {}, x.program), el("td", { class: `st-${x.status}` }, x.status), el("td", { class: "mono small" }, x.url || ""))));
}
async function openFinding(id) {
  const f = await api(`/api/findings/${id}`);
  const body = el("div");
  const tabs = { overview: "Vue d'ensemble", verify: "Vérification", poc: "PoC", proof: "Non prouvé", traffic: `Trafic (${f.flows.length})`, triage: "Triage" };
  const pane = el("div");
  const sub = el("div", { class: "subtabs" }, ...Object.entries(tabs).map(([k, v]) => el("button", { "data-k": k, onclick: () => sel(k) }, v)));
  function sel(k) {
    sub.querySelectorAll("button").forEach((b) => b.classList.toggle("on", b.dataset.k === k));
    if (k === "overview") fill(pane, el("dl", {},
      el("dt", {}, "Sévérité"), el("dd", {}, sev(f.severity)), el("dt", {}, "Statut"), el("dd", { class: `st-${f.status}` }, f.status),
      el("dt", {}, "Classe"), el("dd", {}, f.vuln_class || "—"), el("dt", {}, "Programme"), el("dd", {}, f.program),
      el("dt", {}, "URL"), el("dd", { class: "mono" }, f.url || "—"), el("dt", {}, "Créé"), el("dd", {}, time(f.created)),
      el("dt", {}, "Verdict"), el("dd", {}, f.verdict || "—"), el("dt", {}, "Preuve (fichier)"), el("dd", { class: "mono" }, f.evidence || "—")),
      el("h2", {}, "Impact / résumé"), el("pre", {}, f.summary || ""));
    if (k === "verify") {
      let replay = null; try { replay = f.replay ? JSON.parse(f.replay) : null; } catch (e) { replay = null; }
      const steps = (replay?.rounds || []).flatMap((r, i) => r.map((s) => el("tr", {},
        el("td", {}, i + 1), el("td", {}, s.role), el("td", {}, s.name), el("td", {}, s.status ?? "—"),
        el("td", { class: s.ok ? "st-verified" : "st-rejected" }, s.ok ? "ok" : (s.misses || []).join("; ")))));
      fill(pane, el("dl", {}, el("dt", {}, "Statut"), el("dd", { class: `st-${f.status}` }, f.status),
          el("dt", {}, "Verdict"), el("dd", {}, f.verdict || "pas encore vérifié")),
        el("h2", {}, "Rejeu déterministe (2 tours, via le gate)"),
        steps.length ? el("table", {}, el("tr", {}, ...["tour", "rôle", "étape", "statut", "résultat"].map((h) => el("th", {}, h))), ...steps)
          : el("div", { class: "empty" }, "Pas de rejeu."),
        el("h2", {}, "PoC pour le triager (sessions à remplacer)"),
        el("div", { class: "row" }, el("button", { class: "btn", onclick: () => { navigator.clipboard.writeText(f.poc_triager || "").then(() => toast("PoC copiée"), () => toast("copie refusée")); } }, "Copier")),
        el("pre", { style: "max-height:50vh" }, f.poc_triager || "(générée après la vérification)"));
    }
    if (k === "poc") fill(pane, el("div", { class: "row" }, el("button", { class: "btn", onclick: () => { navigator.clipboard.writeText(f.poc || ""); toast("PoC copiée"); } }, "Copier la PoC")),
      el("pre", { style: "max-height:70vh" }, f.poc || "(vide)"));
    if (k === "proof") fill(pane, el("p", { class: "muted small" }, "Ce que l'agent déclare NE PAS avoir prouvé. À lire avant toute soumission."), el("pre", {}, f.not_proven || "(rien déclaré)"));
    if (k === "traffic") fill(pane, f.flows.length ? flowTable(f.flows.slice().reverse()) : el("div", { class: "empty" }, "Aucun flux du gate sur cet hôte."));
    if (k === "triage") {
      const v = el("input", { placeholder: "verdict / note", style: "flex:1", value: f.verdict || "" });
      const act = (s) => el("button", { class: `btn ${s === "verified" || s === "submitted" ? "primary" : ""}`, onclick: async () => {
        await api(`/api/findings/${f.id}/status`, { status: s, verdict: v.value }); toast(`F${f.id} → ${s}`); openFinding(f.id); refresh(); } }, s);
      fill(pane, el("p", { class: "muted small" }, "Relis la PoC, rejoue-la, puis classe le finding."),
        el("div", { class: "row" }, v), el("div", { class: "row" }, ...["verified", "submitted", "inconclusive", "duplicate", "rejected", "new"].map(act)));
    }
  }
  fill(body, el("div", { class: "row" }, sev(f.severity), el("h3", { style: "margin:0" }, `F${f.id} · ${f.title}`)), sub, pane);
  sel("overview");
  drawer(body);
}

// ------------------------------------------------------------------ human todo
const TODO_HELP = {
  auth: "Connecte-toi sur la cible, copie les en-têtes de session (Cookie / Authorization) et enregistre une identité ci-dessous.",
  account: "Crée le compte demandé (2e utilisateur, rôle…) puis enregistre son identité.",
  waf: "Ouvre l'URL dans ton navigateur, passe le challenge, copie le cookie de clearance (cf_clearance…) dans une identité, ou marque l'hôte comme bloqué.",
  "scope-question": "Vérifie sur la page du programme si l'actif est dans le scope. Si oui, ajoute-le au YAML de scope.",
  refusal: "Le modèle a refusé une action. Lis le run, décide : reformuler, faire à la main, ou abandonner.",
  submit: "Finding vérifié : relis la PoC et soumets sur la plateforme.",
};
views.todo = async () => {
  const [open, done] = await Promise.all([api("/api/todos"), api("/api/todos?status=done")]);
  fill($("#todo"), el("h2", {}, "À faire pour que l'agent continue"),
    open.length ? todoTable(open, true) : el("div", { class: "empty" }, "Rien à faire. L'agent n'est pas bloqué."),
    el("h2", {}, "Fait"), done.length ? todoTable(done.slice(0, 20)) : el("div", { class: "empty" }, "—"));
};
function todoTable(t, actions) {
  return el("table", {}, el("tr", {}, ...["#", "type", "programme", "quoi", "depuis", ""].map((h) => el("th", {}, h))),
    ...t.map((x) => el("tr", { class: "click", onclick: () => openTodo(x) },
      el("td", {}, `T${x.id}`), el("td", { class: `k-${x.kind}` }, x.kind), el("td", {}, x.program || "—"), el("td", {}, x.title),
      el("td", { class: "small muted" }, ago(x.created)),
      el("td", {}, actions && x.status === "open" ? el("button", { class: "btn", onclick: async (e) => { e.stopPropagation(); await api(`/api/todos/${x.id}/done`, {}); toast(`T${x.id} fait`); refresh(); } }, "Fait") : ""))));
}
function openTodo(x) {
  const name = el("input", { placeholder: "nom de l'identité (ex: user-c)" });
  const overwrite = el("input", { type: "checkbox" });
  const hdr = el("textarea", { placeholder: "Cookie: session=...\nAuthorization: Bearer ..." });
  const needsIdentity = ["auth", "account", "waf"].includes(x.kind) && x.program;
  drawer(el("h3", {}, `T${x.id} · ${x.title}`), el("p", { class: `k-${x.kind}` }, x.kind),
    el("p", { class: "muted" }, TODO_HELP[x.kind] || ""), x.detail ? el("pre", {}, x.detail) : null,
    needsIdentity ? el("div", {}, el("h2", {}, `Enregistrer une identité pour ${x.program}`),
      el("p", { class: "small muted" }, "Une ligne « En-tête: valeur » par ligne. Stocké côté hôte (var/state/identities, chmod 600), injecté par le gate quand l'agent envoie X-BH-Identity. L'agent ne voit jamais la valeur."),
      el("div", { class: "row" }, name, el("label", { class: "small muted" }, overwrite, " remplacer si elle existe")), hdr,
      el("div", { class: "row" }, el("button", { class: "btn primary", onclick: async () => {
        try { const r = await api("/api/identities", { program: x.program, name: name.value, headers: hdr.value, overwrite: overwrite.checked, todo_id: x.id }); toast(`identité ${r.identity} enregistrée`); $("#drawer").classList.add("hidden"); refresh(); }
        catch (e) { toast(`erreur: ${e.message}`); } } }, "Enregistrer et clore la todo"))) : null,
    x.status === "open" ? el("div", { class: "row" }, el("button", { class: "btn", onclick: async () => { await api(`/api/todos/${x.id}/done`, {}); toast("fait"); $("#drawer").classList.add("hidden"); refresh(); } }, "Marquer comme fait")) : null);
}

// ------------------------------------------------------------------ traffic
let flowGrep = "";
views.traffic = async () => {
  const [flows, events] = await Promise.all([api(`/api/flows?n=300&grep=${encodeURIComponent(flowGrep)}`), api("/api/events?n=100")]);
  const q = el("input", { placeholder: "filtrer l'URL…", value: flowGrep, style: "min-width:320px", onchange: (e) => { flowGrep = e.target.value; views.traffic(); } });
  const blocked = events.filter((e) => e.kind === "blocked");
  fill($("#traffic"), el("div", { class: "row" }, q, el("span", { class: "muted small" }, `${flows.length} requêtes vers les cibles (gate)`)),
    flows.length ? flowTable(flows) : el("div", { class: "empty" }, "Pas encore de trafic."),
    el("h2", {}, `Refusés par le gate (${blocked.length})`),
    blocked.length ? el("table", {}, el("tr", {}, ...["quand", "où", "méthode", "cible", "raison"].map((h) => el("th", {}, h))),
      ...blocked.slice(0, 60).map((e) => el("tr", {}, el("td", { class: "small" }, time(e.ts)), el("td", {}, e.where), el("td", {}, e.method || ""),
        el("td", { class: "mono small" }, e.url || `${e.host} → ${e.ip}`), el("td", { class: "small" }, e.reason + (e.rule ? ` [${e.rule}]` : ""))))) : el("div", { class: "empty" }, "Aucun refus."));
};
function flowTable(flows) {
  return el("table", {}, el("tr", {}, ...["heure", "statut", "méthode", "taille", "url"].map((h) => el("th", {}, h))),
    ...flows.map((f) => el("tr", { class: "click", onclick: () => openFlow(f.id) },
      el("td", { class: "small" }, new Date(f.ts * 1000).toLocaleTimeString("fr-CH")), el("td", {}, f.status), el("td", {}, f.method),
      el("td", { class: "small" }, f.len), el("td", { class: "mono small" }, f.url))));
}
async function openFlow(id) {
  const f = await api(`/api/flows/${encodeURIComponent(id)}`);
  const hdrs = (h) => h.map(([k, v]) => `${k}: ${v}`).join("\n");
  const curl = ["curl -sk -X " + f.method + " '" + f.url.replace(/'/g, "'\\''") + "'",
    ...f.request.headers.filter(([k]) => !/^(host|content-length|connection|accept-encoding)$/i.test(k)).map(([k, v]) => `  -H '${(k + ": " + v).replace(/'/g, "'\\''")}'`),
    f.request.body ? `  --data-raw '${f.request.body.replace(/'/g, "'\\''")}'` : null].filter(Boolean).join(" \\\n");
  drawer(el("h3", {}, `${f.method} ${f.status}`), el("p", { class: "mono small" }, f.url),
    el("div", { class: "row" }, el("button", { class: "btn", onclick: () => { navigator.clipboard.writeText(curl); toast("curl copié"); } }, "Copier en curl")),
    el("h2", {}, "Requête"), el("pre", {}, hdrs(f.request.headers) + (f.request.body ? "\n\n" + f.request.body : "")),
    el("h2", {}, "Réponse"), el("pre", {}, hdrs(f.response.headers) + "\n\n" + f.response.body));
}

// ------------------------------------------------------------------ board
let boardProg = null;
views.board = async () => {
  const progs = await api("/api/programs");
  const names = progs.filter((p) => p.program).map((p) => p.program);
  if (!boardProg) boardProg = status.active_scope?.program || names[0];
  const sel = el("select", { onchange: (e) => { boardProg = e.target.value; views.board(); } }, ...names.map((n) => el("option", { value: n, selected: n === boardProg }, n)));
  if (!boardProg) { fill($("#board"), el("div", { class: "empty" }, "Aucun programme.")); return; }
  const b = await api(`/api/board/${encodeURIComponent(boardProg)}`);
  fill($("#board"), el("div", { class: "row" }, "Programme ", sel, el("span", { class: "muted small" }, `identités: ${b.identities.join(", ") || "aucune"}`)),
    el("div", { class: "two" },
      el("div", {}, el("h2", {}, `Faits (${b.facts.length})`), b.facts.length ? el("table", {}, ...b.facts.map((x) => el("tr", { class: "click", onclick: () => drawer(el("h3", {}, x.title), el("p", { class: "muted" }, `${x.kind} · ${time(x.created)}`), el("pre", {}, x.summary || "(pas de résumé)"), x.evidence ? el("p", { class: "mono small" }, `preuve: ${x.evidence}`) : null) },
        el("td", { class: "small muted" }, x.id), el("td", {}, el("span", { class: "badge" }, x.kind)), el("td", {}, x.title)))) : el("div", { class: "empty" }, "Board vide.")),
      el("div", {}, el("h2", {}, "Intentions"), b.intents.length ? el("table", {}, ...b.intents.map((x) => el("tr", {},
        el("td", {}, `I${x.id}`), el("td", {}, x.status), el("td", {}, x.title, x.outcome ? el("div", { class: "small muted" }, x.outcome) : null)))) : el("div", { class: "empty" }, "—"))));
};

// ------------------------------------------------------------------ metrics (observability)
const usd = (v) => (v == null ? "—" : `$${v.toFixed(2)}`);
const kTok = (v) => (v == null ? "—" : v >= 1000 ? `${(v / 1000).toFixed(1)}k` : String(v));
views.metrics = async () => {
  const m = await api("/api/metrics");
  const kinds = m.tool_kinds || {};
  const total = Object.values(kinds).reduce((a, k) => a + k.n, 0) || 0;
  const share = total ? Math.round(100 * ((kinds.arsenal?.n || 0) / total)) : null;
  fill($("#metrics"),
    el("div", { class: "grid" }, kpi("Coût total (éq. API)", usd(m.cost)), kpi("Findings vérifiés", m.verified),
      kpi("Coût par finding vérifié", usd(m.cost_per_verified)), kpi("Part arsenal des outils", share == null ? "—" : `${share} %`)),
    el("h2", {}, "Runs"),
    el("div", { style: "overflow-x:auto" }, el("table", {},
      el("tr", {}, ...["#", "programme", "statut", "legs·tours", "tokens lus / écrits / sortis", "outils a/m/🔒", "gate req · refus · 429", "findings → vérifiés", "fiches", "coût run + vérif"].map((h) => el("th", {}, h))),
      ...m.runs.map((r) => el("tr", { class: "click", onclick: () => openRunTools(r) },
        el("td", {}, r.id), el("td", {}, r.program), el("td", {}, el("span", { class: "badge" }, r.status)),
        el("td", {}, `${r.turns ?? "—"}`), el("td", { class: "small" }, `${kTok(r.cache_read)} / ${kTok(r.cache_write ?? r.cache_write_turns)} / ${kTok(r.output_tokens)}`),
        el("td", { class: "small" }, r.arsenal_calls == null ? "—" : `${r.arsenal_calls}/${r.manual_calls}/${r.locked_calls}`),
        el("td", { class: "small" }, r.gate_requests == null ? "—" : `${r.gate_requests} · ${r.gate_denied} · ${r.gate_pushback}`),
        el("td", {}, `${r.findings_new} → ${r.findings_verified}`), el("td", { class: "small muted" }, r.cards || "—"),
        el("td", {}, `${usd(r.cost_usd)} + ${usd(r.verify_cost)}`))))));
};
async function openRunTools(r) {
  const calls = await api(`/api/runs/${r.id}/tools`);
  drawer(el("h3", {}, `Run ${r.id} · ${calls.length} appels d'outil`),
    calls.length ? el("table", {}, el("tr", {}, ...["#", "type", "durée", "commande"].map((h) => el("th", {}, h))),
      ...calls.map((t) => el("tr", {}, el("td", {}, t.idx + 1), el("td", {}, t.locked ? "🔒 " + t.kind : t.kind),
        el("td", { class: "small" }, t.ms == null ? "—" : `${(t.ms / 1000).toFixed(1)} s`), el("td", { class: "mono small" }, (t.cmd || "").slice(0, 160)))))
      : el("div", { class: "empty" }, "Pas de détail pour ce run (antérieur aux métriques)."));
}

// ------------------------------------------------------------------ programs + launch
views.programs = async () => {
  const [progs, runs] = await Promise.all([api("/api/programs"), api("/api/runs")]);
  const w = status.worker;
  fill($("#programs"),
    el("div", { class: "row" }, w.run ? el("span", {}, el("i", { class: "dot up" }), `run lancé depuis l'UI (pid ${w.run})`) : el("span", { class: "muted" }, "aucun run lancé depuis l'UI"),
      w.run ? el("button", { class: "btn danger", onclick: async () => { await api("/api/run/stop", {}); toast("arrêt demandé"); refresh(); } }, "Stop") : null),
    el("h2", {}, "Programmes (scopes/)"),
    ...progs.map((p) => p.error ? el("div", { class: "card err" }, `${p.file}: ${p.error}`) : programCard(p, !!w.run)),
    el("h2", {}, "Runs"), runTable(runs));
};
function programCard(p, busy) {
  const minutes = el("input", { type: "number", value: 20, style: "width:80px" });
  const turns = el("input", { type: "number", value: 40, style: "width:80px" });
  const model = el("select", {}, ...["sonnet", "opus", "haiku"].map((m) => el("option", { value: m }, m)));
  const effort = el("select", {}, ...["medium", "low", "high", "xhigh", "max"].map((e) => el("option", { value: e }, `effort ${e}`)));
  const task = el("input", { placeholder: "consigne pour ce segment (optionnel)", style: "flex:1;min-width:240px" });
  const launch = (mode) => async () => {
    try { await api("/api/run", { scope: p.file, mode, minutes: minutes.value, max_turns: turns.value, model: model.value, effort: effort.value, task: task.value, hours: 4 }); toast(`${mode} lancé sur ${p.program}`); liveRun = "latest"; liveRunId = null; setTimeout(refresh, 1500); }
    catch (e) { toast(`erreur: ${e.message}`); }
  };
  return el("div", { class: "card", style: "margin-bottom:10px" },
    el("div", { class: "row" }, el("b", {}, `${p.platform}/${p.program}`), el("span", { class: "muted small mono" }, p.file),
      el("span", { class: "badge" }, `${p.rps ?? "∞"} req/s`), el("span", { class: "badge" }, p.automation === false ? "automation interdite" : p.automation ? "automation OK" : "automation ?"),
      el("span", { class: "muted small" }, `${p.runs} runs · dernier ${ago(p.last_run)}`)),
    el("div", { class: "small" }, el("span", { class: "muted" }, "in: "), p.in_scope.join(", ")),
    p.out_of_scope.length ? el("div", { class: "small" }, el("span", { class: "muted" }, "out: "), p.out_of_scope.join(", ")) : null,
    el("div", { class: "small muted" }, `en-têtes: ${Object.entries(p.headers).map(([k, v]) => `${k}: ${v}`).join(" · ") || "—"} · identités: ${p.identities.join(", ") || "—"}`),
    el("div", { class: "row" }, "minutes", minutes, "tours", turns, model, effort, task,
      el("button", { class: "btn primary", disabled: busy || p.automation === false, onclick: launch("run") }, "Lancer un segment"),
      el("button", { class: "btn", disabled: busy || p.automation === false, onclick: launch("hunt") }, "Hunt 4 h")));
}

// ------------------------------------------------------------------ loop
let busy = false;
async function refresh() {
  if (busy) return; busy = true;
  try { await loadStatus(); await views[current](); } catch (e) { if (e.message !== "401") console.error(e); } finally { busy = false; }
}
window.addEventListener("hashchange", () => { const t = location.hash.slice(1); if (views[t] && t !== current) show(t); });
const start = (location.hash || "#dash").slice(1);
show(views[start] ? start : "dash");
setInterval(() => { if (["dash", "live", "todo", "traffic"].includes(current) && $("#drawer").classList.contains("hidden")) refresh(); else loadStatus().catch(() => {}); }, 3000);
