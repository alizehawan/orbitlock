"use strict";
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const api = (url, body) => fetch(url, body === undefined ? {} : {
  method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body)
}).then(r => r.json().catch(() => ({}))).catch(() => ({ ok: false }));

let S = null, switching = false, toastTimer = null;

/* ---------- tabs ---------- */
$$(".tab").forEach(b => b.onclick = () => {
  $$(".tab").forEach(x => x.classList.toggle("active", x === b));
  $$(".tabpane").forEach(p => p.classList.toggle("hidden", p.id !== "tab-" + b.dataset.tab));
  if (b.dataset.tab === "eval") loadResults();
});

/* ---------- link mode ---------- */
$$("#modeSeg button").forEach(b => b.onclick = async () => {
  const want = b.dataset.secure === "1";
  if (S && S.secure === want) return;
  switching = true; setPill("wait", want ? "negotiating X25519 session…" : "switching…");
  await api("/api/secure", { secure: want });
  switching = false; poll();
});

/* ---------- commands ---------- */
$$("[data-cmd]").forEach(b => b.onclick = async () => {
  const c = b.dataset.cmd, body = { cmd: c };
  if (c === "mode") body.mode = $("#modeSel").value;
  if (c === "attitude") Object.assign(body, { roll: $("#aRoll").value, pitch: $("#aPitch").value, yaw: $("#aYaw").value });
  if (c === "payload") body.on = b.dataset.on === "1";
  if (c === "downlink") body.kb = $("#dlKb").value;
  if (c === "burn") body.dv = $("#burnDv").value;
  const r = await api("/api/command", body);
  if (!r.ok) toast(r.error || "command failed");
  poll();
});
$("#btnRotate").onclick = async () => { const r = await api("/api/link", { action: "rotate" }); toast(r.ok ? "Keys rotated" : "Rotation needs an established secured link"); poll(); };
$("#btnRekey").onclick = async () => { toast("Emergency rekey: REKEY command + fresh handshake…"); const r = await api("/api/link", { action: "rekey" }); toast(r.ok ? "Fresh session established" : "Rekey failed (secured link required)"); poll(); };
$("#autoRot").onchange = e => api("/api/link", { action: "auto", on: e.target.checked });
$$("[data-fault]").forEach(b => b.onclick = () => api("/api/fault", { kind: b.dataset.fault }));

/* ---------- attacks ---------- */
$$("[data-attack]").forEach(b => b.onclick = async () => {
  const r = await api("/api/attack", { type: b.dataset.attack, op: b.dataset.op });
  if (r.ok === false) toast(r.error || "attack failed");
  poll();
});
$("#btnDrop").onclick = () => api("/api/attack", { type: "drop", up: !S.attacker.drop.up, down: false }).then(poll);
$("#btnFlood").onclick = () => api("/api/attack", { type: "flood", on: !S.attacker.flooding }).then(poll);

function toast(msg) {
  const b = $("#banner"); b.className = "banner info"; b.textContent = msg;
  clearTimeout(toastTimer); toastTimer = setTimeout(() => { if (b.classList.contains("info")) b.classList.add("hidden"); }, 3500);
}

/* ---------- polling ---------- */
async function poll() {
  if (switching) return;
  try { S = await (await fetch("/api/state")).json(); } catch { setPill("down", "console offline"); return; }
  render(S);
}
setInterval(poll, 500); poll();

function setPill(cls, text) { const p = $("#linkPill"); p.className = "pill " + cls; $("span", p).textContent = text; }

function render(s) {
  $$("#modeSeg button").forEach(b => b.classList.toggle("on", (b.dataset.secure === "1") === s.secure));
  const L = s.link;
  if (L.handshaking) setPill("wait", "handshake in progress…");
  else if (!L.up) setPill("down", "link down");
  else if (s.secure) setPill("up", `AES-256-GCM · epoch ${L.epoch} · seq ${L.tx_seq}`);
  else setPill("down", "UNPROTECTED · cleartext frames");
  $("#btnRotate").disabled = $("#btnRekey").disabled = !s.secure || !L.up;

  renderTiles(s); renderCharts(s); renderEvents(s); renderCmdLog(s);
  renderAttack(s); renderAnomaly(s);

  const b = $("#banner");
  const rec = s.detector && s.detector.recent.length ? s.detector.recent[s.detector.recent.length - 1] : null;
  if (rec && s.now - rec.t < 5) { b.className = "banner anom"; b.textContent = "⚠ Telemetry anomaly detected: " + rec.reason; }
  else if (b.classList.contains("anom")) b.classList.add("hidden");
}

function tile(k, v, sub, extra = "", cls = "") { return `<div class="tile ${cls}"><div class="k">${k}</div><div class="v">${v}</div><div class="s">${sub}</div>${extra}</div>`; }

function renderTiles(s) {
  const t = s.latest, sat = s.satellite;
  if (!t) { $("#tiles").innerHTML = tile("Telemetry", "—", s.secure ? "waiting for secured session" : "waiting for downlink"); return; }
  const age = s.link.last_tlm_age;
  const stale = age !== null && age > 3;
  const modes = ["SAFE", "NOMINAL", "SCIENCE", "COMMS"];
  const bat = t.battery;
  $("#tiles").innerHTML =
    tile("Mode", modes[t.mode] ?? "?", t.payload_on ? "payload ON" : "payload off", "", t.spoofed ? "spoof" : "") +
    tile("Battery", bat.toFixed(1) + "%", sat.sunlit ? "☀ sunlit · charging" : "● eclipse", `<div class="bar"><div style="width:${bat}%;background:${bat < 25 ? "var(--bad)" : bat < 50 ? "var(--warn)" : "var(--good)"}"></div></div>`, t.anomaly ? "warn" : "") +
    tile("Temperature", t.temp.toFixed(1) + " °C", "bus sensor", "", t.temp > 50 ? "warn" : "") +
    tile("Attitude", `${t.roll.toFixed(0)}° ${t.pitch.toFixed(0)}° ${t.yaw.toFixed(0)}°`, "roll · pitch · yaw") +
    tile("Altitude", t.alt.toFixed(1) + " km", `Δv total ${t.dv.toFixed(1)} m/s`) +
    tile("Position", `<span style="font-size:17px">${t.lat.toFixed(1)}°, ${t.lon.toFixed(1)}°</span>`, "lat, lon") +
    tile("Downlink", stale ? "STALE" : "LIVE", `${age === null ? "–" : age.toFixed(1) + " s ago"} · ${s.data_kb.toFixed(0)} kB bulk`, "", stale ? "warn" : "") +
    tile("Satellite rx", sat.rx_frames, `${sat.rx_rejects} rejected`, "", "");
}

/* ---------- charts ---------- */
function fit(c) { const dpr = window.devicePixelRatio || 1, w = c.clientWidth, h = c.getAttribute("height") | 0; if (c.width !== w * dpr) { c.width = w * dpr; c.height = h * dpr; } const x = c.getContext("2d"); x.setTransform(dpr, 0, 0, dpr, 0, 0); return [x, w, h]; }

function lineChart(c, series, marks) {
  const [x, w, h] = fit(c); x.clearRect(0, 0, w, h);
  const pad = { l: 34, r: 8, t: 8, b: 14 };
  x.strokeStyle = "#1a2640"; x.lineWidth = 1; x.font = "10px ui-monospace,monospace"; x.fillStyle = "#6f82a3";
  const n = Math.max(...series.map(s => s.data.length));
  if (n < 2) { x.fillText("waiting for data…", 12, h / 2); return; }
  const all = series.flatMap(s => s.data); let lo = Math.min(...all), hi = Math.max(...all);
  if (series[0].fixed) { lo = series[0].fixed[0]; hi = series[0].fixed[1]; }
  if (hi - lo < 1) { hi += .5; lo -= .5; }
  const px = i => pad.l + (w - pad.l - pad.r) * i / Math.max(n - 1, 1), py = v => pad.t + (h - pad.t - pad.b) * (1 - (v - lo) / (hi - lo));
  for (let i = 0; i <= 3; i++) { const v = lo + (hi - lo) * i / 3, yy = py(v); x.beginPath(); x.moveTo(pad.l, yy); x.lineTo(w - pad.r, yy); x.stroke(); x.fillText(v.toFixed(0), 3, yy + 3); }
  if (marks) marks.forEach((m, i) => { if (m.anomaly) { x.fillStyle = "rgba(255,93,108,.22)"; x.fillRect(px(i) - 2, pad.t, 4, h - pad.t - pad.b); } if (m.spoofed) { x.fillStyle = "rgba(255,180,84,.3)"; x.fillRect(px(i) - 2, pad.t, 4, h - pad.t - pad.b); } });
  series.forEach(s => { x.strokeStyle = s.color; x.lineWidth = 1.6; x.beginPath(); s.data.forEach((v, i) => { const X = px(i + n - s.data.length), Y = py(v); i ? x.lineTo(X, Y) : x.moveTo(X, Y); }); x.stroke(); });
}

function renderCharts(s) {
  const H = s.history;
  lineChart($("#chBatt"), [{ data: H.map(h => h.battery), color: "#35d49a" }, { data: H.map(h => h.temp), color: "#ffb454" }], H);
  lineChart($("#chAtt"), [{ data: H.map(h => h.roll), color: "#6aa6ff" }, { data: H.map(h => h.pitch), color: "#a78bfa" }, { data: H.map(h => h.yaw), color: "#f472b6" }], H);
  drawMap(s);
  $("#tlmMeta").textContent = H.length ? `${H.length} samples · ${s.secure ? "authenticated" : "UNAUTHENTICATED"}` : "";
}

function drawMap(s) {
  const c = $("#map"), [x, w, h] = fit(c); x.clearRect(0, 0, w, h);
  x.strokeStyle = "#16233d"; x.lineWidth = 1; x.fillStyle = "#4e6285"; x.font = "10px ui-monospace,monospace";
  for (let lon = -180; lon <= 180; lon += 30) { const X = (lon + 180) / 360 * w; x.beginPath(); x.moveTo(X, 0); x.lineTo(X, h); x.stroke(); if (lon > -180 && lon < 180) x.fillText(lon + "°", X + 2, h - 3); }
  for (let lat = -60; lat <= 60; lat += 30) { const Y = (90 - lat) / 180 * h; x.beginPath(); x.moveTo(0, Y); x.lineTo(w, Y); x.stroke(); x.fillText(lat + "°", 3, Y - 2); }
  const pts = s.history.map(p => [(p.lon + 180) / 360 * w, (90 - p.lat) / 180 * h]);
  x.strokeStyle = "rgba(90,162,255,.7)"; x.lineWidth = 1.5; x.beginPath();
  pts.forEach((p, i) => { if (i && Math.abs(p[0] - pts[i - 1][0]) > w / 2) x.moveTo(p[0], p[1]); else i ? x.lineTo(p[0], p[1]) : x.moveTo(p[0], p[1]); }); x.stroke();
  if (pts.length) { const p = pts[pts.length - 1]; x.fillStyle = "rgba(90,162,255,.25)"; x.beginPath(); x.arc(p[0], p[1], 11, 0, 7); x.fill(); x.fillStyle = "#cfe3ff"; x.beginPath(); x.arc(p[0], p[1], 4, 0, 7); x.fill(); }
}

/* ---------- events / commands ---------- */
const hhmmss = ts => new Date(ts * 1000).toLocaleTimeString([], { hour12: false });

function renderEvents(s) {
  const chips = [];
  for (const [node, m] of Object.entries(s.reject_totals)) for (const [r, n] of Object.entries(m)) chips.push(`<span class="chip">${node}: ${r.replace(/_/g, " ")} <b>${n}</b></span>`);
  $("#rejChips").innerHTML = chips.join("") || `<span class="chip">no frames rejected</span>`;
  const ev = [...s.events].reverse();
  $("#events").innerHTML = ev.length ? ev.map(e => `<li class="${e.kind}"><span class="t">${hhmmss(e.ts)}</span> <span class="t">${e.node}</span>
      <span class="r">${e.kind === "reject" ? "REJECT · " + esc(e.reason) : esc(e.reason)}</span>${e.count > 1 ? `<span class="x">×${e.count}</span>` : ""}
      ${e.seq != null ? `<span class="t"> seq=${e.seq} ep=${e.epoch ?? "–"}</span>` : ""}<div class="d">${esc(e.text)}</div></li>`).join("")
    : `<li class="empty">No security events yet. Launch an attack from the toolkit and watch the secured link reject it.</li>`;
}

function renderCmdLog(s) {
  $("#cmdLog").innerHTML = [...s.commands].reverse().map(c => `<li><span>#${c.cmd_id} ${esc(c.text)}</span><span class="st-${c.status}">${c.status}</span></li>`).join("") || `<li class="muted">none yet</li>`;
}

/* ---------- attacker ---------- */
function renderAttack(s) {
  const A = s.attacker;
  $("#btnTamper").classList.toggle("active", A.tamper_armed > 0);
  $("#btnTamper").textContent = A.tamper_armed > 0 ? "Bit-flip ARMED (next cmd)" : "Arm bit-flip";
  $("#btnDrop").classList.toggle("active", A.drop.up);
  $("#btnDrop").textContent = A.drop.up ? "Dropping uplink…" : "Drop uplink";
  $("#btnFlood").classList.toggle("active", A.flooding);
  $("#btnFlood").textContent = A.flooding ? "Flooding…" : "Frame flood";

  const c = s.impact.counts;
  const items = [["Spoofed cmds executed", c.spoofed], ["Replayed cmds executed", c.replayed], ["Tampered cmds executed", c.tampered], ["Spoofed telemetry accepted", s.spoofed_accepted]];
  const attempts = A.stats.forged + A.stats.replayed + A.stats.tampered;
  $("#impact").innerHTML = items.map(([l, n]) => `<div class="imp ${n > 0 ? "hit" : (attempts && s.secure ? "safe" : "")}"><div class="n">${n}</div><div class="l">${l}</div></div>`).join("");

  const rows = [...A.captures].reverse().slice(0, 16).map(p => {
    const d = p.decoded || {};
    return `<tr><td class="${p.dir === "up" ? "up-a" : "down-a"}">${p.dir === "up" ? "▲ up" : "▼ dn"}</td><td>${p.hdr ? p.hdr.type : "?"}</td><td>${p.hdr ? p.hdr.seq : ""}</td><td>${p.hdr ? p.hdr.epoch : ""}</td><td>${p.len}</td>
      <td class="dec ${d.readable ? "plain" : "cipher"}">${esc(d.text)}${p.status !== "relayed" ? ` <span class="tag-t">[${p.status}]</span>` : ""}</td></tr>`;
  }).join("");
  $("#wire tbody").innerHTML = rows || `<tr><td colspan="6" class="muted">no traffic captured</td></tr>`;
}

/* ---------- anomaly ---------- */
function renderAnomaly(s) {
  const d = s.detector; if (!d) { $("#anom").innerHTML = '<div class="empty">detector disabled</div>'; return; }
  const pct = Math.max(0, Math.min(100, (d.score + 0.2) / 0.6 * 100));
  $("#anom").innerHTML = `
    <div class="big"><div><div class="n">${d.flagged}</div><div class="muted">samples flagged</div></div><div><div class="n">${d.total}</div><div class="muted">samples scored</div></div></div>
    <div class="muted">anomaly score ${d.score.toFixed(3)} (flag &gt; 0)</div><div class="meter"><div style="width:${pct}%"></div></div>
    ${d.recent.length ? d.recent.slice().reverse().map(r => `<div class="alert"><span class="muted">${hhmmss(r.t)}</span> ${esc(r.reason)}</div>`).join("") : '<div class="empty">No anomalies. Inject a fault or start a frame flood.</div>'}
    <p class="muted" style="font-size:11.5px;margin-top:12px">Model: ${esc(d.info.model || "")}, trained on ${d.info.samples || 0} normal samples. Features: ${(d.info.features || []).join(", ")}.</p>`;
}

/* ---------- evaluation tab ---------- */
let evalTimer = null;
$("#btnEval").onclick = async () => {
  const r = await api("/api/evaluate", {});
  if (r.ok === false && r.error !== "already running") return;
  $("#btnEval").disabled = true;
  evalTimer = setInterval(async () => {
    const st = await (await fetch("/api/evaluate/status")).json();
    $("#evalMsg").textContent = st.error ? "Error: " + st.error : (st.msgs[st.msgs.length - 1] || "starting…");
    if (!st.running) { clearInterval(evalTimer); $("#btnEval").disabled = false; loadResults(); }
  }, 800);
};

const rate = (v, bad) => `<div class="rbar"><div class="b"><div style="width:${v}%;background:${bad ? "var(--bad)" : "var(--good)"}"></div></div><b class="${bad ? "bad" : "good"}">${v.toFixed(0)}%</b></div>`;

async function loadResults() {
  const r = await (await fetch("/api/results")).json();
  if (!r.available) { $("#evalBody").innerHTML = '<div class="card empty">No results yet — press “Run evaluation”.</div>'; return; }
  const A = r.attacks, P = r.performance, N = r.anomaly;
  const rows = Object.keys(A.labels).map(k => `<tr><td>${esc(A.labels[k])}</td><td style="width:26%">${rate(A.clear.rates[k], A.clear.rates[k] > 0)}</td><td style="width:26%">${rate(A.secured.rates[k], A.secured.rates[k] > 0)}</td></tr>`).join("");
  const sizes = Object.keys(P.sizes).sort((a, b) => a - b);
  const prow = sizes.map(z => { const p = P.sizes[z]; return `<tr><td>${z} B</td><td>${p.plain_us.toFixed(1)} → ${p.secure_us.toFixed(1)} µs <span class="muted">(+${p.added_us.toFixed(1)})</span></td><td>${p.plain_bytes} → ${p.secure_bytes} B <span class="muted">(+${p.overhead_pct.toFixed(0)}%)</span></td><td>${p.plain_mbps.toFixed(1)} → ${p.secure_mbps.toFixed(1)} MB/s</td></tr>`; }).join("");
  const kinds = Object.entries(N.per_kind).map(([k, v]) => `<tr><td>${k.replace("_", " ")}</td><td>${v.detected}/${v.events}</td><td>${v.recall.toFixed(0)}%</td></tr>`).join("");
  $("#evalBody").innerHTML = `
  <div class="kpis">
    <div class="kpi"><div class="n good">${Math.max(...["eavesdrop", "spoof_command", "replay", "tamper", "downgrade", "spoof_telemetry"].map(k => A.secured.rates[k])).toFixed(0)}%</div><div class="l">worst-case integrity/confidentiality attack success, secured (${A.secured.trials} trials each)</div></div>
    <div class="kpi"><div class="n">${P.header_bytes + P.tag_bytes - P.header_bytes} B</div><div class="l">per-frame security overhead (GCM tag; header is shared)</div></div>
    <div class="kpi"><div class="n">${(P.rtt.secure.median_ms - P.rtt.plain.median_ms).toFixed(2)} ms</div><div class="l">added median command round-trip (${P.rtt.plain.median_ms.toFixed(2)} → ${P.rtt.secure.median_ms.toFixed(2)} ms)</div></div>
    <div class="kpi"><div class="n">${P.handshake_ms.toFixed(2)} ms</div><div class="l">full X25519 + HKDF handshake (both sides)</div></div>
    <div class="kpi"><div class="n">${N.event_recall.toFixed(0)}%</div><div class="l">anomaly events detected (${N.events_detected}/${N.injected_events})</div></div>
    <div class="kpi"><div class="n">${N.false_positive_rate.toFixed(2)}%</div><div class="l">false-positive rate (per sample)</div></div>
  </div>
  <div class="evgrid">
    <div class="card"><h2>Attack success rate</h2><table><thead><tr><th>Attack</th><th>Clear link</th><th>OrbitLock</th></tr></thead><tbody>${rows}</tbody></table>
      <p class="muted" style="font-size:12px">Dropping frames is an availability attack: no cryptographic protocol can stop an on-path node from discarding packets, but the secured link makes the loss detectable (missing ACKs, sequence gaps).</p></div>
    <div class="card"><img class="evimg" src="/results/attack_success.png?${Date.now()}" alt="attack success plot"></div>
  </div>
  <div class="evgrid">
    <div class="card"><h2>Protocol overhead (clear → secured)</h2><table><thead><tr><th>Payload</th><th>Latency / frame</th><th>Frame size</th><th>Throughput</th></tr></thead><tbody>${prow}</tbody></table>
      <p class="muted" style="font-size:12px">Latency = protect + verify in-process. End-to-end command RTT over loopback UDP (median / p95): clear ${P.rtt.plain.median_ms.toFixed(2)} / ${P.rtt.plain.p95_ms.toFixed(2)} ms, secured ${P.rtt.secure.median_ms.toFixed(2)} / ${P.rtt.secure.p95_ms.toFixed(2)} ms.</p></div>
    <div class="card"><img class="evimg" src="/results/overhead.png?${Date.now()}" alt="overhead plot"></div>
  </div>
  <div class="evgrid">
    <div class="card"><h2>Anomaly detector</h2>
      <div class="kpis"><div class="kpi"><div class="n">${N.alert_precision.toFixed(0)}%</div><div class="l">alert precision (${N.alerts} alerts)</div></div><div class="kpi"><div class="n">${N.sample_precision.toFixed(0)}%</div><div class="l">sample precision</div></div><div class="kpi"><div class="n">${N.sample_recall.toFixed(0)}%</div><div class="l">sample recall</div></div></div>
      <table><thead><tr><th>Injected anomaly</th><th>Detected</th><th>Recall</th></tr></thead><tbody>${kinds}</tbody></table>
      <p class="muted" style="font-size:12px">${N.samples} test samples; confusion TP ${N.confusion.tp} · FP ${N.confusion.fp} · FN ${N.confusion.fn} · TN ${N.confusion.tn}. Event recall counts an injected anomaly as detected if any sample in its window is flagged.</p></div>
    <div class="card"><img class="evimg" src="/results/anomaly.png?${Date.now()}" alt="anomaly plot"></div>
  </div>
  <p class="muted">Generated ${esc(r.generated)} · <a href="/results/security_analysis.md" target="_blank">Comparative security analysis (written report)</a></p>`;
}
