"""Evaluation plan from the proposal:
 1. attack success rate, clear vs secured (target 0 % when secured)
 2. performance overhead: latency / frame size / throughput
 3. anomaly detector precision, recall, false-positive rate on injected anomalies
Produces results/results.json and PNG plots.
"""
from __future__ import annotations

import json
import os
import statistics
import time
from pathlib import Path
from typing import Callable, Optional

import numpy as np

from . import messages as M
from . import protocol as P
from .anomaly import AnomalyDetector, generate_normal
from .sim import Simulation, shared_detector

RESULTS = Path(__file__).resolve().parent.parent / "results"
ATTACKS = ["eavesdrop", "spoof_command", "replay", "tamper", "downgrade", "spoof_telemetry", "drop"]
ATTACK_LABELS = {
    "eavesdrop": "Eavesdropping (read traffic)", "spoof_command": "Command spoofing (forged cmd)",
    "replay": "Replay of captured command", "tamper": "In-transit bit-flip tampering",
    "downgrade": "Downgrade (inject clear frame)", "spoof_telemetry": "Telemetry spoofing",
    "drop": "Frame dropping (DoS)",
}


# --------------------------------------------------------------------------
def _attack_trials(secure: bool, n: int, progress: Callable[[str], None]) -> dict:
    sim = Simulation(secure=secure, with_detector=False, seed=11)
    out = {a: 0 for a in ATTACKS}
    try:
        sim.wait_for(lambda: sim.ground.link_up, 4)
        sim.command_and_wait(M.OP_PING)
        time.sleep(0.5)
        for i in range(n):
            # eavesdrop: can the attacker read the command just sent?
            sim.attacker.captures.clear()
            sim.command_and_wait(M.OP_SET_MODE, 1)
            caps = [c for c in sim.attacker.snapshot(10)["captures"] if c["hdr"] and c["hdr"]["type"] == "CMD"]
            if caps and caps[-1]["decoded"]["readable"]:
                out["eavesdrop"] += 1

            before = sim.impact_snapshot()["counts"]["spoofed"]
            sim.attacker.forge_command(M.OP_BURN, 1.0)
            sim.wait_for(lambda: sim.impact_snapshot()["counts"]["spoofed"] > before, 0.12)
            if sim.impact_snapshot()["counts"]["spoofed"] > before:
                out["spoof_command"] += 1

            before = sim.impact_snapshot()["counts"]["spoofed"]
            sim.attacker.forge_clear_command(M.OP_BURN, 1.0)
            sim.wait_for(lambda: sim.impact_snapshot()["counts"]["spoofed"] > before, 0.12)
            if sim.impact_snapshot()["counts"]["spoofed"] > before:
                out["downgrade"] += 1

            before = sim.impact_snapshot()["counts"]["replayed"]
            sim.command_and_wait(M.OP_PAYLOAD, i % 2)
            sim.attacker.replay()
            sim.wait_for(lambda: sim.impact_snapshot()["counts"]["replayed"] > before, 0.12)
            if sim.impact_snapshot()["counts"]["replayed"] > before:
                out["replay"] += 1

            before = sim.impact_snapshot()["counts"]["tampered"]
            sim.attacker.arm_tamper(1)
            sim.ground.send_command(M.OP_SET_MODE, 1)
            sim.wait_for(lambda: sim.impact_snapshot()["counts"]["tampered"] > before, 0.12)
            if sim.impact_snapshot()["counts"]["tampered"] > before:
                out["tamper"] += 1
            sim.attacker.arm_tamper(0)

            before = sim.ground.spoofed_accepted
            sim.attacker.forge_telemetry(battery=99.0)
            sim.wait_for(lambda: sim.ground.spoofed_accepted > before, 0.12)
            if sim.ground.spoofed_accepted > before:
                out["spoof_telemetry"] += 1

            sim.attacker.set_drop(up=True)
            cid = sim.ground.send_command(M.OP_PING)
            time.sleep(0.05)
            if cid not in sim.ground.acks:
                out["drop"] += 1
            sim.attacker.set_drop(up=False)
            time.sleep(0.02)
        reasons = sim.log.reasons("satellite")
        reasons_g = sim.log.reasons("ground")
    finally:
        sim.shutdown()
    return dict(counts=out, trials=n, rates={k: 100.0 * v / n for k, v in out.items()},
                sat_rejects=reasons, ground_rejects=reasons_g)


# --------------------------------------------------------------------------
def _perf(progress: Callable[[str], None]) -> dict:
    psk = os.urandom(32)
    g = P.GroundHandshake(1, psk)
    s = P.SatelliteHandshake(1, psk)
    reply, sch = s.respond(g.make_hello())
    gch = g.finish(reply)
    pg, ps = P.PlainChannel(1, "ground"), P.PlainChannel(1, "satellite")

    def bench(tx, rx, size, n=4000):
        pay = os.urandom(size)
        t0 = time.perf_counter()
        for _ in range(n):
            f = tx.protect(P.F_CMD, 0, pay)
            rx.unprotect(f)
        dt = time.perf_counter() - t0
        return dt / n * 1e6, n / dt, n * size / dt / 1e6

    res = {}
    for size in (16, 64, 256, 1024):
        lp, fp, mp = bench(pg, ps, size)
        ls, fs, ms = bench(gch, sch, size)
        res[size] = dict(plain_us=lp, secure_us=ls, plain_fps=fp, secure_fps=fs, plain_mbps=mp,
                         secure_mbps=ms, added_us=ls - lp,
                         plain_bytes=P.HEADER_LEN + size, secure_bytes=P.HEADER_LEN + size + P.TAG_LEN,
                         overhead_pct=100.0 * P.TAG_LEN / (P.HEADER_LEN + size))
    # end-to-end command round-trip over loopback UDP (ground -> attacker -> sat -> attacker -> ground)
    rtt = {}
    for secure in (False, True):
        sim = Simulation(secure=secure, with_detector=False, seed=5)
        try:
            sim.wait_for(lambda: sim.ground.link_up, 4)
            sim.command_and_wait(M.OP_PING)
            xs = []
            for _ in range(150):
                t0 = time.perf_counter()
                cid = sim.ground.send_command(M.OP_PING)
                while cid not in sim.ground.acks and time.perf_counter() - t0 < 1:
                    time.sleep(0.0002)
                xs.append((time.perf_counter() - t0) * 1e3)
            rtt["secure" if secure else "plain"] = dict(median_ms=statistics.median(xs),
                                                         p95_ms=float(np.percentile(xs, 95)))
        finally:
            sim.shutdown()
    # handshake cost
    t0 = time.perf_counter()
    for _ in range(50):
        gh = P.GroundHandshake(1, psk)
        sh = P.SatelliteHandshake(1, psk)
        r, _c = sh.respond(gh.make_hello())
        gh.finish(r)
    hs_ms = (time.perf_counter() - t0) / 50 * 1e3
    return dict(sizes=res, rtt=rtt, handshake_ms=hs_ms, header_bytes=P.HEADER_LEN, tag_bytes=P.TAG_LEN)


# --------------------------------------------------------------------------
def _alerts(flags: np.ndarray) -> list:
    out, start = [], None
    for i, f in enumerate(flags):
        if f and start is None:
            start = i
        if not f and start is not None:
            out.append((start, i - 1))
            start = None
    if start is not None:
        out.append((start, len(flags) - 1))
    return out


def _anomaly_eval(progress: Callable[[str], None], seed: int = 1234) -> dict:
    det = shared_detector()
    n = 6000
    rng = np.random.default_rng(seed)
    kinds = ["battery_drop", "temp_spike", "tumble", "flood"]
    spots = sorted(rng.choice(np.arange(200, n - 60, 120), size=36, replace=False))
    inject = [(int(s), kinds[i % 4]) for i, s in enumerate(spots)]
    X, y = generate_normal(n, seed=seed, anomalies=inject)
    flags, scores = det.predict(X)
    flags, scores = flags[30:], scores[30:]
    y = y[30:]
    inject = [(i - 30, k) for i, k in inject]
    per_kind = {}
    for k in kinds:
        evs = [i for i, kk in inject if kk == k]
        hit = sum(1 for i in evs if flags[i:i + (20 if k == "flood" else 14)].any())
        per_kind[k] = dict(events=len(evs), detected=hit, recall=100.0 * hit / max(len(evs), 1))
    tp = int(((flags == 1) & (y == 1)).sum())
    fp = int(((flags == 1) & (y == 0)).sum())
    fn = int(((flags == 0) & (y == 1)).sum())
    tn = int(((flags == 0) & (y == 0)).sum())
    alerts = _alerts(flags)
    good_alerts = sum(1 for a, b in alerts if y[a:b + 1].any())
    ev_hit = sum(v["detected"] for v in per_kind.values())
    ev_all = sum(v["events"] for v in per_kind.values())
    return dict(
        samples=len(y), injected_events=ev_all, events_detected=ev_hit,
        event_recall=100.0 * ev_hit / max(ev_all, 1),
        alert_precision=100.0 * good_alerts / max(len(alerts), 1), alerts=len(alerts),
        sample_precision=100.0 * tp / max(tp + fp, 1), sample_recall=100.0 * tp / max(tp + fn, 1),
        false_positive_rate=100.0 * fp / max(fp + tn, 1), confusion=dict(tp=tp, fp=fp, fn=fn, tn=tn),
        per_kind=per_kind,
        trace=dict(score=[float(x) for x in scores[:1500]], label=[int(x) for x in y[:1500]],
                   flag=[int(x) for x in flags[:1500]]),
    )


# --------------------------------------------------------------------------
def make_plots(res: dict) -> list:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    RESULTS.mkdir(exist_ok=True)
    files = []
    bg, fg, grid = "#0b1220", "#d8e2f0", "#26334a"

    def style(ax):
        ax.set_facecolor(bg)
        for sp in ax.spines.values():
            sp.set_color(grid)
        ax.tick_params(colors=fg)
        ax.yaxis.label.set_color(fg)
        ax.xaxis.label.set_color(fg)
        ax.title.set_color(fg)
        ax.grid(color=grid, alpha=.6, lw=.6)
        ax.set_axisbelow(True)

    # attack success
    a = res["attacks"]
    fig, ax = plt.subplots(figsize=(9, 4.6), facecolor=bg)
    x = np.arange(len(ATTACKS))
    ax.bar(x - .2, [a["clear"]["rates"][k] for k in ATTACKS], .4, label="Clear link", color="#ff5d6c")
    ax.bar(x + .2, [a["secured"]["rates"][k] for k in ATTACKS], .4, label="OrbitLock secured", color="#35d49a")
    ax.set_xticks(x)
    ax.set_xticklabels([ATTACK_LABELS[k].split(" (")[0].replace(" ", "\n", 1) for k in ATTACKS], fontsize=8)
    ax.set_ylabel("Attack success rate (%)")
    ax.set_title("Attack success: clear vs secured")
    ax.set_ylim(0, 108)
    ax.legend(facecolor=bg, labelcolor=fg, edgecolor=grid)
    style(ax)
    fig.tight_layout()
    fn = RESULTS / "attack_success.png"
    fig.savefig(fn, dpi=130)
    plt.close(fig)
    files.append(fn.name)

    # overhead
    p = res["performance"]
    sizes = sorted(p["sizes"], key=int)
    fig, axs = plt.subplots(1, 3, figsize=(12, 3.8), facecolor=bg)
    xx = np.arange(len(sizes))
    axs[0].bar(xx - .2, [p["sizes"][s]["plain_us"] for s in sizes], .4, color="#6aa6ff", label="Clear")
    axs[0].bar(xx + .2, [p["sizes"][s]["secure_us"] for s in sizes], .4, color="#35d49a", label="Secured")
    axs[0].set_title("Latency per frame (protect+verify, µs)")
    axs[1].bar(xx - .2, [p["sizes"][s]["plain_bytes"] for s in sizes], .4, color="#6aa6ff")
    axs[1].bar(xx + .2, [p["sizes"][s]["secure_bytes"] for s in sizes], .4, color="#35d49a")
    axs[1].set_title("Frame size (bytes)")
    axs[2].bar(xx - .2, [p["sizes"][s]["plain_mbps"] for s in sizes], .4, color="#6aa6ff")
    axs[2].bar(xx + .2, [p["sizes"][s]["secure_mbps"] for s in sizes], .4, color="#35d49a")
    axs[2].set_title("Throughput (MB/s)")
    for ax in axs:
        ax.set_xticks(xx)
        ax.set_xticklabels([f"{s} B" for s in sizes])
        style(ax)
    axs[0].legend(facecolor=bg, labelcolor=fg, edgecolor=grid)
    fig.tight_layout()
    fn = RESULTS / "overhead.png"
    fig.savefig(fn, dpi=130)
    plt.close(fig)
    files.append(fn.name)

    # anomaly
    an = res["anomaly"]
    t = an["trace"]
    fig, ax = plt.subplots(figsize=(11, 3.8), facecolor=bg)
    sc = np.array(t["score"])
    ax.plot(sc, color="#6aa6ff", lw=.8, label="anomaly score")
    ax.axhline(0, color="#ffb454", lw=1, ls="--", label="decision threshold")
    lab = np.array(t["label"])
    ax.fill_between(np.arange(len(sc)), sc.min(), sc.max(), where=lab == 1, color="#ff5d6c", alpha=.25, label="injected anomaly")
    fl = np.where(np.array(t["flag"]) == 1)[0]
    ax.scatter(fl, sc[fl], s=10, color="#ff5d6c", zorder=3, label="flagged")
    ax.set_title("Isolation Forest score on test telemetry with injected anomalies")
    ax.set_xlabel("telemetry sample (2 Hz)")
    ax.legend(facecolor=bg, labelcolor=fg, edgecolor=grid, ncol=4, fontsize=8)
    style(ax)
    fig.tight_layout()
    fn = RESULTS / "anomaly.png"
    fig.savefig(fn, dpi=130)
    plt.close(fig)
    files.append(fn.name)
    return files


def run_all(trials: int = 25, progress: Optional[Callable[[str], None]] = None) -> dict:
    progress = progress or (lambda m: print(m, flush=True))
    res = {"generated": time.strftime("%Y-%m-%d %H:%M:%S")}
    progress("Training / loading anomaly model…")
    shared_detector()
    progress("Running attacks against the clear link…")
    clear = _attack_trials(False, trials, progress)
    progress("Running attacks against the secured link…")
    secured = _attack_trials(True, trials, progress)
    res["attacks"] = dict(clear=clear, secured=secured, labels=ATTACK_LABELS)
    progress("Measuring protocol overhead…")
    res["performance"] = _perf(progress)
    progress("Evaluating anomaly detector…")
    res["anomaly"] = _anomaly_eval(progress)
    progress("Rendering plots…")
    res["plots"] = make_plots(res)
    RESULTS.mkdir(exist_ok=True)
    (RESULTS / "results.json").write_text(json.dumps(res, indent=1))
    from .report import write_report
    write_report(res)
    progress("Done.")
    return res


if __name__ == "__main__":
    r = run_all()
    print(json.dumps({k: r["attacks"][k]["rates"] for k in ("clear", "secured")}, indent=1))
    print(json.dumps({k: v for k, v in r["anomaly"].items() if k != "trace"}, indent=1))
    print(json.dumps(r["performance"]["rtt"], indent=1), r["performance"]["handshake_ms"])
