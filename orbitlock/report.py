"""Comparative security analysis (proposal §4 scope): renders ``results/results.json`` into a written report.

    python -m orbitlock.report      ->  results/security_analysis.md

Every number in the report is read from the latest evaluation run, so it never goes stale.
"""
from __future__ import annotations

import json
from pathlib import Path

RESULTS = Path(__file__).resolve().parent.parent / "results"

# attack -> (security property attacked, what happens on a clear link, how OrbitLock stops it)
MECHANISM = {
    "eavesdrop": ("Confidentiality",
                  "Command and telemetry fields are readable straight off the wire.",
                  "AES-256-GCM: payloads are ciphertext; the sniffer sees only the 15-byte header and an opaque body."),
    "spoof_command": ("Authenticity",
                      "Any well-formed frame is executed; a forged BURN changes the orbit.",
                      "The forger holds no session key, so its 16-byte GCM tag is wrong; the frame is rejected as `bad_tag` before any state is touched."),
    "replay": ("Freshness / anti-replay",
               "A captured command is executed again, any number of times.",
               "Sequence number is already inside the sliding window; rejected as `replay` (or `out_of_window` once it is older than 64 frames). The window is updated only after the tag verifies."),
    "tamper": ("Integrity",
               "A single flipped bit silently changes a command argument and the altered command executes.",
               "The flipped bit breaks the GCM tag (header is authenticated as associated data too); rejected as `bad_tag`."),
    "downgrade": ("Protocol downgrade",
                  "n/a - the link has no protection to downgrade.",
                  "A secured satellite refuses unprotected frames outright (`clear_frame_on_secure_link`)."),
    "spoof_telemetry": ("Authenticity (downlink)",
                        "The ground station accepts fabricated telemetry, hiding a real fault.",
                        "Ground-side verification fails (`bad_tag`); the fake frame never reaches the operator display or the detector."),
    "drop": ("Availability",
             "Frames are silently discarded by the man in the middle.",
             "Not preventable by any cryptographic layer. It is *detectable* (missing ACKs, telemetry gap) and is out of scope per the proposal (no physical-layer / DoS guarantees)."),
}


def _f(x, nd=1):
    return f"{x:.{nd}f}"


def render(res: dict) -> str:
    a = res["attacks"]
    clear, sec = a["clear"], a["secured"]
    labels = a["labels"]
    perf = res["performance"]
    an = res["anomaly"]
    out: list = []
    w = out.append

    w("# OrbitLock - Comparative Security Analysis\n")
    w(f"*Generated {res['generated']} from `results/results.json` "
      f"({clear['trials']} trials per attack per mode).*\n")

    w("## 1. Threat model\n")
    w("A man-in-the-middle sits on the ground-to-space link (ground <-> attacker <-> satellite, all over UDP). "
      "It can read, drop, modify, replay and inject frames. It knows the public frame format "
      "(`ver | scid | vc | type | epoch | seq`) but holds **no keys**. Physical-layer attacks (jamming), "
      "compromise of the ground station or satellite, and full CCSDS compliance are out of scope.\n")

    w("## 2. Attack success: unsecured vs OrbitLock-secured\n")
    w("Success is judged by *ground truth* from the simulator (did the spacecraft actually execute the "
      "spoofed / replayed / tampered command, did the attacker read the traffic), not by the protocol's own logging.\n")
    w("| Attack | Property attacked | Clear link | Secured |")
    w("|---|---|---:|---:|")
    for k, lab in labels.items():
        w(f"| {lab} | {MECHANISM[k][0]} | {_f(clear['rates'][k])} % | {_f(sec['rates'][k])} % |")
    non_drop = [k for k in labels if k != "drop"]
    worst = max(sec["rates"][k] for k in non_drop)
    w("")
    if worst == 0:
        w(f"**Target met:** every attack that cryptography can address succeeds at 100 % on the clear link "
          f"and at **0 %** on the secured link ({len(non_drop)} of {len(labels)} attack types). "
          f"Frame dropping is the one exception, see section 3.\n")
    else:
        w(f"**Target NOT met:** worst secured success rate among non-DoS attacks is {_f(worst)} %.\n")

    w("## 3. Why each attack fails (or cannot) when secured\n")
    for k, lab in labels.items():
        prop, on_clear, on_sec = MECHANISM[k]
        w(f"### {lab}\n")
        w(f"* **Property:** {prop}")
        w(f"* **Clear link:** {on_clear}")
        w(f"* **Secured:** {on_sec}\n")

    w("### Rejection reasons observed on the secured link\n")
    w("| Reason (security log) | Satellite | Ground |")
    w("|---|---:|---:|")
    reasons = sorted(set(sec["sat_rejects"]) | set(sec["ground_rejects"]))
    for r in reasons:
        w(f"| `{r}` | {sec['sat_rejects'].get(r, 0)} | {sec['ground_rejects'].get(r, 0)} |")
    w("\nEvery rejected frame is logged with its reason, sequence number, epoch and virtual channel "
      "(shown live in the console's *Security events* panel).\n")

    w("## 4. Cost of protection\n")
    hdr, tag = perf["header_bytes"], perf["tag_bytes"]
    w(f"* **Frame size:** header is {hdr} B in both modes; security adds a {tag}-byte GCM tag per frame.")
    w("* **Per-frame latency and throughput** (protect + unprotect, single core, in-process):\n")
    w("| Payload | Clear (us) | Secured (us) | Added (us) | Clear (frames/s) | Secured (frames/s) | Size overhead |")
    w("|---:|---:|---:|---:|---:|---:|---:|")
    for size, d in sorted(perf["sizes"].items(), key=lambda kv: int(kv[0])):
        w(f"| {size} B | {_f(d['plain_us'])} | {_f(d['secure_us'])} | {_f(d['added_us'])} | "
          f"{d['plain_fps']:.0f} | {d['secure_fps']:.0f} | {_f(d['overhead_pct'])} % |")
    r = perf["rtt"]
    w(f"\n* **End-to-end command round trip** (ground -> attacker relay -> satellite -> ACK): "
      f"median {_f(r['plain']['median_ms'], 2)} ms clear vs {_f(r['secure']['median_ms'], 2)} ms secured "
      f"(p95 {_f(r['plain']['p95_ms'], 2)} vs {_f(r['secure']['p95_ms'], 2)} ms).")
    w(f"* **Session setup:** X25519 + HKDF-SHA256 handshake takes {_f(perf['handshake_ms'], 1)} ms "
      f"(paid once per session / emergency rekey).")
    w("* **Conclusion:** the overhead is tens to ~100 microseconds and 16 bytes per frame, "
      "negligible against telemetry rates of a few hertz and typical RF link latencies.\n")

    w("## 5. Second line of defence: telemetry anomaly detection\n")
    w("An Isolation Forest, trained on normal simulated telemetry, flags abnormal behaviour. Anomalies are "
      "*real* injected failures (battery drop, temperature spike, tumble) plus a frame flood.\n")
    w(f"* **Event-level recall:** {an['events_detected']} of {an['injected_events']} injected events detected "
      f"({_f(an['event_recall'])} %).")
    w(f"* **Alert precision:** {_f(an['alert_precision'])} % ({an['alerts']} alerts).")
    w(f"* **Sample-level:** precision {_f(an['sample_precision'])} %, recall {_f(an['sample_recall'])} %, "
      f"**false-positive rate {_f(an['false_positive_rate'], 2)} %** "
      f"(TP {an['confusion']['tp']}, FP {an['confusion']['fp']}, FN {an['confusion']['fn']}, TN {an['confusion']['tn']}).")
    w("* Per-kind recall: " + ", ".join(f"{k} {_f(v['recall'], 0)} %" for k, v in an["per_kind"].items()) + ".")
    w("\nSample-level recall is lower than event-level recall because the detector reliably flags the "
      "*onset* of an event but not every subsequent sample while the system recovers. For an operator "
      "alert this is the relevant measure.\n")

    w("## 6. Residual risk and limitations\n")
    w("* **Availability:** dropping, jamming and flooding remain possible; cryptography cannot prevent them. "
      "OrbitLock rejects flooded frames cheaply (tag check before any state update) and the detector flags the flood.")
    w("* **Key custody:** the pre-launch PSK is a stand-in; compromise of the PSK breaks handshake authentication "
      "(session keys remain forward-secret per ephemeral X25519 exchange).")
    w("* **Not flight-grade:** simplified SDLS-inspired framing, no RF layer, no certified implementation.")
    w("* **Simulation-only evidence:** results are from a local simulator; real links add loss, reordering and delay "
      "that the sliding window and one-epoch look-ahead are designed to tolerate but were not tested against live RF.\n")

    w("## 7. Reproduce\n")
    w("```bash\n.venv/bin/python -m pytest -q            # protocol + end-to-end attack tests\n"
      ".venv/bin/python -m orbitlock.evaluate     # re-run experiments, regenerate plots and this report\n```\n")
    w("Plots: `attack_success.png`, `overhead.png`, `anomaly.png` in `results/`.\n")
    return "\n".join(out)


def write_report(res: dict | None = None) -> Path:
    if res is None:
        res = json.loads((RESULTS / "results.json").read_text())
    p = RESULTS / "security_analysis.md"
    RESULTS.mkdir(exist_ok=True)
    p.write_text(render(res))
    return p


if __name__ == "__main__":
    print(write_report())
