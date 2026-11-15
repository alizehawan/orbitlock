# OrbitLock - Comparative Security Analysis

*Generated 2026-11-15 23:55:12 from `results/results.json` (25 trials per attack per mode).*

## 1. Threat model

A man-in-the-middle sits on the ground-to-space link (ground <-> attacker <-> satellite, all over UDP). It can read, drop, modify, replay and inject frames. It knows the public frame format (`ver | scid | vc | type | epoch | seq`) but holds **no keys**. Physical-layer attacks (jamming), compromise of the ground station or satellite, and full CCSDS compliance are out of scope.

## 2. Attack success: unsecured vs OrbitLock-secured

Success is judged by *ground truth* from the simulator (did the spacecraft actually execute the spoofed / replayed / tampered command, did the attacker read the traffic), not by the protocol's own logging.

| Attack | Property attacked | Clear link | Secured |
|---|---|---:|---:|
| Eavesdropping (read traffic) | Confidentiality | 100.0 % | 0.0 % |
| Command spoofing (forged cmd) | Authenticity | 100.0 % | 0.0 % |
| Replay of captured command | Freshness / anti-replay | 100.0 % | 0.0 % |
| In-transit bit-flip tampering | Integrity | 100.0 % | 0.0 % |
| Downgrade (inject clear frame) | Protocol downgrade | 100.0 % | 0.0 % |
| Telemetry spoofing | Authenticity (downlink) | 100.0 % | 0.0 % |
| Frame dropping (DoS) | Availability | 100.0 % | 100.0 % |

**Target met:** every attack that cryptography can address succeeds at 100 % on the clear link and at **0 %** on the secured link (6 of 7 attack types). Frame dropping is the one exception, see section 3.

## 3. Why each attack fails (or cannot) when secured

### Eavesdropping (read traffic)

* **Property:** Confidentiality
* **Clear link:** Command and telemetry fields are readable straight off the wire.
* **Secured:** AES-256-GCM: payloads are ciphertext; the sniffer sees only the 15-byte header and an opaque body.

### Command spoofing (forged cmd)

* **Property:** Authenticity
* **Clear link:** Any well-formed frame is executed; a forged BURN changes the orbit.
* **Secured:** The forger holds no session key, so its 16-byte GCM tag is wrong; the frame is rejected as `bad_tag` before any state is touched.

### Replay of captured command

* **Property:** Freshness / anti-replay
* **Clear link:** A captured command is executed again, any number of times.
* **Secured:** Sequence number is already inside the sliding window; rejected as `replay` (or `out_of_window` once it is older than 64 frames). The window is updated only after the tag verifies.

### In-transit bit-flip tampering

* **Property:** Integrity
* **Clear link:** A single flipped bit silently changes a command argument and the altered command executes.
* **Secured:** The flipped bit breaks the GCM tag (header is authenticated as associated data too); rejected as `bad_tag`.

### Downgrade (inject clear frame)

* **Property:** Protocol downgrade
* **Clear link:** n/a - the link has no protection to downgrade.
* **Secured:** A secured satellite refuses unprotected frames outright (`clear_frame_on_secure_link`).

### Telemetry spoofing

* **Property:** Authenticity (downlink)
* **Clear link:** The ground station accepts fabricated telemetry, hiding a real fault.
* **Secured:** Ground-side verification fails (`bad_tag`); the fake frame never reaches the operator display or the detector.

### Frame dropping (DoS)

* **Property:** Availability
* **Clear link:** Frames are silently discarded by the man in the middle.
* **Secured:** Not preventable by any cryptographic layer. It is *detectable* (missing ACKs, telemetry gap) and is out of scope per the proposal (no physical-layer / DoS guarantees).

### Rejection reasons observed on the secured link

| Reason (security log) | Satellite | Ground |
|---|---:|---:|
| `bad_tag` | 50 | 25 |
| `clear_frame_on_secure_link` | 25 | 0 |
| `replay` | 25 | 0 |

Every rejected frame is logged with its reason, sequence number, epoch and virtual channel (shown live in the console's *Security events* panel).

## 4. Cost of protection

* **Frame size:** header is 15 B in both modes; security adds a 16-byte GCM tag per frame.
* **Per-frame latency and throughput** (protect + unprotect, single core, in-process):

| Payload | Clear (us) | Secured (us) | Added (us) | Clear (frames/s) | Secured (frames/s) | Size overhead |
|---:|---:|---:|---:|---:|---:|---:|
| 16 B | 5.5 | 15.7 | 10.2 | 180841 | 63754 | 51.6 % |
| 64 B | 4.3 | 14.5 | 10.2 | 231918 | 68970 | 20.3 % |
| 256 B | 4.3 | 13.7 | 9.4 | 234649 | 73093 | 5.9 % |
| 1024 B | 4.4 | 17.2 | 12.8 | 228515 | 58204 | 1.5 % |

* **End-to-end command round trip** (ground -> attacker relay -> satellite -> ACK): median 0.78 ms clear vs 0.82 ms secured (p95 1.38 vs 1.61 ms).
* **Session setup:** X25519 + HKDF-SHA256 handshake takes 0.6 ms (paid once per session / emergency rekey).
* **Conclusion:** the overhead is tens to ~100 microseconds and 16 bytes per frame, negligible against telemetry rates of a few hertz and typical RF link latencies.

## 5. Second line of defence: telemetry anomaly detection

An Isolation Forest, trained on normal simulated telemetry, flags abnormal behaviour. Anomalies are *real* injected failures (battery drop, temperature spike, tumble) plus a frame flood.

* **Event-level recall:** 36 of 36 injected events detected (100.0 %).
* **Alert precision:** 86.0 % (43 alerts).
* **Sample-level:** precision 81.3 %, recall 52.7 %, **false-positive rate 0.90 %** (TP 218, FP 50, FN 196, TN 5506).
* Per-kind recall: battery_drop 100 %, temp_spike 100 %, tumble 100 %, flood 100 %.

Sample-level recall is lower than event-level recall because the detector reliably flags the *onset* of an event but not every subsequent sample while the system recovers. For an operator alert this is the relevant measure.

## 6. Residual risk and limitations

* **Availability:** dropping, jamming and flooding remain possible; cryptography cannot prevent them. OrbitLock rejects flooded frames cheaply (tag check before any state update) and the detector flags the flood.
* **Key custody:** the pre-launch PSK is a stand-in; compromise of the PSK breaks handshake authentication (session keys remain forward-secret per ephemeral X25519 exchange).
* **Not flight-grade:** simplified SDLS-inspired framing, no RF layer, no certified implementation.
* **Simulation-only evidence:** results are from a local simulator; real links add loss, reordering and delay that the sliding window and one-epoch look-ahead are designed to tolerate but were not tested against live RF.

## 7. Reproduce

```bash
.venv/bin/python -m pytest -q            # protocol + end-to-end attack tests
.venv/bin/python -m orbitlock.evaluate     # re-run experiments, regenerate plots and this report
```

Plots: `attack_success.png`, `overhead.png`, `anomaly.png` in `results/`.
