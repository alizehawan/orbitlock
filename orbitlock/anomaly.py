"""Telemetry anomaly detector: Isolation Forest trained on normal simulated telemetry."""
from __future__ import annotations

import random
from collections import deque
from typing import Optional

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from . import messages as M
from .satellite import SpacecraftModel

FEATURES = ["battery", "temp", "d_battery", "d_temp", "att_rate", "frame_rate", "reject_rate"]
RATE_WINDOW = 4.0   # seconds over which frame/reject counters are turned into rates


class FeatureExtractor:
    """Stateful: turns a stream of telemetry samples into feature vectors."""

    def __init__(self):
        self.prev: Optional[dict] = None
        self.prev_t: float = 0.0
        self.hist: deque = deque()

    def reset(self):
        self.__init__()

    def push(self, tlm: dict, t_recv: float) -> np.ndarray:
        if self.prev is None:
            d_b = d_t = att = 0.0
        else:
            dt = max(t_recv - self.prev_t, 0.05)
            p = self.prev
            d_b = abs(tlm["battery"] - p["battery"]) / dt
            d_t = abs(tlm["temp"] - p["temp"]) / dt
            att = (abs(tlm["roll"] - p["roll"]) + abs(tlm["pitch"] - p["pitch"]) + abs(tlm["yaw"] - p["yaw"])) / dt
        self.prev, self.prev_t = tlm, t_recv
        self.hist.append((t_recv, tlm["rx_frames"], tlm["rx_rejects"]))
        while self.hist and t_recv - self.hist[0][0] > RATE_WINDOW:
            self.hist.popleft()
        t0, f0, r0 = self.hist[0]
        span = max(t_recv - t0, 0.5)
        frate = ((tlm["rx_frames"] - f0) & 0xFFFFFFFF) / span
        rrate = ((tlm["rx_rejects"] - r0) & 0xFFFFFFFF) / span
        return np.array([tlm["battery"], tlm["temp"], d_b, d_t, att, frate, rrate])


def generate_normal(n: int, seed: int, hz: float = 2.0, anomalies: Optional[list] = None):
    """Simulate nominal operations offline. ``anomalies``: list of (sample_idx, kind).

    Returns (X, labels, kinds) with labels 1 on samples belonging to an injected anomaly.
    """
    rng = random.Random(seed)
    sat = SpacecraftModel(warp=60.0, seed=seed)
    fx = FeatureExtractor()
    rx_frames = rx_rejects = 0
    X, labels = [], []
    inject = dict(anomalies or [])
    active_until = {}
    flood_until = -1
    dt = 1.0 / hz
    for i in range(n):
        # operator behaviour
        if rng.random() < 0.012:
            k = rng.random()
            rx_frames += 1
            if k < 0.35:
                sat.execute(dict(op=M.OP_SET_MODE, args=(rng.choice([1, 1, 2, 3]),)))
            elif k < 0.6:
                sat.execute(dict(op=M.OP_PAYLOAD, args=(rng.choice([0, 1]),)))
            elif k < 0.85:
                sat.execute(dict(op=M.OP_ATTITUDE, args=tuple(rng.uniform(-40, 40) for _ in range(3))))
            else:
                sat.execute(dict(op=M.OP_PING, args=()))
        sat.step(dt)
        label = 0
        kind = inject.get(i)
        if kind:
            if kind == "flood":
                flood_until = i + 16
                active_until[i] = i + 20
            else:
                sat.inject_fault(kind)
                active_until[i] = i + (14 if kind == "tumble" else 4)
        if i <= flood_until:
            burst = rng.randint(80, 250)
            rx_frames += burst
            rx_rejects += burst
        if any(i <= end for end in active_until.values()):
            label = 1
        tlm = sat.telemetry(rx_frames, rx_rejects, 0)
        X.append(fx.push(tlm, i * dt))
        labels.append(label)
    return np.array(X), np.array(labels)


class AnomalyDetector:
    def __init__(self, seed: int = 7):
        self.seed = seed
        self.scaler = StandardScaler()
        self.model = IsolationForest(n_estimators=200, contamination=0.004, random_state=seed)
        self.threshold = 0.0
        self.guard = np.full(5, np.inf)      # range guard for delta/rate features (see train)
        self.trained = False
        self.train_info: dict = {}

    def train(self, samples: int = 9000) -> dict:
        Xs = []
        for s in range(3):
            X, _ = generate_normal(samples // 3, seed=self.seed + s)
            Xs.append(X[30:])
        X = np.vstack(Xs)
        Z = self.scaler.fit_transform(X)
        self.model.fit(Z)
        self.threshold = 0.0
        # Isolation Forest cannot extrapolate: a value far *outside* the training range is
        # isolated no faster than the training extremes. Hybrid fix: also flag delta/rate
        # features that exceed 3x their 99.9th training percentile (with sane floors).
        floors = np.array([1.0, 1.0, 15.0, 5.0, 3.0])
        self.guard = np.maximum(np.percentile(X[:, 2:], 99.9, axis=0) * 3.0, floors)
        self.trained = True
        self.train_info = dict(samples=len(X), features=FEATURES, model="IsolationForest(200) + range guard",
                               guard=[round(float(g), 2) for g in self.guard])
        return self.train_info

    def score(self, x: np.ndarray) -> tuple[bool, float]:
        """Returns (is_anomaly, anomaly_score). Higher score = more anomalous."""
        flags, scores = self.predict(np.asarray(x).reshape(1, -1))
        return bool(flags[0]), float(scores[0])

    def predict(self, X: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        Z = self.scaler.transform(X)
        s = -self.model.decision_function(Z)
        ratio = (X[:, 2:] / self.guard).max(axis=1)
        s = np.where(ratio > 1.0, np.maximum(s, 0.05 + 0.05 * np.minimum(ratio, 8.0)), s)
        return s > self.threshold, s


class LiveDetector:
    """Glue used by the ground station: features -> model -> verdict, plus counters."""

    def __init__(self, detector: AnomalyDetector):
        self.det = detector
        self.fx = FeatureExtractor()
        self.flagged = 0
        self.total = 0
        self.last_score = 0.0
        self.recent: deque = deque(maxlen=200)

    def reset(self):
        self.fx.reset()
        self.flagged = self.total = 0
        self.recent.clear()

    def process(self, tlm: dict, t_recv: float) -> dict:
        x = self.fx.push(tlm, t_recv)
        self.total += 1
        if self.total < 4 or not self.det.trained:      # warm-up for rate features
            return dict(anomaly=False, score=0.0, features=x.tolist())
        flag, s = self.det.score(x)
        self.last_score = s
        if flag:
            self.flagged += 1
        return dict(anomaly=bool(flag), score=s, features=x.tolist(), reason=self.explain(x) if flag else "")

    @staticmethod
    def explain(x: np.ndarray) -> str:
        battery, temp, d_b, d_t, att, fr, rr = x
        if rr > 10:
            return f"flood of rejected frames ({rr:.0f}/s)"
        if fr > 15:
            return f"command-frame flood ({fr:.0f}/s)"
        if d_b > 3:
            return f"sudden battery jump ({d_b:.1f} %/s)"
        if d_t > 3:
            return f"sudden temperature jump ({d_t:.1f} °C/s)"
        if att > 40:
            return f"abnormal attitude rate ({att:.0f} °/s)"
        return "joint pattern unusual for normal operations"
