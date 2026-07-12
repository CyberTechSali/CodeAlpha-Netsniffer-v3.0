"""Pure packet-rate tracking for the real-time throughput chart.

Kept separate from the UI (no matplotlib/Tkinter import here) so the
bucketing logic can be unit tested directly: feed it timestamps, ask for
the per-second series, done.
"""

from __future__ import annotations

from collections import deque


class RateTracker:
    """Buckets packet arrivals into 1-second buckets and keeps a rolling
    window of `history_seconds` buckets for a packets/sec chart."""

    def __init__(self, history_seconds: int = 60) -> None:
        self._history_seconds = history_seconds
        # deque[(bucket_epoch_second, count)], oldest first
        self._buckets: deque[list] = deque()

    def record(self, epoch_seconds: float) -> None:
        bucket = int(epoch_seconds)
        if self._buckets and self._buckets[-1][0] == bucket:
            self._buckets[-1][1] += 1
        else:
            self._buckets.append([bucket, 1])
        self._trim(bucket)

    def _trim(self, now_bucket: int) -> None:
        cutoff = now_bucket - self._history_seconds
        while self._buckets and self._buckets[0][0] < cutoff:
            self._buckets.popleft()

    def series(self, now_epoch_seconds: float) -> tuple[list[int], list[int]]:
        """Return (relative_seconds_ago, count) pairs covering the full
        history window, zero-filling seconds with no traffic, so the chart
        x-axis is a continuous, evenly spaced timeline instead of only the
        seconds that happened to have packets."""
        now_bucket = int(now_epoch_seconds)
        self._trim(now_bucket)
        counts_by_bucket = {b: c for b, c in self._buckets}

        xs: list[int] = []
        ys: list[int] = []
        for offset in range(self._history_seconds, -1, -1):
            bucket = now_bucket - offset
            xs.append(-offset)
            ys.append(counts_by_bucket.get(bucket, 0))
        return xs, ys

    def current_rate(self) -> int:
        """Packets counted in the most recent completed bucket."""
        return self._buckets[-1][1] if self._buckets else 0
