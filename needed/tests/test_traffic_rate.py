from netsniffer.analysis.traffic_rate import RateTracker


def test_empty_tracker_has_zero_current_rate():
    tracker = RateTracker(history_seconds=10)
    assert tracker.current_rate() == 0


def test_records_within_same_second_bucket_together():
    tracker = RateTracker(history_seconds=10)
    tracker.record(100.1)
    tracker.record(100.4)
    tracker.record(100.9)
    assert tracker.current_rate() == 3


def test_new_second_starts_a_new_bucket():
    tracker = RateTracker(history_seconds=10)
    tracker.record(100.1)
    tracker.record(101.0)
    assert tracker.current_rate() == 1


def test_old_buckets_are_trimmed_outside_history_window():
    tracker = RateTracker(history_seconds=5)
    tracker.record(100.0)
    tracker.record(200.0)  # far beyond the 5s window
    xs, ys = tracker.series(200.0)
    assert sum(ys) == 1  # the packet at t=100 must have been trimmed away


def test_series_is_zero_filled_and_evenly_spaced():
    tracker = RateTracker(history_seconds=5)
    tracker.record(100.0)
    tracker.record(103.0)
    xs, ys = tracker.series(100.0 + 5)
    assert xs == [-5, -4, -3, -2, -1, 0]
    assert len(xs) == len(ys)
    assert sum(ys) == 2
