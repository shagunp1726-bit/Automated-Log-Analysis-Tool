def build_timeline(events):
    return sorted(events, key=lambda e: e["timestamp"])
