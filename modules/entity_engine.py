"""
ForensicLens – Entity Intelligence Engine
Entity linking, pivoting, risk scoring per entity
"""

from collections import defaultdict, Counter


# ──────────────────────────────────────────────
# Risk weights by event type
# ──────────────────────────────────────────────
EVENT_RISK_WEIGHTS = {
    "AUTH_FAIL": 2,
    "AUTH_SUCCESS": 1,
    "PRIV_ESCALATION": 5,
    "ACCOUNT_CHANGE": 3,
    "PROCESS_CREATE": 1,
    "PROCESS_TERMINATE": 0,
    "NETWORK_CONN": 2,
    "DNS_QUERY": 1,
    "FIREWALL": 2,
    "FILE_CREATE": 1,
    "FILE_MODIFY": 2,
    "FILE_DELETE": 3,
    "FILE_COPY": 3,
    "USB": 3,
    "REGISTRY": 2,
    "MALWARE_INDICATOR": 5,
    "EXECUTION_SUSPICIOUS": 5,
    "CLOUD_API": 2,
    "WEB_REQUEST": 1,
    "WEB_ATTACK": 5,
    "OTHER": 0,
}


class EntityEngine:
    """
    Entity intelligence: tracks all entities across events,
    computes risk scores, and supports pivot queries.
    """

    def __init__(self, events):
        self.events = events
        self.entity_index = defaultdict(list)
        self._build_index()

    def _build_index(self):
        """Index events by entity values."""
        entity_fields = [
            "user", "ip", "dest_ip", "process", "hostname",
            "domain", "hash_md5", "hash_sha256",
        ]
        for i, event in enumerate(self.events):
            for field in entity_fields:
                val = event.get(field)
                if val:
                    self.entity_index[f"{field}:{val}"].append(i)

    def get_entity_summary(self):
        """
        Get summary of all entities with event counts and risk scores.
        Returns dict by entity type.
        """
        summary = defaultdict(list)

        for key, event_indices in self.entity_index.items():
            entity_type, entity_value = key.split(":", 1)

            # Calculate risk score
            risk = sum(
                EVENT_RISK_WEIGHTS.get(self.events[i].get("type", "OTHER"), 0)
                for i in event_indices
            )

            # Get severity breakdown
            severities = Counter(
                self.events[i].get("severity", "info") for i in event_indices
            )

            # Get event types
            event_types = Counter(
                self.events[i].get("type", "OTHER") for i in event_indices
            )

            # Determine risk level
            if risk >= 20:
                risk_level = "critical"
            elif risk >= 12:
                risk_level = "high"
            elif risk >= 6:
                risk_level = "medium"
            else:
                risk_level = "low"

            summary[entity_type].append({
                "value": entity_value,
                "event_count": len(event_indices),
                "risk_score": risk,
                "risk_level": risk_level,
                "severities": dict(severities),
                "event_types": dict(event_types),
                "first_seen": self.events[event_indices[0]].get("timestamp", "?"),
                "last_seen": self.events[event_indices[-1]].get("timestamp", "?"),
            })

        # Sort each entity type by risk score descending
        for etype in summary:
            summary[etype].sort(key=lambda x: x["risk_score"], reverse=True)

        return dict(summary)

    def pivot(self, entity_type, entity_value):
        """
        Pivot on an entity: return all events related to it.
        Also returns related entities found in those events.
        """
        key = f"{entity_type}:{entity_value}"
        event_indices = self.entity_index.get(key, [])
        related_events = [self.events[i] for i in event_indices]

        # Find related entities
        related = defaultdict(set)
        entity_fields = ["user", "ip", "dest_ip", "process", "hostname", "domain"]
        for event in related_events:
            for field in entity_fields:
                val = event.get(field)
                if val and not (field == entity_type and val == entity_value):
                    related[field].add(val)

        return {
            "entity_type": entity_type,
            "entity_value": entity_value,
            "events": related_events,
            "event_count": len(related_events),
            "related_entities": {k: list(v) for k, v in related.items()},
        }

    def get_activity_timeline(self, entity_type, entity_value):
        """Get chronological activity for an entity."""
        pivot_data = self.pivot(entity_type, entity_value)
        events = sorted(pivot_data["events"], key=lambda e: e.get("timestamp", ""))
        return events


def build_entity_data(events):
    """Convenience function to build entity summary."""
    engine = EntityEngine(events)
    return engine.get_entity_summary()
