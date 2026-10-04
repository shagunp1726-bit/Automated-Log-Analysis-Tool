import json
from collections import defaultdict

class EvidenceBuilder:
    """
    Transforms the case dictionary into a compressed, structured context for Gemini.
    """
    
    def build_context(self, case_data: dict) -> str:
        """
        Converts the entire case store entry into a stringified JSON representation
        for the LLM.
        """
        events = case_data.get("events", [])
        timeline = case_data.get("timeline", [])
        
        # Summarize large numbers of identical events
        summarized_events = self._summarize_events(events)
        
        # Extract critical details
        context = {
            "case_id": case_data.get("case_id"),
            "risk_score": case_data.get("risk_score"),
            "severity": case_data.get("severity"),
            "incident_type": case_data.get("incident_type"),
            "mitre_techniques": case_data.get("mitre_techniques", []),
            "detections": case_data.get("detections", []),
            "attack_chains": case_data.get("attack_chains", []),
            "timeline": self._compress_timeline(timeline),
            "evidence_summary": summarized_events
        }
        
        return json.dumps(context, indent=2)

    def _summarize_events(self, events: list, max_events: int = 500) -> list:
        """
        Aggregates identical events to prevent context window explosion.
        """
        # Prioritize high severity events
        sorted_events = sorted(
            events, 
            key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(x.get("severity", "info"), 5)
        )
        
        summary = []
        counts = defaultdict(int)
        
        for e in sorted_events:
            # Create a signature for the event
            sig = f"{e.get('type')}|{e.get('user')}|{e.get('ip')}|{e.get('process')}"
            counts[sig] += 1
            
            if counts[sig] <= 5: # Keep up to 5 examples of this specific signature
                summary.append({
                    "event_id": e.get("event_id"),
                    "timestamp": e.get("timestamp"),
                    "type": e.get("type"),
                    "severity": e.get("severity"),
                    "user": e.get("user"),
                    "ip": e.get("ip"),
                    "process": e.get("process"),
                    "message": e.get("message") or e.get("raw")
                })
                
            if len(summary) >= max_events:
                break
                
        # Append aggregation stats
        summary.append({"aggregation_stats": dict(counts)})
        return summary
        
    def _compress_timeline(self, timeline: list) -> list:
        """
        Returns a simplified timeline.
        """
        return [
            {
                "timestamp": t.get("timestamp"),
                "type": t.get("type"),
                "raw": t.get("raw")
            }
            for t in timeline[-100:] # Keep last 100 timeline events
        ]
