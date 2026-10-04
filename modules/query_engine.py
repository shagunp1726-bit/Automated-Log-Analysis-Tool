

import re
import fnmatch
from collections import Counter


# ──────────────────────────────────────────────
# Searchable fields on each event
# ──────────────────────────────────────────────
SEARCHABLE_FIELDS = [
    "type", "severity", "category", "raw", "user", "ip", "dest_ip",
    "process", "pid", "ppid", "parent_process", "commandline",
    "hash_md5", "hash_sha256", "hostname", "domain", "port",
    "protocol", "url", "source_file", "source_type", "timestamp",
]


class QueryEngine:
    """
    SIEM-style query engine.

    Query syntax:
        field:value                  → exact match
        field:val*                   → wildcard match
        field:/regex/                → regex match
        term                         → full-text search across raw log
        expr1 AND expr2              → both must match
        expr1 OR expr2               → either must match
        NOT expr                     → negation
        mitre.technique:T1078        → MITRE technique filter
        mitre.tactic:TA0001          → MITRE tactic filter
        severity:critical            → severity filter
        (expr1 OR expr2) AND expr3   → grouping

    Aggregations (pipe syntax):
        query | count by field
        query | top 10 field
        query | stats count by field
    """

    def __init__(self, events):
        self.events = events

    def search(self, query_string):
        """
        Execute a query and return matching events + aggregation results.
        """
        query_string = query_string.strip()
        if not query_string:
            return {"events": self.events, "total": len(self.events), "aggregation": None}

        # Check for pipe-based aggregation
        agg_result = None
        if "|" in query_string:
            parts = query_string.split("|", 1)
            query_string = parts[0].strip()
            agg_string = parts[1].strip()
        else:
            agg_string = None

        # Parse and filter
        if query_string:
            matched = [e for e in self.events if self._match_event(e, query_string)]
        else:
            matched = self.events

        # Run aggregation if present
        if agg_string:
            agg_result = self._aggregate(matched, agg_string)

        return {
            "events": matched,
            "total": len(matched),
            "aggregation": agg_result,
        }

    def _match_event(self, event, query):
        """Evaluate a query against a single event."""
        query = query.strip()

        # Handle parentheses (simple recursive)
        query = self._resolve_parens(event, query)
        if isinstance(query, bool):
            return query

        # Handle AND/OR/NOT
        # Split on OR first (lower precedence)
        or_parts = self._split_boolean(query, " OR ")
        if len(or_parts) > 1:
            return any(self._match_event(event, part) for part in or_parts)

        # Split on AND
        and_parts = self._split_boolean(query, " AND ")
        if len(and_parts) > 1:
            return all(self._match_event(event, part) for part in and_parts)

        # Handle NOT
        if query.startswith("NOT "):
            return not self._match_event(event, query[4:])

        # Handle field:value
        field_match = re.match(r'^([\w.]+):(.+)$', query)
        if field_match:
            field = field_match.group(1)
            pattern = field_match.group(2).strip('"').strip("'")
            return self._match_field(event, field, pattern)

        # Fallback: full-text search in raw
        return query.lower() in (event.get("raw") or "").lower()

    def _resolve_parens(self, event, query):
        """Resolve parenthetical expressions."""
        while "(" in query:
            # Find innermost parens
            match = re.search(r'\(([^()]+)\)', query)
            if not match:
                break
            inner = match.group(1)
            result = self._match_event(event, inner)
            query = query[:match.start()] + ("TRUE" if result else "FALSE") + query[match.end():]

        if query == "TRUE":
            return True
        if query == "FALSE":
            return False
        return query

    def _split_boolean(self, query, operator):
        """Split query by boolean operator, respecting parentheses."""
        parts = []
        depth = 0
        current = ""

        tokens = query.split(" ")
        i = 0
        op_word = operator.strip()

        while i < len(tokens):
            token = tokens[i]

            # Track parentheses depth
            depth += token.count("(") - token.count(")")

            if depth == 0 and token == op_word:
                if current.strip():
                    parts.append(current.strip())
                current = ""
            else:
                current += (" " if current else "") + token

            i += 1

        if current.strip():
            parts.append(current.strip())

        return parts

    def _match_field(self, event, field, pattern):
        """Match a specific field against a pattern."""
        # MITRE fields
        if field == "mitre.technique":
            techniques = event.get("mitre_techniques", [])
            return any(pattern.upper() in t.get("id", "").upper() or
                       pattern.lower() in t.get("name", "").lower()
                       for t in techniques)

        if field == "mitre.tactic":
            tactics = event.get("mitre_tactics", [])
            return any(pattern.upper() in t.get("id", "").upper() or
                       pattern.lower() in t.get("name", "").lower()
                       for t in tactics)

        # Normal fields
        if field == "event_type":
            field = "type"
        if field == "source_ip":
            field = "ip"
        if field == "status":
            return self._match_status(event, pattern)

        value = event.get(field)
        if value is None:
            # Check in json_data
            json_data = event.get("json_data") or {}
            value = json_data.get(field)

        if value is None:
            return False

        value = str(value)

        # Regex pattern
        if pattern.startswith("/") and pattern.endswith("/"):
            try:
                return bool(re.search(pattern[1:-1], value, re.IGNORECASE))
            except re.error:
                return False

        # Wildcard
        if "*" in pattern or "?" in pattern:
            return fnmatch.fnmatch(value.lower(), pattern.lower())

        # Exact match (case-insensitive)
        return value.lower() == pattern.lower()

    def _match_status(self, event, pattern):
        """Match status field (derived from event type)."""
        etype = event.get("type", "")
        if pattern.lower() == "failed":
            return "FAIL" in etype or "DENIED" in etype
        if pattern.lower() == "success":
            return "SUCCESS" in etype
        return False

    def _aggregate(self, events, agg_string):
        """Process aggregation commands."""
        agg_lower = agg_string.lower().strip()

        # count by field
        count_match = re.match(r'(?:count|stats\s+count)\s+by\s+(\w+)', agg_lower)
        if count_match:
            field = count_match.group(1)
            counter = Counter(str(e.get(field, "N/A")) for e in events)
            return {
                "type": "count",
                "field": field,
                "results": dict(counter.most_common(50)),
            }

        # top N field
        top_match = re.match(r'top\s+(\d+)\s+(\w+)', agg_lower)
        if top_match:
            n = int(top_match.group(1))
            field = top_match.group(2)
            counter = Counter(str(e.get(field, "N/A")) for e in events)
            return {
                "type": "top",
                "field": field,
                "n": n,
                "results": dict(counter.most_common(n)),
            }

        # group by field
        group_match = re.match(r'group\s+by\s+(\w+)', agg_lower)
        if group_match:
            field = group_match.group(1)
            counter = Counter(str(e.get(field, "N/A")) for e in events)
            return {
                "type": "group",
                "field": field,
                "results": dict(counter.most_common(50)),
            }

        return None


def execute_query(events, query_string):
    """Convenience function to execute a query."""
    engine = QueryEngine(events)
    return engine.search(query_string)
