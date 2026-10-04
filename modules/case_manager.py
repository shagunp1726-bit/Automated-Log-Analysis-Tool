"""
ForensicLens – Investigation Case Management Module
Case CRUD, investigation bookmarks, analyst audit trail,
and case status workflow.
"""

import uuid
from datetime import datetime
from collections import defaultdict


class CaseManager:
    """
    Investigation case management system.
    Supports creating cases, bookmarking evidence, and tracking analyst actions.
    """

    def __init__(self):
        self.cases = {}

    # ─── Case CRUD ────────────────────────────────

    def create_case(self, case_id, analyst="", description="", priority="medium", tags=None):
        """Create a new investigation case."""
        case = {
            "case_id": case_id,
            "analyst": analyst,
            "description": description,
            "priority": priority,
            "status": "open",
            "tags": tags or [],
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat(),
            "bookmarks": [],
            "audit_log": [],
            "notes": [],
            "findings": [],
        }
        self.cases[case_id] = case
        self.add_audit_entry(case_id, analyst or "system", "Case created")
        return case

    def get_case(self, case_id):
        """Get case by ID."""
        return self.cases.get(case_id)

    def update_case(self, case_id, **kwargs):
        """Update case fields."""
        case = self.cases.get(case_id)
        if not case:
            return None
        for key, value in kwargs.items():
            if key in case and key not in ("case_id", "created_at", "audit_log"):
                case[key] = value
        case["updated_at"] = datetime.utcnow().isoformat()
        return case

    def set_status(self, case_id, status, analyst="system"):
        """Update case status with audit trail."""
        valid = ["open", "in_progress", "resolved", "closed", "escalated"]
        if status not in valid:
            return None
        case = self.update_case(case_id, status=status)
        if case:
            self.add_audit_entry(case_id, analyst, f"Status changed to {status}")
        return case

    def list_cases(self):
        """List all cases."""
        return list(self.cases.values())

    # ─── Bookmarks ────────────────────────────────

    def add_bookmark(self, case_id, bookmark):
        """Add investigation bookmark (pinned event, query, entity pivot)."""
        case = self.cases.get(case_id)
        if not case:
            return None
        bm = {
            "id": str(uuid.uuid4())[:8],
            "type": bookmark.get("type", "event"),
            "value": bookmark.get("value", ""),
            "note": bookmark.get("note", ""),
            "created_at": datetime.utcnow().isoformat(),
            "tags": bookmark.get("tags", []),
        }
        case["bookmarks"].append(bm)
        case["updated_at"] = datetime.utcnow().isoformat()
        return bm

    def remove_bookmark(self, case_id, bookmark_id):
        """Remove a bookmark by ID."""
        case = self.cases.get(case_id)
        if not case:
            return False
        case["bookmarks"] = [b for b in case["bookmarks"] if b["id"] != bookmark_id]
        case["updated_at"] = datetime.utcnow().isoformat()
        return True

    def get_bookmarks(self, case_id):
        """Get all bookmarks for a case."""
        case = self.cases.get(case_id)
        return case["bookmarks"] if case else []

    # ─── Audit Trail ──────────────────────────────

    def add_audit_entry(self, case_id, analyst, action):
        """Add audit trail entry."""
        case = self.cases.get(case_id)
        if not case:
            return None
        entry = {
            "analyst": analyst,
            "action": action,
            "timestamp": datetime.utcnow().isoformat(),
        }
        case["audit_log"].append(entry)
        return entry

    def get_audit_log(self, case_id):
        """Get audit trail for a case."""
        case = self.cases.get(case_id)
        return case["audit_log"] if case else []

    # ─── Notes & Findings ─────────────────────────

    def add_note(self, case_id, analyst, content):
        """Add analyst note."""
        case = self.cases.get(case_id)
        if not case:
            return None
        note = {
            "id": str(uuid.uuid4())[:8],
            "analyst": analyst,
            "content": content,
            "created_at": datetime.utcnow().isoformat(),
        }
        case["notes"].append(note)
        case["updated_at"] = datetime.utcnow().isoformat()
        return note

    def add_finding(self, case_id, finding):
        """Add investigation finding."""
        case = self.cases.get(case_id)
        if not case:
            return None
        f = {
            "id": str(uuid.uuid4())[:8],
            "title": finding.get("title", ""),
            "description": finding.get("description", ""),
            "severity": finding.get("severity", "medium"),
            "mitre": finding.get("mitre", []),
            "evidence": finding.get("evidence", []),
            "created_at": datetime.utcnow().isoformat(),
        }
        case["findings"].append(f)
        case["updated_at"] = datetime.utcnow().isoformat()
        return f
