"""ForensicLens – Full pipeline integration test."""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

try:
    from modules.parser import parse_logs
    print("[OK] parser")
except Exception as e:
    print(f"[FAIL] parser: {e}")

try:
    from modules.mitre_mapper import (
        map_mitre, get_mitre_heatmap_data, detect_attack_chains,
        get_coverage_score, TACTICS, TECHNIQUES
    )
    print(f"[OK] mitre_mapper ({len(TACTICS)} tactics, {len(TECHNIQUES)} techniques)")
except Exception as e:
    print(f"[FAIL] mitre_mapper: {e}")

try:
    from modules.correlation_engine import run_all_detections, build_entity_graph, build_process_tree
    print("[OK] correlation_engine")
except Exception as e:
    print(f"[FAIL] correlation_engine: {e}")

try:
    from modules.query_engine import execute_query
    print("[OK] query_engine")
except Exception as e:
    print(f"[FAIL] query_engine: {e}")

try:
    from modules.entity_engine import EntityEngine, build_entity_data
    print("[OK] entity_engine")
except Exception as e:
    print(f"[FAIL] entity_engine: {e}")

try:
    from modules.ai_hunter import translate_nl_query, generate_investigation_summary, generate_detection_suggestions
    print("[OK] ai_hunter")
except Exception as e:
    print(f"[FAIL] ai_hunter: {e}")

try:
    from modules.highlight_engine import get_highlight_rules_json
    rules = get_highlight_rules_json()
    print(f"[OK] highlight_engine ({len(rules)} rules)")
except Exception as e:
    print(f"[FAIL] highlight_engine: {e}")

try:
    from modules.attack_chain_engine import AttackChainEngine
    print("[OK] attack_chain_engine")
except Exception as e:
    print(f"[FAIL] attack_chain_engine: {e}")

try:
    from modules.rule_builder import RuleEngine, DEFAULT_RULES
    print(f"[OK] rule_builder ({len(DEFAULT_RULES)} default rules)")
except Exception as e:
    print(f"[FAIL] rule_builder: {e}")

try:
    from modules.ioc_enrichment import IOCEngine
    print("[OK] ioc_enrichment")
except Exception as e:
    print(f"[FAIL] ioc_enrichment: {e}")

try:
    from modules.case_manager import CaseManager
    print("[OK] case_manager")
except Exception as e:
    print(f"[FAIL] case_manager: {e}")

# ── Test full pipeline with sample log ──
print("\n--- Testing Pipeline ---")
try:
    log_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "sample_logs", "attack_scenario.log")
    events, diagnostics = parse_logs([log_path])
    print(f"[OK] Parsed {len(events)} events")

    techniques = map_mitre(events)
    print(f"[OK] MITRE mapped: {len(techniques)} techniques found")

    detections = run_all_detections(events)
    print(f"[OK] Detections: {len(detections)} alerts")

    heatmap = get_mitre_heatmap_data(events)
    print(f"[OK] Heatmap: {len(heatmap)} tactics with data")

    chains = detect_attack_chains(events)
    print(f"[OK] Attack chains: {len(chains)} found")

    coverage = get_coverage_score(events)
    print(f"[OK] Coverage: {coverage}")

    entity_data = build_entity_data(events)
    print(f"[OK] Entity data: {list(entity_data.keys())}")

    result = execute_query(events, "type:AUTH_FAIL")
    print(f"[OK] Query 'type:AUTH_FAIL': {result['total']} events")

    translated, conf, expl = translate_nl_query("show all failed logins")
    print(f"[OK] NL query: '{translated}' (confidence: {conf})")

    summary = generate_investigation_summary(events, detections, techniques, entity_data)
    print(f"[OK] AI summary: {summary['risk_assessment']}")

    suggestions = generate_detection_suggestions(events, detections)
    print(f"[OK] Detection suggestions: {len(suggestions)} rules")

    graph = build_entity_graph(events)
    print(f"[OK] Entity graph: {len(graph['nodes'])} nodes, {len(graph['edges'])} edges")

    # ── New module tests ──
    print("\n--- Testing New Modules ---")

    # Attack chain engine
    ace = AttackChainEngine(events)
    discovered = ace.discover_chains()
    print(f"[OK] Attack chain engine: {len(discovered)} chains discovered")
    entity_risks = ace.get_entity_risk_scores()
    print(f"[OK] Entity risk scores: {len(entity_risks)} entities scored")
    storyline = ace.generate_storyline()
    print(f"[OK] Attack storyline: {len(storyline)} steps")

    # Rule builder
    re_ = RuleEngine()
    for rule in DEFAULT_RULES:
        re_.add_rule(rule)
    rule_results = re_.evaluate_all(events)
    print(f"[OK] Rule engine: {len(rule_results)} rules triggered")

    # IOC enrichment
    ioc = IOCEngine()
    matches = ioc.scan_events(events)
    print(f"[OK] IOC enrichment: {len(matches)} matches found")

    # Case manager
    cm = CaseManager()
    case = cm.create_case("test-case-001", "Test Analyst", "Testing case management")
    cm.add_bookmark("test-case-001", {"type": "query", "value": "type:AUTH_FAIL", "note": "Test"})
    cm.add_audit_entry("test-case-001", "Test Analyst", "Ran query")
    case_data = cm.get_case("test-case-001")
    print(f"[OK] Case manager: case '{case_data['case_id']}' with {len(case_data['bookmarks'])} bookmarks")

    print("\n=== ALL TESTS PASSED ===")
except Exception as e:
    import traceback
    print(f"[FAIL] Pipeline: {e}")
    traceback.print_exc()
