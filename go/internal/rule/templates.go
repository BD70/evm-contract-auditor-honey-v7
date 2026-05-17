package rule

func detectorTemplate() map[string]any {
	return map[string]any{
		"schema":         "evm-audit.detector.v1",
		"schema_version": "1.0.0",
		"rule": map[string]any{
			"id":              "{rule_id}",
			"internal_name":   "reference_{rule_id}",
			"title":           "Review required for {rule_id}",
			"category":        "custom",
			"severity":        "medium",
			"scope":           "function",
			"lifecycle_status": "example",
			"default_status":  "suspicious_behavior",
			"confidence_policy": map[string]any{
				"base":         0.6,
				"with_witness": 0.82,
				"inconclusive": 0.35,
			},
			"disallow_primary_evidence": []any{"function_name", "selector"},
		},
		"intent": map[string]any{
			"vulnerability_class":       "replace_me",
			"attack_thesis":             "Replace with a bytecode-observable attack thesis.",
			"protected_asset_or_effect": []any{"replace_me"},
			"exploit_model":             "single_tx_or_multi_tx",
		},
		"requires": map[string]any{
			"stateful":                   false,
			"facts_all":                  []any{"REVIEW_REQUIRED"},
			"flows_all":                  []any{},
			"reachable_effect_any":       []any{},
			"authorized_path_effect_any": []any{},
			"economic_effect_any":        []any{},
			"sequence":                   []any{},
		},
		"counter_evidence": map[string]any{
			"suppress_if_any":      []any{},
			"downgrade_if_any":     []any{},
			"inconclusive_if_any":  []any{},
			"manual_review_if_any": []any{},
		},
		"proof": map[string]any{
			"min_level":            "P2",
			"preferred_witness":    "reachable_path",
			"acceptable_witnesses": []any{"reachable_path", "invariant_argument"},
			"witness_generation": map[string]any{
				"native":            "path_match",
				"optional_adapters": []any{},
			},
		},
		"analysis_requirements": map[string]any{
			"min_function_coverage":               0.85,
			"min_storage_role_confidence":         0.8,
			"min_path_reachability_confidence":    0.8,
			"max_unknown_action_expression_count": 10,
			"max_unresolved_selector_count":       20,
			"max_unresolved_paths":                10,
			"require_no_unmodeled_terminators":    true,
		},
		"fixture_requirements": map[string]any{
			"corpus":                    "corpus/{rule_id}",
			"positive_fixtures_min":     2,
			"negative_fixtures_min":     2,
			"inconclusive_fixtures_min": 1,
			"required_scenarios":        []any{"positive", "negative", "inconclusive"},
		},
		"reporting": map[string]any{
			"title_template":        "{rule_id}",
			"summary":               "Replace with a one-paragraph detector summary.",
			"user_summary":          "Replace with a short user-facing explanation.",
			"technical_summary":     "Replace with the precise technical explanation of the matched behavior.",
			"exploit_narrative":     "Replace with a short exploit narrative that explains how the behavior becomes exploitable.",
			"exploit_preconditions": []any{},
			"remediation_hints":     []any{},
			"sarif": map[string]any{
				"taxa":      []any{},
				"precision": "medium",
			},
		},
	}
}

func corpusTemplate() map[string]any {
	return map[string]any{
		"schema":             "evm-audit.corpus.v1",
		"schema_version":     "1.0.0",
		"detector_id":        "{rule_id}",
		"scenario_taxonomy":  []any{"positive", "negative", "inconclusive"},
		"metrics": map[string]any{
			"unit_fixture_metrics": map[string]any{
				"false_positive_count": 0,
				"false_negative_count": 0,
			},
			"benchmark_metrics": map[string]any{},
		},
		"cases": []any{map[string]any{
			"id":         "replace_me_positive",
			"audit_json": "positive.audit.json",
			"expectation": map[string]any{
				"kind":     "positive",
				"rule_ids": []any{"{rule_id}"},
			},
		}},
	}
}
