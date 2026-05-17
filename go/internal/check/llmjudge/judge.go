// Package llmjudge ports evm_check.llm_judge: optional local-LLM judge that
// downgrades probable false-positive findings via an OpenAI-compatible HTTP API.
package llmjudge

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	chk "github.com/evm-auditor/evm-auditor/internal/check"
	"github.com/evm-auditor/evm-auditor/internal/cli"
)

const (
	VerdictValid         = "valid"
	VerdictFalsePositive = "false_positive"
	VerdictNeedsHuman    = "needs_human"

	statusProbable      = "probable_vulnerability"
	statusSuspicious    = "suspicious_behavior"
	witnessSuppressed   = "suppressed_by_counter_evidence"
	witnessInconclusive = "analysis_inconclusive"

	systemPrompt = `You are a senior smart-contract security auditor reviewing a potential vulnerability finding produced by a static bytecode analyzer. Your job is to assess whether the finding is a real vulnerability or a false positive.

Respond ONLY with a JSON object — no prose, no markdown, no code fences. The object must have exactly these three fields:
  "verdict":    one of "valid", "false_positive", or "needs_human"
  "rationale":  one sentence explaining your verdict
  "confidence": a float between 0.0 and 1.0

"valid"          — the finding appears to be a genuine vulnerability worth reporting.
"false_positive" — the finding is clearly not exploitable given the context.
"needs_human"    — you cannot determine without additional context.
`
)

// Config holds env-driven judge configuration.
type Config struct {
	BaseURL      string
	Model        string
	APIKey       string
	Timeout      time.Duration
	RefreshCache bool
}

// LoadConfig builds a Config from EVM_LLM_* env vars.
func LoadConfig(refresh bool) Config {
	return Config{
		BaseURL:      envOr("EVM_LLM_BASE_URL", "http://localhost:11434/v1"),
		Model:        envOr("EVM_LLM_MODEL", "qwen2.5-coder:14b"),
		APIKey:       envOr("EVM_LLM_API_KEY", "local"),
		Timeout:      time.Duration(envFloat("EVM_LLM_TIMEOUT", 30) * float64(time.Second)),
		RefreshCache: refresh,
	}
}

// Result is the parsed judge verdict.
type Result struct {
	Verdict    string  `json:"verdict"`
	Rationale  string  `json:"rationale"`
	Confidence float64 `json:"confidence"`
	Cached     bool    `json:"cached"`
	JudgedAt   float64 `json:"judged_at"`
}

func cacheDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".cache", "evm-auditor", "llm-judge")
}

// IsAvailable mirrors evm_check.llm_judge.is_available: hits {base_url}/models
// with a 3s timeout. Always reports false on transport error.
func IsAvailable(cfg Config) bool {
	url := strings.TrimRight(cfg.BaseURL, "/") + "/models"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false
	}
	req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode < 500
}

// CacheKey mirrors evm_check.llm_judge.cache_key: sha256("bid|rule|bindings").
func CacheKey(bytecodeID, ruleID, bindingSummary string) string {
	raw := fmt.Sprintf("%s|%s|%s", bytecodeID, ruleID, bindingSummary)
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func cachePath(key string) string {
	return filepath.Join(cacheDir(), key+".json")
}

func readCache(key string) *Result {
	raw, err := os.ReadFile(cachePath(key))
	if err != nil {
		return nil
	}
	var r Result
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil
	}
	r.Cached = true
	return &r
}

func writeCache(key string, r Result) {
	_ = os.MkdirAll(cacheDir(), 0o755)
	out := map[string]any{
		"verdict":    r.Verdict,
		"rationale":  r.Rationale,
		"confidence": r.Confidence,
		"judged_at":  r.JudgedAt,
	}
	raw, _ := json.Marshal(out)
	_ = os.WriteFile(cachePath(key), raw, 0o644)
}

// JudgeFinding invokes the LLM judge for one finding. Returns nil on any error.
func JudgeFinding(finding, audit, rule map[string]any, cfg Config) *Result {
	bytecodeID := chk.AsString(chk.AsMap(audit["bytecode_identity"])["keccak256"])
	if bytecodeID == "" {
		bytecodeID = "unknown"
	}
	ruleID := chk.AsString(finding["rule_id"])
	if ruleID == "" {
		ruleID = "unknown"
	}
	bindings := chk.AsMap(chk.AsMap(chk.AsMap(finding["evidence"])["details"])["bindings"])
	bindRaw, _ := json.Marshal(sortedMap(bindings))
	key := CacheKey(bytecodeID, ruleID, string(bindRaw))

	if !cfg.RefreshCache {
		if cached := readCache(key); cached != nil {
			return cached
		}
	}

	auditSlice := buildAuditSlice(finding, audit, rule)
	prompt := buildPrompt(finding, auditSlice)

	body := map[string]any{
		"model": cfg.Model,
		"messages": []any{
			map[string]any{"role": "system", "content": systemPrompt},
			map[string]any{"role": "user", "content": prompt},
		},
		"max_tokens":      256,
		"temperature":     0.1,
		"response_format": map[string]any{"type": "json_object"},
	}
	resp, err := postChat(cfg, body)
	if err != nil {
		// Retry without response_format (some servers reject it).
		delete(body, "response_format")
		resp, err = postChat(cfg, body)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: LLM judge request failed for %s: %v\n", ruleID, err)
			return nil
		}
	}
	result := parseVerdict(resp)
	if result == nil {
		return nil
	}
	result.JudgedAt = float64(time.Now().Unix())
	writeCache(key, *result)
	return result
}

func postChat(cfg Config, body map[string]any) (string, error) {
	url := strings.TrimRight(cfg.BaseURL, "/") + "/chat/completions"
	raw, _ := json.Marshal(body)
	req, err := http.NewRequest("POST", url, bytes.NewReader(raw))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	req.Header.Set("Content-Type", "application/json")
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	respRaw, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respRaw))
	}
	var parsed struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(respRaw, &parsed); err != nil {
		return "", err
	}
	if len(parsed.Choices) == 0 {
		return "", fmt.Errorf("no choices in response")
	}
	return parsed.Choices[0].Message.Content, nil
}

func parseVerdict(raw string) *Result {
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, "```") {
		lines := strings.Split(raw, "\n")
		out := []string{}
		for _, l := range lines {
			if strings.HasPrefix(l, "```") {
				continue
			}
			out = append(out, l)
		}
		raw = strings.Join(out, "\n")
	}
	var data map[string]any
	if err := json.Unmarshal([]byte(raw), &data); err != nil {
		return nil
	}
	verdict := chk.AsString(data["verdict"])
	if verdict != VerdictValid && verdict != VerdictFalsePositive && verdict != VerdictNeedsHuman {
		return &Result{
			Verdict:    VerdictNeedsHuman,
			Rationale:  "model returned unexpected verdict",
			Confidence: 0.5,
		}
	}
	rationale := chk.AsString(data["rationale"])
	if len(rationale) > 500 {
		rationale = rationale[:500]
	}
	conf := chk.AsFloat(data["confidence"], 0.5)
	if conf < 0 {
		conf = 0
	}
	if conf > 1 {
		conf = 1
	}
	return &Result{Verdict: verdict, Rationale: rationale, Confidence: conf}
}

func buildPrompt(finding, auditSlice map[string]any) string {
	ruleID := chk.AsString(finding["rule_id"])
	if ruleID == "" {
		ruleID = "unknown"
	}
	intent := chk.AsMap(auditSlice["intent"])
	witnessGoal := chk.AsMap(finding["witness_goal"])
	tech := chk.AsString(finding["technical_summary"])
	exploit := chk.AsString(finding["exploit_narrative"])
	pseudo := chk.AsString(auditSlice["pseudocode"])
	slotSlice := chk.AsMap(auditSlice["slot_slice"])

	lines := []string{
		"Rule: " + ruleID,
		"Vulnerability class: " + coalesce(chk.AsString(intent["vulnerability_class"]), "unknown"),
		"Attack thesis: " + chk.AsString(intent["attack_thesis"]),
		"",
		"Technical summary: " + tech,
		"Exploit narrative: " + exploit,
	}
	if sc := chk.AsString(witnessGoal["success_condition"]); sc != "" {
		lines = append(lines, "Success condition: "+sc)
	}
	if pseudo != "" {
		if len(pseudo) > 2000 {
			pseudo = pseudo[:2000]
		}
		lines = append(lines, "\nRelevant pseudocode:\n"+pseudo)
	}
	if len(slotSlice) > 0 {
		raw, _ := cli.EncodePythonCompat(slotSlice)
		s := string(raw)
		if len(s) > 1000 {
			s = s[:1000]
		}
		lines = append(lines, "\nStorage context (JSON):\n"+s)
	}
	return strings.Join(lines, "\n")
}

func buildAuditSlice(finding, audit, rule map[string]any) map[string]any {
	state := chk.AsMap(audit["state_model"])
	relevant := []any{}
	for _, slotAny := range chk.AsList(state["slot_index"]) {
		slot := chk.AsMap(slotAny)
		role := chk.AsString(slot["semantic_role"])
		switch role {
		case "balance", "owner", "price", "reserve", "totalSupply", "share_price":
			relevant = append(relevant, map[string]any{
				"slot":            slot["slot"],
				"role":            slot["semantic_role"],
				"role_confidence": slot["role_confidence"],
			})
		}
	}
	fnSelector := chk.AsString(chk.AsMap(finding["function"])["selector"])
	pseudo := ""
	for _, fnAny := range chk.AsList(audit["functions"]) {
		fn := chk.AsMap(fnAny)
		if chk.AsString(fn["selector"]) == fnSelector {
			pseudo = chk.AsString(fn["pseudocode"])
			break
		}
	}
	return map[string]any{
		"intent":     chk.AsMap(rule["intent"]),
		"pseudocode": pseudo,
		"slot_slice": map[string]any{"relevant_slots": truncate(relevant, 5)},
	}
}

// ApplyJudgeResult mirrors evm_check.llm_judge.apply_judge_result.
func ApplyJudgeResult(finding map[string]any, r Result) map[string]any {
	out := map[string]any{}
	for k, v := range finding {
		out[k] = v
	}
	out["judged_by"] = "llm"
	out["judge_verdict"] = r.Verdict
	out["judge_rationale"] = r.Rationale
	out["judge_confidence"] = r.Confidence
	status := chk.AsString(out["status"])
	if r.Verdict == VerdictFalsePositive {
		switch status {
		case statusProbable:
			out["status"] = witnessInconclusive
			out["witness_status"] = witnessInconclusive
		case statusSuspicious:
			out["status"] = witnessSuppressed
			out["witness_status"] = witnessSuppressed
		}
	} else if r.Verdict == VerdictNeedsHuman {
		out["requires_manual_review"] = true
	}
	return out
}

// RunJudgePass mirrors evm_check.llm_judge.run_judge_pass.
func RunJudgePass(findings []map[string]any, audit map[string]any, rulesByID map[string]map[string]any, cfg Config) []map[string]any {
	out := make([]map[string]any, 0, len(findings))
	for _, f := range findings {
		status := chk.AsString(f["status"])
		if status == witnessSuppressed || status == witnessInconclusive {
			out = append(out, f)
			continue
		}
		ruleID := chk.AsString(f["rule_id"])
		rule := rulesByID[ruleID]
		if rule == nil {
			rule = map[string]any{}
		}
		result := JudgeFinding(f, audit, rule, cfg)
		if result != nil {
			f = ApplyJudgeResult(f, *result)
		}
		out = append(out, f)
	}
	return out
}

func sortedMap(m map[string]any) map[string]any { return m }

func envOr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func envFloat(name string, def float64) float64 {
	if v := os.Getenv(name); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return def
}

func coalesce(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func truncate(items []any, n int) []any {
	if len(items) <= n {
		return items
	}
	return items[:n]
}
