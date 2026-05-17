package version

const (
	Engine        = "1.0.0"
	Ruleset       = "1.0.0"
	CheckerSchema = "evm-audit.checker"
	CheckerVer    = "1.0.0"
)

// Version is the binary semver. Output format pinned to `evm_audit X.Y.Z` for
// runner/health.ts version probe parity.
var Version = "2.0.0-go"
