BEHAVIOR_SCHEMA_V2 = "evm-audit.behavior.v2"
BEHAVIOR_SCHEMA_VERSION = "2.0.0"

STATE_MODEL_SCHEMA_V2 = "evm-audit.state_model.v2"
STATE_MODEL_SCHEMA_VERSION = "2.1.0"

API_SCHEMA_V2 = "evm-audit.api.v2"
API_SCHEMA_VERSION = "2.0.0"

DETECTOR_SCHEMA_V1 = "evm-audit.detector.v1"
DETECTOR_SCHEMA_VERSION = "1.1.0"
DETECTOR_SCHEMA_SUPPORTED_VERSIONS = ("1.0.0", "1.1.0")

WITNESS_STATUS_VALUES = (
    "confirmed_exploit",
    "probable_vulnerability",
    "suspicious_behavior",
    "analysis_inconclusive",
    "suppressed_by_counter_evidence",
    "not_reproduced",
    "not_attempted",
)
