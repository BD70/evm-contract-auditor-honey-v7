# Profile Spec

Profiles are semantic hints, not detector logic.

## Profiles May Add

- selector labels
- protocol role names
- storage anchors
- known layout expectations
- function semantic overrides

## Profiles May Not Add

- vulnerability findings
- severity decisions
- detector suppressions
- corpus expectations

## Safety Rule

If a profile is wrong, the detector should still fail safely because detectors must depend on behavior and state-model evidence, not only profile labels.

Profile-only hints are not detector-grade proof.

If a semantic override or storage anchor is used, the engine should treat it as:

- `profile_hint` when it is not corroborated by bytecode-derived signal
- `profile_corroborated` only when underlying bytecode-derived evidence also exists
