from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable
import string
import time

from evm_core.contracts import validate_behavior_document
from evm_core.telemetry import AnalysisContext, AnalysisTimer, build_analysis_context

from .abi_recovery import recover_abi
from .annotations import annotate_instructions
from .audit_json import build_audit_json
from .blocks import build_basic_blocks
from .boilerplate import classify_boilerplate
from .cfg import analyze_cfg
from .disassembler import disassemble
from .function_slicer import slice_functions
from .keccak import keccak256_hex
from .metadata import extract_metadata
from .output import build_full_output, format_json, format_semantic
from .patterns import detect_patterns
from .profile_packs import default_profile_dirs, load_profile_registry
from .resolver import resolve_selectors
from .selectors import extract_selectors
from .semantic_patterns import analyze_semantics
from .stack_sim import simulate
from .storage_layout import recover_storage_layout


ProgressCallback = Callable[[str], None]
MAX_INPUT_BYTECODE_BYTES = 512 * 1024


@dataclass(frozen=True)
class PipelineOptions:
    no_resolve: bool = False
    no_profiles: bool = False
    profile_dirs: list[str] = field(default_factory=list)
    no_blocks: bool = False
    no_assembly: bool = False
    no_deep: bool = False
    verbose: bool = False
    debug_dump: bool = False
    eof_format: bool = False
    proxy_shell: bool = False
    step_budget_ms: int | None = None


class StepBudget:
    def __init__(self, budget_ms: int | None) -> None:
        self._deadline = (time.perf_counter() + budget_ms / 1000.0) if budget_ms else None

    def expired(self) -> bool:
        return self._deadline is not None and time.perf_counter() > self._deadline

    def check(self, step_name: str, warnings: list[str]) -> bool:
        if self.expired():
            warnings.append(f"step_budget_exceeded:step={step_name}")
            return True
        return False


@dataclass
class DeconstructionArtifacts:
    analysis_context: AnalysisContext
    bytecode_hex: str
    runtime_bytecode_hex: str
    analysis_bytecode_hex: str
    original_hash: str | None
    runtime_hash: str
    analysis_hash: str
    full_output: dict[str, Any]
    semantic_analysis: Any | None
    storage_layout_result: Any | None
    slice_result: Any | None
    sim_result: Any | None
    block_analysis: Any | None
    boilerplate_tags: Any | None
    timings: list[dict[str, object]]
    diagnostics: dict[str, Any]


class BytecodeInputError(ValueError):
    pass


def load_bytecode_from_file(path: str | Path) -> str:
    source = Path(path)
    if not source.exists():
        raise BytecodeInputError(f"File not found: {source}")
    text = source.read_text().strip()
    if not text:
        raise BytecodeInputError(f"Empty bytecode file: {source}")
    validate_hex_bytecode(text, source=str(source))
    return text


def normalize_hex_string(bytecode_hex: str) -> str:
    compact = "".join(str(bytecode_hex).split())
    if compact.startswith(("0x", "0X")):
        compact = compact[2:]
    return compact


def validate_hex_bytecode(bytecode_hex: str, *, source: str = "<input>") -> str:
    clean = normalize_hex_string(bytecode_hex)
    if not clean:
        raise BytecodeInputError(f"Empty bytecode: {source}")
    if len(clean) % 2 != 0:
        raise BytecodeInputError(f"Bytecode must contain an even number of hex characters: {source}")
    invalid = sorted({char for char in clean if char not in string.hexdigits})
    if invalid:
        display = "".join(invalid[:8])
        raise BytecodeInputError(f"Bytecode contains non-hex characters ({display}): {source}")
    byte_count = len(clean) // 2
    if byte_count > MAX_INPUT_BYTECODE_BYTES:
        raise BytecodeInputError(
            f"Bytecode exceeds safe analysis limit ({byte_count} bytes > {MAX_INPUT_BYTECODE_BYTES} bytes): {source}"
        )
    return clean


def extract_runtime_bytecode(bytecode_hex: str) -> str:
    clean_hex = validate_hex_bytecode(bytecode_hex)

    try:
        data = bytes.fromhex(clean_hex)
    except ValueError:
        return clean_hex

    patterns = [
        bytes.fromhex("396000f3fe"),
        bytes.fromhex("396000f3"),
    ]

    for pattern in patterns:
        idx = data.find(pattern)
        if 0 < idx < 5000:
            runtime_data = data[idx + len(pattern):]
            if len(runtime_data) > 50:
                return runtime_data.hex()

    return clean_hex


def strip_metadata_bytecode(bytecode_hex: str, metadata: Any) -> str:
    clean_hex = validate_hex_bytecode(bytecode_hex)
    if not metadata or not getattr(metadata, "found", False):
        return clean_hex
    start = getattr(metadata, "metadata_start_offset", 0)
    if start <= 0:
        return clean_hex
    return clean_hex[: start * 2]


def analyze_bytecode(
    bytecode_hex: str,
    options: PipelineOptions | None = None,
    progress: ProgressCallback | None = None,
    *,
    input_kind: str = "hex_string",
) -> DeconstructionArtifacts:
    opts = options or PipelineOptions()
    _effective_no_blocks = opts.no_blocks or opts.proxy_shell or opts.eof_format
    _effective_no_deep = opts.no_deep or opts.proxy_shell or opts.eof_format
    budget = StepBudget(opts.step_budget_ms)
    pipeline_warnings: list[str] = []

    clean_input = validate_hex_bytecode(bytecode_hex)
    analysis_context = build_analysis_context(
        input_kind=input_kind,
        resolver_enabled=not opts.no_resolve,
        profiles_enabled=not opts.no_profiles,
    )
    timer = AnalysisTimer()

    original_hash = "0x" + keccak256_hex(bytes.fromhex(clean_input)) if clean_input else None
    runtime_bytecode_hex = extract_runtime_bytecode(bytecode_hex)
    runtime_hash = "0x" + keccak256_hex(bytes.fromhex(validate_hex_bytecode(runtime_bytecode_hex)))

    profile_dirs: list[str] = []
    with timer.measure("profile_registry") as scope:
        if not opts.no_profiles:
            profile_dirs.extend(default_profile_dirs())
        profile_dirs.extend(opts.profile_dirs or [])
        profile_registry = load_profile_registry(profile_dirs)
        if not profile_dirs:
            scope.degrade(reason="no_profile_directories")

    _emit(progress, "[1/12] Disassembling bytecode...")
    with timer.measure("disassembly"):
        disasm = disassemble(runtime_bytecode_hex)
        for error in disasm.errors:
            _emit(progress, f"Warning: {error}")

    _emit(progress, "[2/12] Extracting compiler metadata...")
    with timer.measure("metadata"):
        metadata = extract_metadata(runtime_bytecode_hex)

    analysis_bytecode_hex = strip_metadata_bytecode(runtime_bytecode_hex, metadata)
    analysis_hash = "0x" + keccak256_hex(bytes.fromhex(validate_hex_bytecode(analysis_bytecode_hex)))
    bytecode_for_analysis = analysis_bytecode_hex
    if analysis_bytecode_hex != runtime_bytecode_hex:
        with timer.measure("metadata_strip_re_disassembly"):
            disasm = disassemble(analysis_bytecode_hex)

    _emit(progress, "[3/12] Extracting function selectors...")
    with timer.measure("selector_extraction"):
        selectors = extract_selectors(disasm)

    _emit(progress, "[4/12] Resolving function signatures...")
    selector_hexes = [selector.selector for selector in selectors.selectors]
    with timer.measure("selector_resolution") as scope:
        resolved = resolve_selectors(
            selector_hexes,
            use_api=not opts.no_resolve,
            api_delay=0,
            profile_registry=profile_registry,
        )
        if resolved.errors:
            scope.degrade(error_count=len(resolved.errors))

    _emit(progress, "[5/12] Detecting patterns...")
    with timer.measure("pattern_detection"):
        selector_set = {selector.selector.replace("0x", "") for selector in selectors.selectors}
        patterns = detect_patterns(disasm, bytecode_for_analysis, selector_set)

    blocks = None
    if not _effective_no_blocks and not budget.check("basic_blocks", pipeline_warnings):
        _emit(progress, "[6/12] Building basic blocks...")
        with timer.measure("basic_blocks"):
            blocks = build_basic_blocks(disasm)
    else:
        reason = "eof_or_proxy_shell" if (opts.eof_format or opts.proxy_shell) else "--no-blocks"
        _emit(progress, f"[6/12] Skipping basic blocks ({reason})")

    sim_result = None
    cfg_result = None
    enhanced_annotations = None
    if not _effective_no_deep and not _effective_no_blocks and blocks and not budget.check("stack_simulation", pipeline_warnings):
        _emit(progress, "[7/12] Stack simulation & constant propagation...")
        with timer.measure("stack_simulation"):
            sim_result = simulate(blocks, disasm)
        if not budget.check("cfg_and_annotations", pipeline_warnings):
            _emit(progress, "[8/12] Control flow analysis & pseudocode...")
            with timer.measure("cfg_and_annotations"):
                cfg_result = analyze_cfg(blocks, sim_result)
                enhanced_annotations = annotate_instructions(disasm, blocks, sim_result, cfg_result)
        else:
            _emit(progress, "[8/12] Skipping CFG (step budget)")
    else:
        _emit(progress, "[7/12] Skipping deep analysis")
        _emit(progress, "[8/12] Done")

    semantic_analysis = None
    storage_layout_result = None
    slice_result = None
    boilerplate_tags = None
    if sim_result and blocks and cfg_result:
        resolver_map = {
            result.selector: result.text_signatures[0]
            for result in resolved.resolved
            if result.text_signatures
        }

        if not budget.check("function_slicing", pipeline_warnings):
            _emit(progress, "[9/12] Slicing into per-function units...")
            with timer.measure("function_slicing"):
                slice_result = slice_functions(blocks, selectors, sim_result, resolved_map=resolver_map)
            _emit(
                progress,
                (
                    f"  -> {len(slice_result.functions)} functions, "
                    f"{len(slice_result.dispatcher_blocks)} dispatcher blocks, "
                    f"{len(slice_result.shared_blocks)} shared blocks"
                ),
            )
        else:
            _emit(progress, "[9/12] Skipping function slicing (step budget)")

        if slice_result and not budget.check("abi_recovery", pipeline_warnings):
            _emit(progress, "[10/12] Recovering ABI from bytecode patterns...")
            with timer.measure("abi_recovery"):
                abi_results = recover_abi(slice_result, blocks, sim_result)
        else:
            abi_results = None  # type: ignore[assignment]

        if slice_result and abi_results and not budget.check("storage_layout", pipeline_warnings):
            _emit(progress, "[11/12] Recovering storage layout...")
            with timer.measure("storage_layout"):
                storage_layout_result = recover_storage_layout(
                    blocks,
                    sim_result,
                    slice_result,
                    resolved_names=resolver_map,
                    profile_registry=profile_registry,
                )
            _emit(progress, f"  -> {len(storage_layout_result.slots)} slots recovered")

            boilerplate_tags = classify_boilerplate(blocks, sim_result)

            if not budget.check("semantic_patterns", pipeline_warnings):
                _emit(progress, "[12/12] Semantic pattern analysis...")
                with timer.measure("semantic_patterns"):
                    semantic_analysis = analyze_semantics(
                        slice_result=slice_result,
                        storage_layout=storage_layout_result,
                        abi_results=abi_results,
                        sim_result=sim_result,
                        block_analysis=blocks,
                        resolved_names=resolver_map,
                        profile_registry=profile_registry,
                    )
                _emit(progress, f"  -> Contract family: {semantic_analysis.contract_family}")
                for pattern in semantic_analysis.patterns:
                    if pattern.confidence >= 0.3:
                        _emit(progress, f"  -> {pattern.pattern_name}: {pattern.confidence:.0%}")
            else:
                _emit(progress, "[12/12] Skipping semantic patterns (step budget)")
        else:
            _emit(progress, "[10/12] Skipping ABI recovery (step budget or missing data)")
            _emit(progress, "[11/12] Skipping storage layout")
            _emit(progress, "[12/12] Skipping semantic patterns")

    with timer.measure("render_full_output"):
        full_output = build_full_output(
            bytecode_hex=bytecode_for_analysis,
            disasm=disasm,
            metadata=metadata,
            selectors=selectors,
            resolved=resolved,
            patterns=patterns,
            blocks=blocks,
            sim=sim_result,
            cfg=cfg_result,
            enhanced_annotations=enhanced_annotations,
            include_assembly=not opts.no_assembly,
            include_blocks=not opts.no_blocks,
        )
    full_output.setdefault("meta", {})["bytecode"] = {
        "original_hash": original_hash,
        "runtime_hash": runtime_hash,
        "analysis_hash": analysis_hash,
        "runtime_size": len(normalize_hex_string(runtime_bytecode_hex)) // 2,
        "analysis_size": len(normalize_hex_string(analysis_bytecode_hex)) // 2,
        "metadata_stripped": analysis_bytecode_hex != runtime_bytecode_hex,
    }
    diagnostics = {
        "resolver": {
            "enabled": not opts.no_resolve,
            "resolved_count": len(resolved.resolved),
            "unresolved_count": len(resolved.unresolved),
            "errors": list(resolved.errors),
        },
        "profiles": {
            "enabled": not opts.no_profiles,
            "loaded_directories": [str(path) for path in profile_dirs],
            "pack_count": len(profile_registry.packs),
        },
        "analysis": {
            "metadata_stripped": analysis_bytecode_hex != runtime_bytecode_hex,
            "deep_analysis_enabled": bool(sim_result and cfg_result),
            "eof_format": opts.eof_format,
            "proxy_shell": opts.proxy_shell,
            "pipeline_warnings": pipeline_warnings,
            "pipeline_truncated": bool(pipeline_warnings),
        },
    }

    return DeconstructionArtifacts(
        analysis_context=analysis_context,
        bytecode_hex=bytecode_for_analysis,
        runtime_bytecode_hex=runtime_bytecode_hex,
        analysis_bytecode_hex=analysis_bytecode_hex,
        original_hash=original_hash,
        runtime_hash=runtime_hash,
        analysis_hash=analysis_hash,
        full_output=full_output,
        semantic_analysis=semantic_analysis,
        storage_layout_result=storage_layout_result,
        slice_result=slice_result,
        sim_result=sim_result,
        block_analysis=blocks,
        boilerplate_tags=boilerplate_tags,
        timings=timer.to_list(),
        diagnostics=diagnostics,
    )


def build_behavior_audit(artifacts: DeconstructionArtifacts) -> dict[str, Any]:
    return validate_behavior_document(
        build_audit_json(
            artifacts.full_output,
            artifacts.semantic_analysis,
            artifacts.storage_layout_result,
            artifacts.slice_result,
            artifacts.sim_result,
            artifacts.block_analysis,
            bytecode_hex=artifacts.analysis_bytecode_hex,
            analysis_context=artifacts.analysis_context.to_dict(),
            diagnostics=artifacts.diagnostics,
            timings=artifacts.timings,
        )
    )


def render_output(artifacts: DeconstructionArtifacts, output_format: str, options: PipelineOptions) -> str:
    if options.debug_dump:
        return format_json(artifacts.full_output)
    if output_format == "json":
        return format_json(build_behavior_audit(artifacts))
    if output_format == "semantic":
        return format_semantic(
            artifacts.full_output,
            semantic_analysis=artifacts.semantic_analysis,
            storage_layout=artifacts.storage_layout_result,
            slice_result=artifacts.slice_result,
            boilerplate_tags=artifacts.boilerplate_tags,
            verbose=options.verbose,
        )
    raise ValueError(f"Unsupported output format: {output_format}")


def _emit(progress: ProgressCallback | None, message: str) -> None:
    if progress:
        progress(message)
