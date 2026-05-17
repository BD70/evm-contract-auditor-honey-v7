"""Output helpers for raw analysis assembly and the semantic report."""

from __future__ import annotations

import json
from typing import Any, Optional

from .disassembler import DisassemblyResult, Instruction
from .metadata import MetadataResult
from .selectors import SelectorResult
from .resolver import ResolverResult, ResolvedSignature
from .patterns import PatternResult
from .blocks import BlockAnalysis
from .stack_sim import SimulationResult
from .cfg import CFGAnalysis
from .pseudocode import generate_pseudocode
from .simplifier import simplify_text


def build_full_output(
    bytecode_hex: str,
    disasm: DisassemblyResult,
    metadata: MetadataResult,
    selectors: SelectorResult,
    resolved: ResolverResult,
    patterns: PatternResult,
    blocks: Optional[BlockAnalysis],
    sim: Optional[SimulationResult] = None,
    cfg: Optional[CFGAnalysis] = None,
    enhanced_annotations: Optional[dict[int, str]] = None,
    include_assembly: bool = True,
    include_blocks: bool = True,
) -> dict:
    """Build the complete structured output dictionary."""

    # Build function list with resolved names
    functions = []
    resolver_map = {r.selector: r for r in resolved.resolved}

    for sel in selectors.selectors:
        resolved_entry = resolver_map.get(sel.selector)
        functions.append({
            "selector": sel.selector,
            "resolved_names": resolved_entry.text_signatures if resolved_entry else [],
            "primary_name": resolved_entry.text_signatures[0] if resolved_entry and resolved_entry.text_signatures else None,
            "jump_target": f"0x{sel.jump_target:04x}" if sel.jump_target is not None else None,
            "confidence": resolved_entry.confidence if resolved_entry else "unresolved",
            "source": resolved_entry.source if resolved_entry else None,
        })

    output: dict[str, Any] = {}

    # ── Meta ──────────────────────────────────────────────
    output["meta"] = {
        "bytecode_size": disasm.bytecode_size,
        "bytecode_hash": disasm.bytecode_hash,
        "instruction_count": len(disasm.instructions),
    }

    if metadata.found:
        output["meta"]["compiler"] = {
            "name": metadata.compiler.name if metadata.compiler else "unknown",
            "version": metadata.compiler.version if metadata.compiler else None,
        }
        if metadata.hash_protocol:
            output["meta"]["metadata_hash"] = {
                "protocol": metadata.hash_protocol,
                "hash": metadata.hash_value,
            }
        output["meta"]["metadata_offset"] = f"0x{metadata.metadata_start_offset:04x}"
        output["meta"]["cbor_length"] = metadata.cbor_length
        if metadata.raw_decoded:
            output["meta"]["cbor_decoded"] = metadata.raw_decoded
    else:
        output["meta"]["compiler"] = {"name": "unknown", "version": None}

    # ── Classification ────────────────────────────────────
    output["classification"] = {
        "is_proxy": patterns.proxy.is_proxy,
        "proxy_type": patterns.proxy.proxy_type,
        "implementation_address": patterns.proxy.implementation_address,
        "standards": [s["standard"] for s in patterns.standards],
        "standards_detail": patterns.standards,
        "security": {
            "has_selfdestruct": patterns.security.has_selfdestruct,
            "has_delegatecall": patterns.security.has_delegatecall,
            "has_callcode": patterns.security.has_callcode,
            "has_create": patterns.security.has_create,
            "has_create2": patterns.security.has_create2,
            "has_tx_origin": patterns.security.has_origin,
            "selfdestruct_offsets": [f"0x{o:04x}" for o in patterns.security.selfdestruct_offsets],
            "delegatecall_offsets": [f"0x{o:04x}" for o in patterns.security.delegatecall_offsets],
        },
    }

    # ── Functions ─────────────────────────────────────────
    output["functions"] = functions
    output["unresolved_selectors"] = resolved.unresolved

    # ── Dispatcher ────────────────────────────────────────
    if selectors.dispatcher:
        d = selectors.dispatcher
        output["dispatcher"] = {
            "type": d.type,
            "start_offset": f"0x{d.start_offset:04x}",
            "end_offset": f"0x{d.end_offset:04x}",
            "num_branches": d.num_branches,
            "has_fallback": d.has_fallback,
            "fallback_offset": f"0x{d.fallback_offset:04x}" if d.fallback_offset else None,
            "has_receive": d.has_receive,
        }

    # ── Control Flow Analysis (v2) ────────────────────────
    if cfg and sim and blocks:
        # Loops
        output["control_flow"] = {
            "loops": [
                {
                    "id": l.loop_id,
                    "type": l.loop_type,
                    "header_block": l.header_block,
                    "body_blocks": l.body_blocks,
                    "exit_blocks": l.exit_blocks,
                    "back_edge": [l.back_edge_from, l.header_block],
                    "counter": {
                        "name": l.counter_name,
                        "init": l.counter_init,
                        "bound": l.counter_bound,
                        "step": l.counter_step,
                    },
                    "iterations": l.iterations,
                    "nested_in": l.parent_loop,
                    "condition": l.condition,
                }
                for l in cfg.loops
            ],
            "back_edges": [
                {"from": be.source, "to": be.target}
                for be in cfg.back_edges
            ],
            "block_types": cfg.block_types,
            "block_labels": cfg.block_labels,
        }

        # Pseudocode
        pseudo = generate_pseudocode(blocks, sim, cfg)
        if pseudo:
            output["pseudocode"] = pseudo

        # Stack traces per block
        stack_traces = {}
        for bid, trace in sim.traces.items():
            st = {
                "entry_stack": [repr(sv) for sv in trace.entry_stack],
                "exit_stack": [repr(sv) for sv in trace.exit_stack],
            }
            if trace.branch_condition:
                st["branch_condition"] = repr(trace.branch_condition)
            if trace.operations:
                st["operations"] = [op.description for op in trace.operations]
            if trace.memory_ops:
                st["memory_ops"] = [repr(m) for m in trace.memory_ops]
            if trace.storage_ops:
                st["storage_ops"] = [repr(s) for s in trace.storage_ops]
            stack_traces[str(bid)] = st
        output["stack_traces"] = stack_traces

        # Data flow summary
        all_mem_writes = []
        all_stor_reads = []
        all_stor_writes = []
        all_returns = []

        for bid, trace in sim.traces.items():
            for m in trace.memory_ops:
                if m.op_type == "write":
                    all_mem_writes.append({
                        "block": bid,
                        "offset": f"0x{m.offset_in_code:04x}",
                        "address": repr(m.address),
                        "value": repr(m.value) if m.value else "?",
                    })
            for s in trace.storage_ops:
                entry = {
                    "block": bid,
                    "offset": f"0x{s.offset_in_code:04x}",
                    "slot": repr(s.slot),
                }
                if s.op_type == "write":
                    entry["value"] = repr(s.value) if s.value else "?"
                    all_stor_writes.append(entry)
                else:
                    all_stor_reads.append(entry)
            for op in trace.operations:
                if "return" in op.description.lower():
                    all_returns.append({
                        "block": bid,
                        "offset": f"0x{op.offset:04x}",
                        "description": op.description,
                    })

        output["data_flow"] = {
            "memory_writes": all_mem_writes,
            "storage_reads": all_stor_reads,
            "storage_writes": all_stor_writes,
            "returns": all_returns,
        }

        # Constants with context
        if sim.constants:
            significant = [c for c in sim.constants if c.get("context")]
            if significant:
                output["constants"] = significant

    # ── Assembly ──────────────────────────────────────────
    if include_assembly:
        output["assembly"] = []
        for inst in disasm.instructions:
            ann = inst.annotation
            # Override with enhanced annotation if available
            if enhanced_annotations and inst.offset in enhanced_annotations:
                ann = enhanced_annotations[inst.offset]
            output["assembly"].append({
                "offset": f"0x{inst.offset:04x}",
                "opcode": inst.opcode,
                "operand": inst.operand,
                "raw": inst.raw,
                "annotation": ann,
            })

    # ── Basic Blocks ──────────────────────────────────────
    if include_blocks and blocks:
        output["basic_blocks"] = []
        for block in blocks.blocks:
            entry = {
                "id": block.id,
                "start": f"0x{block.start_offset:04x}",
                "end": f"0x{block.end_offset:04x}",
                "instruction_count": len(block.instructions),
                "terminator": block.terminator,
                "exits_to": block.exits_to,
                "exit_offsets": [f"0x{o:04x}" for o in block.exit_offsets],
            }
            # Add v2 info if available
            if cfg:
                entry["type"] = cfg.block_types.get(block.id, block.block_type)
                entry["label"] = cfg.block_labels.get(block.id, "")
            else:
                entry["type"] = block.block_type
            output["basic_blocks"].append(entry)

    # ── Statistics ────────────────────────────────────────
    output["statistics"] = {
        "opcode_frequency": patterns.opcode_frequency,
        "opcode_categories": patterns.opcode_categories,
    }

    # ── Strings ───────────────────────────────────────────
    if patterns.strings:
        output["strings"] = [
            {
                "offset": f"0x{s.offset:04x}",
                "value": s.value,
                "length": s.length,
            }
            for s in patterns.strings
        ]

    # ── Errors ────────────────────────────────────────────
    all_errors = disasm.errors + selectors.errors + resolved.errors
    if metadata.errors:
        all_errors += metadata.errors
    if sim and sim.errors:
        all_errors += sim.errors
    if all_errors:
        output["errors"] = all_errors

    return output


def format_json(output: dict, indent: int = 2) -> str:
    """Format output as JSON."""
    return json.dumps(output, indent=indent, default=str)


def format_semantic(
    output: dict,
    semantic_analysis = None,
    storage_layout = None,
    slice_result = None,
    boilerplate_tags = None,
    verbose: bool = False,
) -> str:
    """
    Format the analyst-first semantic report.
    
    6-layer structure:
    1. CONTRACT IDENTITY
    2. INTERFACE TABLE
    3. SEMANTIC ARCHITECTURE (pattern cards)
    4. STORAGE LAYOUT
    5. FUNCTION CARDS
    6. RISK SUMMARY
    + optional RAW VIEWS (with --verbose)
    """
    lines: list[str] = []

    lines.append("═" * 72)
    lines.append("  EVM SEMANTIC DECONSTRUCTION REPORT")
    lines.append("═" * 72)
    lines.append("")

    # ═══════════════════════════════════════════════════════
    # 1. CONTRACT IDENTITY
    # ═══════════════════════════════════════════════════════
    lines.append("─" * 72)
    lines.append("  1. CONTRACT IDENTITY")
    lines.append("─" * 72)
    lines.append("")

    meta = output.get("meta", {})
    lines.append(f"  Bytecode Size:    {meta.get('bytecode_size', '?')} bytes")
    lines.append(f"  Instructions:     {meta.get('instruction_count', '?')}")
    lines.append(f"  Hash:             {meta.get('bytecode_hash', '?')}")

    compiler = meta.get("compiler", {})
    if compiler.get("version"):
        lines.append(f"  Compiler:         {compiler.get('name', '?')} v{compiler.get('version', '?')}")

    md_hash = meta.get("metadata_hash", {})
    if md_hash:
        lines.append(f"  Metadata:         {md_hash.get('protocol', '?')}:{md_hash.get('hash', '?')[:24]}...")

    # Proxy status
    cls = output.get("classification", {})
    if cls.get("is_proxy"):
        lines.append(f"  Proxy:            {cls.get('proxy_type', 'unknown')}")
        if cls.get("implementation_address"):
            lines.append(f"  Implementation:   {cls['implementation_address']}")

    # Contract family headline
    if semantic_analysis:
        lines.append("")
        lines.append(f"  ★ Contract Family: {semantic_analysis.contract_family}")

    lines.append("")

    # ═══════════════════════════════════════════════════════
    # 2. INTERFACE TABLE
    # ═══════════════════════════════════════════════════════
    lines.append("─" * 72)
    lines.append("  2. INTERFACE TABLE")
    lines.append("─" * 72)
    lines.append("")

    functions = output.get("functions", [])
    unresolved = output.get("unresolved_selectors", [])

    if functions:
        # Header
        lines.append(f"  {'Selector':<12} {'Signature':<45} {'Source':<12}")
        lines.append(f"  {'─'*10:<12} {'─'*43:<45} {'─'*10:<12}")

        for f in functions:
            sel = f.get("selector", "?")
            name = f.get("primary_name") or "⚠ unresolved"
            conf = f.get("confidence", "?")
            source = f.get("source", "?")

            # Truncate long names
            if len(name) > 43:
                name = name[:40] + "..."

            lines.append(f"  {sel:<12} {name:<45} {str(source):<12}")

        lines.append("")
        lines.append(f"  Total: {len(functions)} functions")

        if unresolved:
            lines.append(f"  ⚠ Unresolved: {len(unresolved)} — {', '.join(unresolved)}")
        else:
            lines.append(f"  ✓ All selectors resolved")
    else:
        lines.append("  No functions detected")

    lines.append("")

    # ═══════════════════════════════════════════════════════
    # 3. SEMANTIC ARCHITECTURE
    # ═══════════════════════════════════════════════════════
    lines.append("─" * 72)
    lines.append("  3. SEMANTIC ARCHITECTURE")
    lines.append("─" * 72)
    lines.append("")

    if semantic_analysis and semantic_analysis.patterns:
        for pattern in semantic_analysis.patterns:
            conf_pct = f"{pattern.confidence:.0%}"
            icon = "✓" if pattern.confidence >= 0.7 else "?" if pattern.confidence >= 0.3 else "✗"
            lines.append(f"  {icon} {pattern.pattern_name:<25} confidence: {conf_pct:<6}")
            for ev in pattern.evidence:
                lines.append(f"      • {ev}")
            # Show details if available
            details = pattern.details
            if details.get("protected_functions"):
                lines.append(f"      ➜ protected: {', '.join(details['protected_functions'])}")
            if details.get("guarded_methods"):
                lines.append(f"      ➜ guarded: {', '.join(details['guarded_methods'])}")
            if details.get("risk"):
                for r in details["risk"]:
                    lines.append(f"      ⚠ {r}")
            lines.append("")

        # Standards detection with confidence
        if semantic_analysis.standards:
            lines.append("  Standards Detection:")
            for std in semantic_analysis.standards:
                conf = std.get("confidence", 0)
                icon = "✓" if conf >= 0.7 else "?" if conf >= 0.3 else "✗"
                lines.append(f"    {icon} {std['standard']:<12} confidence: {conf:.0%}")
                if std.get("missing_required"):
                    lines.append(f"        missing: {', '.join(std['missing_required'])}")
            lines.append("")
    else:
        lines.append("  No semantic patterns detected")
        lines.append("")

    # ═══════════════════════════════════════════════════════
    # 4. STORAGE LAYOUT
    # ═══════════════════════════════════════════════════════
    lines.append("─" * 72)
    lines.append("  4. STORAGE LAYOUT")
    lines.append("─" * 72)
    lines.append("")

    if storage_layout and storage_layout.slots:
        from .storage_layout import format_storage_layout
        layout_str = format_storage_layout(storage_layout)
        for line in layout_str.split("\n"):
            lines.append(f"  {line}")
        lines.append("")

        if storage_layout.unresolved_accesses:
            lines.append(f"  ({len(storage_layout.unresolved_accesses)} computed/dynamic accesses not shown)")
            lines.append("")
    else:
        lines.append("  No storage layout recovered")
        lines.append("")

    # ═══════════════════════════════════════════════════════
    # 5. FUNCTION CARDS
    # ═══════════════════════════════════════════════════════
    lines.append("─" * 72)
    lines.append("  5. FUNCTION CARDS")
    lines.append("─" * 72)
    lines.append("")

    if semantic_analysis and semantic_analysis.function_cards:
        for card in semantic_analysis.function_cards:
            # Function header
            mut_icon = {"payable": "💰", "view": "👁", "pure": "🔢", "nonpayable": "📝"}
            icon = mut_icon.get(card.mutability, "")
            lines.append(f"  ┌─ {card.selector} ─ {card.name}")
            lines.append(f"  │  mutability: {card.mutability} {icon}")

            if card.guards:
                lines.append(f"  │  guards:     {', '.join(card.guards)}")
            if card.state_reads:
                reads = card.state_reads[:5]
                lines.append(f"  │  reads:      {', '.join(reads)}")
                if len(card.state_reads) > 5:
                    lines.append(f"  │               ... and {len(card.state_reads) - 5} more")
            if card.state_writes:
                for w in card.state_writes[:3]:
                    lines.append(f"  │  writes:     {w}")
            if card.external_calls:
                for c in card.external_calls[:3]:
                    lines.append(f"  │  calls:      {c}")
            if card.events:
                lines.append(f"  │  events:     {', '.join(card.events)}")
            if card.branches:
                for b in card.branches:
                    lines.append(f"  │  branch:     {b}")
            if card.risk_flags:
                for r in card.risk_flags:
                    lines.append(f"  │  ⚠ risk:     {r}")

            lines.append(f"  └{'─' * 60}")
            lines.append("")

    # ═══════════════════════════════════════════════════════
    # 6. RISK SUMMARY
    # ═══════════════════════════════════════════════════════
    if semantic_analysis and semantic_analysis.risk_summary:
        lines.append("─" * 72)
        lines.append("  6. RISK SUMMARY")
        lines.append("─" * 72)
        lines.append("")

        for risk in semantic_analysis.risk_summary:
            lines.append(f"  ⚠ {risk}")
        lines.append("")

    # Security flags from raw analysis
    sec = cls.get("security", {})
    sec_warnings = []
    if sec.get("has_selfdestruct"):
        sec_warnings.append("SELFDESTRUCT opcode present")
    if sec.get("has_delegatecall"):
        sec_warnings.append("DELEGATECALL opcode present")
    if sec.get("has_callcode"):
        sec_warnings.append("CALLCODE opcode present (deprecated)")
    if sec.get("has_tx_origin"):
        sec_warnings.append("tx.origin opcode present (observation only; no authorization dependency proven)")

    if sec_warnings:
        lines.append("  Opcode-level observations:")
        for w in sec_warnings:
            lines.append(f"    • {w}")
        lines.append("")

    # ═══════════════════════════════════════════════════════
    # VERBOSE: Raw views
    # ═══════════════════════════════════════════════════════
    if verbose:
        # Simplified pseudocode
        pseudo = output.get("pseudocode")
        if pseudo:
            lines.append("─" * 72)
            lines.append("  APPENDIX A: PSEUDOCODE (simplified)")
            lines.append("─" * 72)
            lines.append("")
            for pl in pseudo.split("\n"):
                simplified = simplify_text(pl)
                lines.append(f"    {simplified}")
            lines.append("")

        # Loop analysis
        cf = output.get("control_flow")
        if cf:
            loops = cf.get("loops", [])
            if loops:
                lines.append("─" * 72)
                lines.append(f"  APPENDIX B: LOOP ANALYSIS ({len(loops)} loops)")
                lines.append("─" * 72)
                lines.append("")
                for l in loops:
                    nested = f" (nested in loop {l['nested_in']})" if l.get("nested_in") is not None else ""
                    lines.append(f"    Loop {l['id']}{nested}: {l['type']}")
                    counter = l.get("counter", {})
                    if counter.get("bound") is not None:
                        lines.append(f"      init={counter.get('init')}, bound={counter.get('bound')}, step={counter.get('step')}")
                    if l.get("iterations") is not None:
                        lines.append(f"      iterations: {l['iterations']}")
                    lines.append("")

        # Boilerplate summary
        if boilerplate_tags:
            from .boilerplate import summarize_boilerplate
            bp_summary = summarize_boilerplate(boilerplate_tags)
            if bp_summary:
                lines.append("─" * 72)
                lines.append("  APPENDIX C: BOILERPLATE CLASSIFICATION")
                lines.append("─" * 72)
                lines.append("")
                for cat, count in bp_summary.items():
                    lines.append(f"    {cat:<30} {count} blocks")
                lines.append("")

    lines.append("═" * 72)
    return "\n".join(lines)
