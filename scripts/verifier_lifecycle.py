#!/usr/bin/env python3
"""Lifecycle wrapper for per-run AI-generated verification scripts."""

from __future__ import annotations

import argparse
import json
import os
import py_compile
import subprocess
import sys
from pathlib import Path
from typing import Any

try:
    from scripts import runtime_context as rt
    from scripts.apply_verification_results import apply_results
    from scripts.policy_validator import validate_source
    from scripts.verification_contract import (
        ContractError,
        PROMPT_MODE_BLACKBOX,
        PROMPT_MODE_GREYBOX,
        approve_manifest,
        assert_approved_manifest,
        build_approval_manifest,
        canonical_target,
        validate_scope,
        write_json,
    )
except ImportError:
    import runtime_context as rt
    from apply_verification_results import apply_results
    from policy_validator import validate_source
    from verification_contract import (
        ContractError,
        PROMPT_MODE_BLACKBOX,
        PROMPT_MODE_GREYBOX,
        approve_manifest,
        assert_approved_manifest,
        build_approval_manifest,
        canonical_target,
        validate_scope,
        write_json,
    )


DEFAULT_QUEUE_FILE = rt.output_dir() / "vuln_validation_queue.csv"


def _mode(value: str) -> str:
    text = (value or "").strip().upper()
    if text in {"GREYBOX", "GREYBOX_AUTHENTICATED"}:
        return PROMPT_MODE_GREYBOX
    return PROMPT_MODE_BLACKBOX


def _python() -> str:
    return sys.executable


def _verifier_args(
    *,
    verifier_file: Path,
    target: str,
    mode: str,
    dry_run: bool,
    approval_file: Path | None = None,
    results_file: Path | None = None,
    plan_file: Path | None = None,
) -> list[str]:
    args = [
        _python(),
        str(verifier_file),
        canonical_target(target),
        "--mode",
        mode,
        "--context-file",
        str(rt.ai_context_dir() / "internal" / "verification_context.jsonl"),
        "--zap-context-file",
        str(rt.ai_context_dir() / "internal" / "zap_instances_compact.jsonl"),
        "--scope-file",
        str(rt.scope_file()),
    ]
    if dry_run:
        args.append("--dry-run")
        args.extend(["--plan-file", str(plan_file or rt.verification_plan_file())])
    else:
        args.extend(["--results-file", str(results_file or rt.verification_results_file())])
        args.extend(["--approval-file", str(approval_file or rt.approval_file())])
    return args


def _run(args: list[str], *, timeout: int) -> subprocess.CompletedProcess[str]:
    display = " ".join(args)
    print(f"[VERIFIER] Exec: {display}")
    env = os.environ.copy()
    env["VA_PROJECT_ROOT"] = str(rt.project_root())
    env["VA_RUN_DIR"] = str(rt.run_dir())
    env["VA_VERIFIER_FILE"] = str(rt.verifier_file())
    env["VA_APPROVAL_FILE"] = str(rt.approval_file())
    env["VA_VERIFICATION_RESULTS_FILE"] = str(rt.verification_results_file())
    env["VA_VERIFICATION_PLAN_FILE"] = str(rt.verification_plan_file())
    try:
        return subprocess.run(
            args,
            cwd=str(rt.project_root()),
            text=True,
            stdout=sys.stdout,
            stderr=sys.stderr,
            timeout=timeout,
            check=False,
            env=env,
        )
    except subprocess.TimeoutExpired:
        print(f"[VERIFIER] Generated verifier timed out after {timeout}s")
        return subprocess.CompletedProcess(args=args, returncode=124)


def validate_verifier(verifier_file: str | Path) -> dict[str, Any]:
    verifier_path = Path(verifier_file)
    if not verifier_path.exists():
        raise ContractError(f"Generated verifier does not exist: {verifier_path}")
    try:
        py_compile.compile(str(verifier_path), doraise=True)
    except py_compile.PyCompileError as exc:
        raise ContractError(f"Generated verifier does not compile: {exc}") from exc

    policy = validate_source(verifier_path)
    write_json(rt.verification_dir() / "policy_validation.json", policy)
    if not policy.get("passed"):
        raise ContractError(f"Policy validation failed for {verifier_path}")
    return policy


def prepare(target: str, *, mode: str, verifier_file: str | Path) -> int:
    rt.ensure_runtime_dirs()
    target_value = canonical_target(target)
    if not rt.scope_file().exists():
        rt.write_scope_template(rt.scope_file(), target_value)
        print(f"[VERIFIER] Created scope template: {rt.scope_file()}")
        print("[VERIFIER] Edit allowed_hosts/allowed_ports before dry-run approval or live verification.")

    print("[VERIFIER] Per-run verifier expected path:")
    print(f"  {Path(verifier_file)}")
    print("[VERIFIER] Stable inputs:")
    print(f"  context: {rt.ai_context_dir() / 'internal' / 'verification_context.jsonl'}")
    print(f"  zap context: {rt.ai_context_dir() / 'internal' / 'zap_instances_compact.jsonl'}")
    print(f"  queue: {DEFAULT_QUEUE_FILE}")
    print(f"  scope: {rt.scope_file()}")
    print(f"  mode: {_mode(mode)}")
    return 0


def dry_run(target: str, *, mode: str, verifier_file: str | Path, queue_file: str | Path) -> int:
    rt.ensure_runtime_dirs()
    verifier_path = Path(verifier_file)
    queue_path = Path(queue_file)
    plan_path = rt.verification_plan_file()
    approval_path = rt.approval_file()
    mode_value = _mode(mode)

    policy = validate_verifier(verifier_path)
    if plan_path.exists():
        plan_path.unlink()

    result = _run(
        _verifier_args(
            verifier_file=verifier_path,
            target=target,
            mode=mode_value,
            dry_run=True,
            plan_file=plan_path,
        ),
        timeout=int(os.environ.get("VA_VERIFIER_DRY_RUN_TIMEOUT", "120")),
    )
    if result.returncode != 0:
        print(f"[VERIFIER] Dry-run failed with exit={result.returncode}")
        return result.returncode
    if not plan_path.exists():
        print(f"[VERIFIER] Dry-run did not create required plan file: {plan_path}")
        return 1

    manifest = build_approval_manifest(
        target=target,
        mode=mode_value,
        verifier_file=verifier_path,
        queue_file=queue_path,
        plan_file=plan_path,
        policy_result=policy,
    )
    write_json(approval_path, manifest)
    print(f"[VERIFIER] Approval manifest written: {approval_path}")

    scope_errors = manifest.get("scope", {}).get("validation_errors", [])
    if scope_errors:
        print("[VERIFIER] Scope is not approvable yet:")
        for item in scope_errors:
            print(f"  - {item}")
        return 1

    print("[VERIFIER] Dry-run complete. Review the approval manifest before live verification.")
    return 0


def approve(target: str, *, operator: str, verifier_file: str | Path, queue_file: str | Path) -> int:
    rt.ensure_runtime_dirs()
    try:
        approve_manifest(
            rt.approval_file(),
            operator=operator,
            target=target,
            verifier_file=verifier_file,
            queue_file=queue_file,
        )
    except ContractError as exc:
        print(f"[VERIFIER] Approval failed: {exc}")
        return 1
    print(f"[VERIFIER] Approval recorded in {rt.approval_file()}")
    return 0


def live_run(target: str, *, mode: str, verifier_file: str | Path, queue_file: str | Path, allow_overwrite: bool = False) -> int:
    rt.ensure_runtime_dirs()
    verifier_path = Path(verifier_file)
    queue_path = Path(queue_file)
    mode_value = _mode(mode)

    validate_verifier(verifier_path)
    try:
        assert_approved_manifest(
            rt.approval_file(),
            target=target,
            verifier_file=verifier_path,
            queue_file=queue_path,
        )
    except ContractError as exc:
        print(f"[VERIFIER] Approved manifest rejected: {exc}")
        return 1

    results_path = rt.verification_results_file()
    if results_path.exists():
        results_path.unlink()
    queue_hash_before = rt.file_sha256(queue_path)

    result = _run(
        _verifier_args(
            verifier_file=verifier_path,
            target=target,
            mode=mode_value,
            dry_run=False,
            approval_file=rt.approval_file(),
            results_file=results_path,
        ),
        timeout=int(os.environ.get("VA_VERIFIER_LIVE_TIMEOUT", "3600")),
    )
    if result.returncode != 0:
        print(f"[VERIFIER] Live verifier failed with exit={result.returncode}")
        return result.returncode
    if rt.file_sha256(queue_path) != queue_hash_before:
        print("[VERIFIER] Generated verifier modified the queue CSV directly. Rejecting run.")
        return 1
    try:
        summary = apply_results(
            queue_file=queue_path,
            results_file=results_path,
            allow_overwrite=allow_overwrite,
        )
    except ContractError as exc:
        print(f"[VERIFIER] Applying results failed: {exc}")
        return 1

    print(f"[VERIFIER] Applied {summary['result_count']} results.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Manage per-run AI-generated verifier lifecycle.")
    parser.add_argument("--verifier-file", default=str(rt.verifier_file()))
    parser.add_argument("--queue-file", default=str(DEFAULT_QUEUE_FILE))
    parser.add_argument("--mode", default=PROMPT_MODE_BLACKBOX)

    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ["prepare", "dry-run", "approve", "run"]:
        sub = subparsers.add_parser(name)
        sub.add_argument("target")
        if name == "approve":
            sub.add_argument("--operator", default=os.environ.get("USER", "operator"))
        if name == "run":
            sub.add_argument("--allow-overwrite", action="store_true")

    args = parser.parse_args(argv)
    verifier_file = Path(args.verifier_file)
    queue_file = Path(args.queue_file)

    try:
        if args.command == "prepare":
            return prepare(args.target, mode=args.mode, verifier_file=verifier_file)
        if args.command == "dry-run":
            return dry_run(args.target, mode=args.mode, verifier_file=verifier_file, queue_file=queue_file)
        if args.command == "approve":
            return approve(args.target, operator=args.operator, verifier_file=verifier_file, queue_file=queue_file)
        if args.command == "run":
            return live_run(
                args.target,
                mode=args.mode,
                verifier_file=verifier_file,
                queue_file=queue_file,
                allow_overwrite=args.allow_overwrite,
            )
    except ContractError as exc:
        print(f"[VERIFIER] FAIL: {exc}")
        return 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
