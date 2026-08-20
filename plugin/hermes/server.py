#!/usr/bin/env python3
"""JACKAL Hermes plugin — proof-carrying mathematical evidence tool server.

Exposes thirty-four tools (see `tools.json`):

  Formal (proof-carrying, checker-attested):
    * `jackal_range_bound`        emit a `jackal-formal-receipt-v1` receipt
    * `jackal_gaussian_integral`  emit a zero-libm Gaussian formal receipt
    * `jackal_integrate_bound_cert`  emit a certified composed-integral
      formal receipt (v1.7 bound_step composition, theorem int_cert_sound,
      checker jackal_int_cert_check)
    * `jackal_sqrt_rat_bound`, `jackal_exp_rat_bound`, `jackal_ln_rat_bound`,
      `jackal_sin_rat_bound`, `jackal_cos_rat_bound`, `jackal_atan_rat_bound`,
      `jackal_tanh_rat_bound`    pure-Q enclosures via Lean-proved checkers
    * `jackal_verify_receipt`     re-run the pinned Lean-proved checker

  Weaker-lane adapters (status passthrough, never inflated):
    * `jackal_exact`, `jackal_evaluate`, `jackal_diff`,
      `jackal_integrate`, `jackal_integrate_adaptive`,
      `jackal_integrate_bound`, `jackal_solve`
    * the fourteen exact-CAS lanes `jackal_canon` … `jackal_prime_cert`

  Claim-kernel front doors (v1.6.0, additive):
    * `jackal_claim`          compile a typed claim request into a
      content-addressed `jackal-claim-bundle-v1` evidence graph
    * `jackal_verify_bundle`  independent caller-pinned bundle replay

The plugin does NOT ship a new checker or a new evaluator.  It is a
narrow, fail-closed adapter that binds every call through the SAME
executables the CLI release wrapper does (`jackal-native` +
`jackal_cert_check`), the SAME shared validator, the SAME formal-status
gate, and the SAME coverage inventory.  The only new trust surface is
this plugin's own bundle hash — verified at startup against the pinned
value in `release/MANIFEST.sha256`.

Fail-closed guarantees (no code path emits `formal-bounded` unless
all hold):

  P0  the plugin bundle hash equals the pin;
  P1  the parsed operator set is a subset of the inventory's FORMAL fragment;
  P2  the shared release validator returns success (evaluator+checker
      pinned identities matched, checker ACCEPT, TOCTOU stable, formal-
      status gate accepted);
  P3  the formal-bounded JSON receipt is emitted and the plugin's OWN
      bundle hash is bound into `identities.plugin_sha256`.

`jackal_verify_receipt` runs the independent verifier
      (`tools/receipt_verify.py`) end-to-end, re-executing the matching pinned checker
over the embedded certificate bytes — recomputing the outer receipt
digest alone is NOT sufficient.
"""
from __future__ import annotations

import sys

if not (sys.flags.isolated and sys.flags.no_site):
    print(
        "status=refused reason=python-not-isolated "
        "detail='invoke plugin/hermes/jackal_hermes'",
        file=sys.stderr,
    )
    raise SystemExit(126)

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any

PLUGIN_DIR = Path(__file__).resolve().parent

# Discover repo/package layout; both ship the same components at either
# `<root>/release`, `<root>/tools`, `<root>/tests` (repo) or as siblings of the
# plugin dir (shipped package).
from bundle_hash import (  # noqa: E402
    compute_bundle_hash,
    find_repo_root,
    resolve_runtime_files,
)

ROOT = find_repo_root()


def _shipped_layout() -> dict[str, Path]:
    """Locate the release wrapper, validator, verifier, and pinned binaries.

    Repo layout (development):
        <ROOT>/jackal-native
        <ROOT>/proofs/lean/.lake/build/bin/jackal_cert_check
        <ROOT>/tests/release_validate.py
        <ROOT>/tools/{formal_receipt,receipt_verify,formal_status_gate,
                       coverage_inventory}.py
        <ROOT>/release/{MANIFEST.sha256,coverage/formal_coverage_inventory.json}

    Shipped-package layout (self-contained):
        <ROOT>/jackal-native
        <ROOT>/jackal_cert_check
        <ROOT>/release_validate.py
        <ROOT>/{formal_receipt,receipt_verify,formal_status_gate,
                coverage_inventory}.py
        <ROOT>/{MANIFEST.sha256,formal_coverage_inventory.json}
    """
    layout: dict[str, Path] = {}
    # Executables
    for name, cands in (
        ("evaluator", [ROOT / "jackal-native"]),
        ("checker", [
            ROOT / "proofs/lean/.lake/build/bin/jackal_cert_check",
            ROOT / "jackal_cert_check",
        ]),
        ("archival_range_checker", [
            ROOT / "jackal_cert_check_v170",
            Path.home() / "Library/Application Support/JACKAL/runtimes/v1.7.0/jackal_cert_check",
        ]),
        ("archival_range_inventory", [
            ROOT / "evidence/formal_coverage_inventory_v170.json",
            Path.home() / "Library/Application Support/JACKAL/runtimes/v1.7.0/formal_coverage_inventory.json",
        ]),
        ("gaussian_producer", [
            ROOT / "tools/gaussian_certificate.py",
            ROOT / "gaussian_certificate.py",
        ]),
        ("gaussian_checker", [
            ROOT / "proofs/lean/.lake/build/bin/jackal_gaussian_check",
            ROOT / "jackal_gaussian_check",
        ]),
        ("int_cert_producer", [
            ROOT / "tools/int_cert_producer.py",
            ROOT / "int_cert_producer.py",
        ]),
        ("int_cert_checker", [
            ROOT / "proofs/lean/.lake/build/bin/jackal_int_cert_check",
            ROOT / "jackal_int_cert_check",
        ]),
        ("validator", [
            ROOT / "tests/release_validate.py",
            ROOT / "release_validate.py",
        ]),
        ("verifier", [
            ROOT / "tools/receipt_verify.py",
            ROOT / "receipt_verify.py",
        ]),
        ("manifest", [
            ROOT / "release/MANIFEST.sha256",
            ROOT / "MANIFEST.sha256",
        ]),
        ("inventory", [
            ROOT / "release/coverage/formal_coverage_inventory.json",
            ROOT / "formal_coverage_inventory.json",
        ]),
        ("range_proof_identity", [
            ROOT / "release/evidence/range_proof_identity_v172.json",
            ROOT / "release/evidence/range_proof_identity.json",
            ROOT / "range_proof_identity.json",
        ]),
        ("archival_range_proof_identity", [
            ROOT / "release/evidence/range_proof_identity.json",
            ROOT / "evidence/range_proof_identity_v1.json",
        ]),
        ("gaussian_proof_identity", [
            ROOT / "release/evidence/gaussian_proof_identity.json",
            ROOT / "gaussian_proof_identity.json",
        ]),
        ("int_cert_proof_identity", [
            ROOT / "release/evidence/int_cert_proof_identity_v172.json",
            ROOT / "release/evidence/int_cert_proof_identity.json",
            ROOT / "int_cert_proof_identity.json",
        ]),
        ("archival_int_cert_proof_identity", [
            ROOT / "release/evidence/int_cert_proof_identity.json",
            ROOT / "evidence/int_cert_proof_identity_v1.json",
        ]),
        ("sqrt_rat_producer", [
            ROOT / "tools/sqrt_rat_producer.py",
            ROOT / "sqrt_rat_producer.py",
        ]),
        ("exp_rat_producer", [
            ROOT / "tools/exp_rat_producer.py",
            ROOT / "exp_rat_producer.py",
        ]),
        ("ln_rat_producer", [
            ROOT / "tools/ln_rat_producer.py",
            ROOT / "ln_rat_producer.py",
        ]),
        ("sin_rat_producer", [
            ROOT / "tools/sin_rat_producer.py",
            ROOT / "sin_rat_producer.py",
        ]),
        ("atan_rat_producer", [
            ROOT / "tools/atan_rat_producer.py",
            ROOT / "atan_rat_producer.py",
        ]),
        ("tanh_rat_producer", [
            ROOT / "tools/tanh_rat_producer.py",
            ROOT / "tanh_rat_producer.py",
        ]),
        ("exact_verifier", [
            ROOT / "tools/exact_verify.py",
            ROOT / "exact_verify.py",
        ]),
        ("claim_kernel", [
            ROOT / "tools/claim_kernel.py",
            ROOT / "claim_kernel.py",
        ]),
        ("claim_router", [
            ROOT / "tools/claim_router.py",
            ROOT / "claim_router.py",
        ]),
        ("claim_verifier", [
            ROOT / "tools/claim_bundle_verify.py",
            ROOT / "claim_bundle_verify.py",
        ]),
        ("claim_inference_registry", [
            ROOT / "release/claim/inference_registry_v1.json",
            ROOT / "inference_registry_v1.json",
        ]),
        ("claim_unit_registry", [
            ROOT / "release/claim/unit_registry_v1.json",
            ROOT / "unit_registry_v1.json",
        ]),
    ):
        for c in cands:
            if c.exists():
                layout[name] = c
                break
        else:
            if name in {"archival_range_checker", "archival_range_inventory"}:
                continue
            raise SystemExit(f"plugin-layout-missing: {name} in {[str(x) for x in cands]}")
    return layout


LAYOUT = _shipped_layout()

# ``isolated_entry.py`` must preload exact source bytes.  Never fall back to
# import-path discovery: that would let an unlisted sibling or .pyc shadow a
# bundle-hashed runtime module.
_RUNTIME_FILES = resolve_runtime_files()
_EXPECTED_MODULE_PATHS = {
    "release_validate": _RUNTIME_FILES["runtime/release_validate.py"],
    "receipt_verify": _RUNTIME_FILES["runtime/receipt_verify.py"],
    "formal_status_gate": _RUNTIME_FILES["runtime/formal_status_gate.py"],
    "gaussian_release": _RUNTIME_FILES["runtime/gaussian_release.py"],
    "int_cert_release": _RUNTIME_FILES["runtime/int_cert_release.py"],
    "formal_receipt": _RUNTIME_FILES["runtime/formal_receipt.py"],
}
for _module_name, _expected_path in _EXPECTED_MODULE_PATHS.items():
    _module = sys.modules.get(_module_name)
    if _module is None or Path(getattr(_module, "__file__", "")).resolve() != \
            _expected_path.resolve():
        raise SystemExit(
            f"plugin-isolated-module-missing: {_module_name} expected {_expected_path}"
        )

import release_validate as rv  # noqa: E402
import receipt_verify as vr  # noqa: E402
import formal_status_gate as fsg  # noqa: E402
import gaussian_release as gr  # noqa: E402
import int_cert_release as icr  # noqa: E402
from formal_receipt import (  # noqa: E402
    CURRENT_PROOF_RELEASE_EPOCH,
    RANGE_ARCHIVAL_RELEASE_EPOCHS,
    _operators_in_sexp as sexp_ops,
    build_variant_formal_receipt,
    SQRT_RAT_VARIANT,
    EXP_RAT_VARIANT,
    LN_RAT_VARIANT,
    SIN_RAT_VARIANT,
    COS_RAT_VARIANT,
    ATAN_RAT_VARIANT,
    TANH_RAT_VARIANT,
    TANH_COMPOSITE_EXPRESSION,
    RATIONAL_VARIANTS,
    canonical_rat as _canonical_rat,
    request_commitment_b64 as _request_commitment_b64,
    load_proof_identity_binding,
)


def _manifest_rows(raw: bytes) -> dict[str, str]:
    """Parse and freeze the manifest labels used as this process's pin root."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SystemExit(f"plugin-manifest-not-utf8: {exc}") from exc
    rows: dict[str, str] = {}
    for number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            raise SystemExit(f"plugin-manifest-row: line {number}")
        label, value = parts[0], parts[-1]
        if label in rows:
            raise SystemExit(f"plugin-manifest-duplicate: {label}")
        rows[label] = value
    return rows


_MANIFEST_BYTES = LAYOUT["manifest"].read_bytes()
_MANIFEST_SHA256 = hashlib.sha256(_MANIFEST_BYTES).hexdigest()
_MANIFEST_ROWS = _manifest_rows(_MANIFEST_BYTES)
PLUGIN_HASH = compute_bundle_hash()
PLUGIN_HASH_PINNED = _MANIFEST_ROWS.get("plugin_hermes")


class PluginRefusal(Exception):
    def __init__(self, reason: str, detail: str = ""):
        super().__init__(f"{reason}: {detail}")
        self.reason = reason
        self.detail = detail


def _manifest_alias(labels: set[str], description: str) -> str:
    present = [(label, _MANIFEST_ROWS[label]) for label in sorted(labels)
               if label in _MANIFEST_ROWS]
    if len(present) != 1:
        raise PluginRefusal(
            "plugin-manifest-incomplete",
            f"{description}: expected exactly one of {sorted(labels)}, got {present}",
        )
    value = present[0][1]
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise PluginRefusal("plugin-manifest-hash", description)
    return value


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON constant: {value}")


def _strict_json_loads(raw: str | bytes) -> Any:
    return json.loads(
        raw,
        object_pairs_hook=_reject_duplicate_pairs,
        parse_constant=_reject_json_constant,
    )


def _startup_gate() -> None:
    """Enforce P0 — bundle hash equals pin (or fail closed at startup).

    If no pinned value is discoverable, refuse startup rather than silently
    running unpinned.  A packaged release MUST have `plugin_hermes <sha>`
    in `MANIFEST.sha256`.
    """
    if PLUGIN_HASH_PINNED is None:
        raise PluginRefusal("plugin-manifest-missing", "no `plugin_hermes` row in release/MANIFEST.sha256")
    try:
        current_manifest_sha = hashlib.sha256(LAYOUT["manifest"].read_bytes()).hexdigest()
        current_bundle_hash = compute_bundle_hash()
    except (OSError, SystemExit) as exc:
        raise PluginRefusal("plugin-runtime-unreadable", str(exc)) from exc
    if current_manifest_sha != _MANIFEST_SHA256:
        raise PluginRefusal(
            "plugin-manifest-changed",
            f"current {current_manifest_sha} != startup {_MANIFEST_SHA256}",
        )
    if current_bundle_hash != PLUGIN_HASH or current_bundle_hash != PLUGIN_HASH_PINNED:
        raise PluginRefusal("plugin-bundle-mismatch", f"current {current_bundle_hash} startup {PLUGIN_HASH} pinned {PLUGIN_HASH_PINNED}")


def _load_pinned_ids() -> tuple[str, str]:
    """Read pinned evaluator/checker sha256 from MANIFEST.sha256."""
    return (
        _manifest_alias({"evaluator"}, "evaluator"),
        _manifest_alias({"checker"}, "checker"),
    )


def _load_pinned_gaussian_ids() -> tuple[str, str]:
    """Read the pinned Gaussian producer/checker identities.

    The repository manifest uses hyphenated labels while the standalone
    package manifest uses underscore labels; both spellings are intentional
    public formats and must resolve to the same exact bytes.
    """
    return (
        _manifest_alias(
            {"gaussian-producer", "gaussian_producer"}, "Gaussian producer"
        ),
        _manifest_alias(
            {"gaussian-checker", "gaussian_checker"}, "Gaussian checker"
        ),
    )


def _load_pinned_int_cert_ids() -> tuple[str, str]:
    """Read the pinned int-cert producer/checker identities (v1.7 lane)."""
    return (
        _manifest_alias(
            {"int-cert-producer", "int_cert_producer"}, "int-cert producer"
        ),
        _manifest_alias(
            {"int-cert-checker", "int_cert_checker"}, "int-cert checker"
        ),
    )


def _load_pinned_source_id() -> str:
    """Read the exact Anubis source identity bound into range receipts."""
    return _manifest_alias({"source"}, "source")


def _load_pinned_inventory_id() -> str:
    return _manifest_alias(
        {"coverage-inventory", "coverage_inventory"}, "coverage inventory"
    )


def _load_pinned_archival_inventory_id() -> str:
    return _manifest_alias(
        {"archival-range-coverage-inventory",
         "archival_range_coverage_inventory"},
        "archival range coverage inventory",
    )


def _load_pinned_proof_ids(lane: str) -> tuple[str, str]:
    """Read exact proof-identity file and internal-digest pins.

    Repo manifests use fully hyphenated labels; package manifests use fully
    underscored labels.  Lane tokens containing a hyphen (`int-cert`) must
    normalize consistently in BOTH spellings — never a mixed separator.
    """
    lane_us = lane.replace("-", "_")
    file_labels = {f"{lane}-proof-identity", f"{lane_us}_proof_identity"}
    digest_labels = {f"{lane}-proof-digest", f"{lane_us}_proof_digest"}
    return (
        _manifest_alias(file_labels, f"{lane} proof identity"),
        _manifest_alias(digest_labels, f"{lane} proof digest"),
    )


def _load_pinned_archival_proof_ids(lane: str) -> tuple[str, str]:
    lane_us = lane.replace("-", "_")
    file_labels = {
        f"archival-{lane}-proof-identity",
        f"archival_{lane_us}_proof_identity",
    }
    digest_labels = {
        f"archival-{lane}-proof-digest",
        f"archival_{lane_us}_proof_digest",
    }
    return (
        _manifest_alias(file_labels, f"archival {lane} proof identity"),
        _manifest_alias(digest_labels, f"archival {lane} proof digest"),
    )


def _archival_checker(lane: str) -> tuple[Path, str]:
    if lane != "range":
        raise PluginRefusal("proof-compatibility",
                            f"archival {lane} replay is revoked")
    key = "archival_range_checker"
    if key not in LAYOUT:
        raise PluginRefusal("archival-runtime-unavailable", key)
    labels = {
        f"archival-{lane}-checker",
        f"archival_{lane.replace('-', '_')}_checker",
    }
    return LAYOUT[key], _manifest_alias(labels, key)


def _admitted_operators() -> set[str]:
    """Live-verified FORMAL operator set from the coverage inventory."""
    inv = fsg.load_inventory(verify_integrity=False)
    return fsg.formal_operators(inv)


def _refuse(reason: str, detail: str = "") -> dict[str, Any]:
    return {"status": "refused", "reason": reason, "detail": detail}


def _validate_args(args: dict[str, Any], keys: list[str],
                   *, object_keys: list[str] | None = None) -> None:
    if not isinstance(args, dict):
        raise PluginRefusal("plugin-args-schema", "arguments must be an object")
    objects = object_keys or []
    expected = set(keys) | set(objects)
    if set(args) != expected:
        raise PluginRefusal(
            "plugin-args-schema", f"missing/extra fields: {sorted(set(args) ^ expected)}"
        )
    for k in keys:
        v = args.get(k)
        if not isinstance(v, str) or not v:
            raise PluginRefusal("plugin-args-schema", f"missing/invalid field: {k!r}")
    for k in objects:
        if not isinstance(args.get(k), dict):
            raise PluginRefusal("plugin-args-schema", f"missing/invalid object: {k!r}")


def tool_range_bound(args: dict[str, Any]) -> dict[str, Any]:
    """Emit a formal-bounded receipt (P1..P3), or refuse.

    Preflight fragment check: the expression's operators must all be in the
    FORMAL fragment.  Because the engine's parser is a runtime component, the
    definitive check is the shared validator's operator-set gate — but a
    cheap preflight run against the evaluator's cert emission catches the
    common cases immediately, without spinning up subprocesses for non-
    formal transcendental expressions.

    On success, returns:
        {"status": "formal-bounded", "receipt": <jackal-formal-receipt-v1>}
    """
    _validate_args(args, ["expression", "input_lo", "input_hi"])
    expr = args["expression"]
    lo = args["input_lo"]
    hi = args["input_hi"]
    ev_expected, ck_expected = _load_pinned_ids()
    proof_file_expected, proof_digest_expected = _load_pinned_proof_ids("range")

    with tempfile.TemporaryDirectory(prefix="jackal-plugin-") as td:
        formal_path = os.path.join(td, "receipt.json")
        try:
            rv.validate_release(
                expr=expr, lo=lo, hi=hi,
                evaluator=str(LAYOUT["evaluator"]),
                checker=str(LAYOUT["checker"]),
                expected_evaluator=ev_expected,
                expected_checker=ck_expected,
                formal_receipt_path=formal_path,
                plugin_sha256=PLUGIN_HASH,
                release_epoch=CURRENT_PROOF_RELEASE_EPOCH,
            )
            receipt = _strict_json_loads(Path(formal_path).read_bytes())
            rerun = vr.verify_receipt(
                receipt=receipt,
                checker=str(LAYOUT["checker"]),
                expected_evaluator=ev_expected,
                expected_checker=ck_expected,
                inventory_path=LAYOUT["inventory"],
                expected_inventory_sha256=_load_pinned_inventory_id(),
                proof_identity_path=LAYOUT["range_proof_identity"],
                expected_proof_identity_file=proof_file_expected,
                expected_proof_identity_digest=proof_digest_expected,
                expected_plugin=PLUGIN_HASH,
                expected_source=_load_pinned_source_id(),
                expected_release_epoch=CURRENT_PROOF_RELEASE_EPOCH,
                expected_request={
                    "command": "range-bound-cert",
                    "expression": expr,
                    "input_lo": lo,
                    "input_hi": hi,
                },
            )
        except rv.ReleaseRefusal as r:
            # Map the validator's stable class through unchanged.  The plugin
            # never converts a bounded failure into a bounded fallback.
            return _refuse(r.cls, r.detail)
        except vr.ReceiptRefusal as r:
            return _refuse(r.cls, r.detail)

    # P1 (post-hoc): every operator in the emitted certificate must be in
    # the live FORMAL fragment.  The validator already enforces this via the
    # formal-status gate; we redo it here so a receipt-emit code-path
    # regression is caught before it leaves the plugin.
    admitted = _admitted_operators()
    stray = sorted(set(receipt["fragment"]["expression_operators"]) - admitted)
    if stray:
        return _refuse("plugin-operator-refused", f"non-formal operators: {stray}")
    # P3: plugin identity bound into the receipt.
    if receipt["identities"].get("plugin_sha256") != PLUGIN_HASH:
        return _refuse("plugin-identity-unbound",
                       f"receipt plugin={receipt['identities'].get('plugin_sha256')} != {PLUGIN_HASH}")
    if rerun.get("verdict") != "ACCEPT":
        return _refuse("plugin-checker-rerun", str(rerun.get("verdict")))
    return {"status": "formal-bounded", "checker_rerun": "ACCEPT", "receipt": receipt}


def tool_gaussian_integral(args: dict[str, Any]) -> dict[str, Any]:
    """Release one theorem-covered Gaussian integral or refuse.

    The producer is untrusted.  ``gaussian_release.release`` first requires
    the independently compiled Gaussian checker to accept the exact
    certificate.  Before the receipt leaves the plugin, this adapter then
    invokes ``receipt_verify.verify_receipt`` which rehydrates the carried
    certificate and runs that pinned checker again.  No other expression is
    routed to a weaker integration lane.
    """
    _validate_args(args, ["expression", "input_lo", "input_hi", "tolerance"])
    producer_expected, checker_expected = _load_pinned_gaussian_ids()
    proof_file_expected, proof_digest_expected = _load_pinned_proof_ids("gaussian")

    with tempfile.TemporaryDirectory(prefix="jackal-plugin-gaussian-") as td:
        receipt_path = Path(td) / "receipt.json"
        ns = argparse.Namespace(
            expression=args["expression"],
            lower=args["input_lo"],
            upper=args["input_hi"],
            tolerance=args["tolerance"],
            producer=str(LAYOUT["gaussian_producer"]),
            checker=str(LAYOUT["gaussian_checker"]),
            expected_producer=producer_expected,
            expected_checker=checker_expected,
            receipt=str(receipt_path),
            plugin_sha256=PLUGIN_HASH,
            release_epoch="v1.5.0",
            timeout=60,
        )
        try:
            gr.release(ns)
            receipt = _strict_json_loads(receipt_path.read_bytes())
            rerun = vr.verify_receipt(
                receipt=receipt,
                checker=str(LAYOUT["gaussian_checker"]),
                expected_evaluator=producer_expected,
                expected_checker=checker_expected,
                inventory_path=LAYOUT["inventory"],
                expected_inventory_sha256=_load_pinned_inventory_id(),
                proof_identity_path=LAYOUT["gaussian_proof_identity"],
                expected_proof_identity_file=proof_file_expected,
                expected_proof_identity_digest=proof_digest_expected,
                expected_plugin=PLUGIN_HASH,
                expected_release_epoch="v1.5.0",
                expected_request={
                    "command": "integrate",
                    "expression": args["expression"],
                    "input_lo": args["input_lo"],
                    "input_hi": args["input_hi"],
                    "tolerance": args["tolerance"],
                },
            )
        except gr.Refusal as r:
            return _refuse(r.cls, r.detail)
        except vr.ReceiptRefusal as r:
            return _refuse(r.cls, r.detail)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return _refuse("plugin-gaussian-runtime", f"{type(exc).__name__}: {exc}")

    if rerun.get("verdict") != "ACCEPT":
        return _refuse("plugin-checker-rerun", str(rerun.get("verdict")))
    return {"status": "formal-bounded", "checker_rerun": "ACCEPT", "receipt": receipt}


def tool_integrate_bound_cert(args: dict[str, Any]) -> dict[str, Any]:
    """Release one certified composed definite-integral enclosure or refuse.

    v1.7 bound_step composition lane: the untrusted exact-rational producer
    (tools/int_cert_producer.py) mirrors the engine's `bound_step` and emits a
    `jackal-int-cert v1` subdivision-tree artifact whose leaves embed ordinary
    evaluation certificates.  `int_cert_release.release` requires ACCEPT from
    the independently compiled proved checker `jackal_int_cert_check`
    (theorem `int_cert_sound`), binds the exact request commitment, and this
    adapter then re-verifies the emitted receipt end-to-end before returning.
    The engine's own float `integrate-bound` lane is a different, weaker tool
    (`jackal_integrate_bound`, status `bounded`) and never flows through here.
    """
    _validate_args(args, ["expression", "input_lo", "input_hi", "tolerance"])
    producer_expected, checker_expected = _load_pinned_int_cert_ids()
    proof_file_expected, proof_digest_expected = _load_pinned_proof_ids("int-cert")

    with tempfile.TemporaryDirectory(prefix="jackal-plugin-int-cert-") as td:
        receipt_path = Path(td) / "receipt.json"
        ns = argparse.Namespace(
            expression=args["expression"],
            lower=args["input_lo"],
            upper=args["input_hi"],
            tolerance=args["tolerance"],
            producer=str(LAYOUT["int_cert_producer"]),
            checker=str(LAYOUT["int_cert_checker"]),
            expected_producer=producer_expected,
            expected_checker=checker_expected,
            receipt=str(receipt_path),
            plugin_sha256=PLUGIN_HASH,
            release_epoch=CURRENT_PROOF_RELEASE_EPOCH,
            timeout=300,
        )
        try:
            icr.release(ns)
            receipt = _strict_json_loads(receipt_path.read_bytes())
            rerun = vr.verify_receipt(
                receipt=receipt,
                checker=str(LAYOUT["int_cert_checker"]),
                expected_evaluator=producer_expected,
                expected_checker=checker_expected,
                inventory_path=LAYOUT["inventory"],
                expected_inventory_sha256=_load_pinned_inventory_id(),
                proof_identity_path=LAYOUT["int_cert_proof_identity"],
                expected_proof_identity_file=proof_file_expected,
                expected_proof_identity_digest=proof_digest_expected,
                expected_plugin=PLUGIN_HASH,
                expected_release_epoch=CURRENT_PROOF_RELEASE_EPOCH,
                expected_request={
                    "command": "integrate-bound-cert",
                    "expression": args["expression"],
                    "input_lo": args["input_lo"],
                    "input_hi": args["input_hi"],
                    "tolerance": args["tolerance"],
                },
            )
        except icr.Refusal as r:
            return _refuse(r.cls, r.detail)
        except vr.ReceiptRefusal as r:
            return _refuse(r.cls, r.detail)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return _refuse("plugin-int-cert-runtime", f"{type(exc).__name__}: {exc}")

    if rerun.get("verdict") != "ACCEPT":
        return _refuse("plugin-checker-rerun", str(rerun.get("verdict")))
    return {"status": "formal-bounded", "checker_rerun": "ACCEPT", "receipt": receipt}


# variant -> MANIFEST producer label: the identity bound as `evaluator` in a
# rational-fragment receipt.  sin_rat and cos_rat share one producer file, so
# both dispatch to the `sin_rat_producer` pin.
_VARIANT_PRODUCER_LABELS = {
    SQRT_RAT_VARIANT: "sqrt_rat_producer",
    EXP_RAT_VARIANT: "exp_rat_producer",
    LN_RAT_VARIANT: "ln_rat_producer",
    SIN_RAT_VARIANT: "sin_rat_producer",
    COS_RAT_VARIANT: "sin_rat_producer",
    ATAN_RAT_VARIANT: "atan_rat_producer",
    TANH_RAT_VARIANT: "tanh_rat_producer",
}


def tool_verify_receipt(args: dict[str, Any]) -> dict[str, Any]:
    """Re-run the pinned Lean-proved checker over an embedded certificate.

    This is NOT a signature check.  The verifier extracts the certificate
    bytes, writes them to a fresh mode-0600 tempfile, and invokes the
    pinned `jackal_cert_check` binary on them.  Only an ACCEPT return
    combined with all binding gates (see `tools/receipt_verify.py`)
    yields `verified`; anything else is a stable refusal.
    """
    if not isinstance(args, dict):
        return _refuse("plugin-args-schema", "arguments must be an object")
    receipt = args.get("receipt")
    if not isinstance(receipt, dict):
        return _refuse("plugin-args-schema", "receipt must be an object")
    cert_schema = receipt.get("certificate", {}).get("schema")
    if cert_schema in {"jackal-gaussian-integral-cert v1", "jackal-int-cert v1"}:
        string_keys = [
            "expected_release_epoch", "expected_command", "expected_expression",
            "expected_input_lo", "expected_input_hi", "expected_tolerance",
        ]
    elif cert_schema == "jackal-eval-cert v2":
        string_keys = [
            "expected_release_epoch", "expected_command", "expected_expression",
            "expected_input_lo", "expected_input_hi",
        ]
    else:
        return _refuse("cert-schema", str(cert_schema))
    try:
        _validate_args(args, string_keys, object_keys=["receipt"])
    except PluginRefusal as refusal:
        return _refuse(refusal.reason, refusal.detail)
    epoch = args["expected_release_epoch"]
    archival_receipt_context = False
    inventory_path = LAYOUT["inventory"]
    inventory_expected = _load_pinned_inventory_id()
    if cert_schema == "jackal-gaussian-integral-cert v1":
        ev_expected, ck_expected = _load_pinned_gaussian_ids()
        checker = LAYOUT["gaussian_checker"]
        proof_file_expected, proof_digest_expected = _load_pinned_proof_ids("gaussian")
        proof_identity_path = LAYOUT["gaussian_proof_identity"]
        expected_source_val = None
        expected_request = {
            "command": args["expected_command"],
            "expression": args["expected_expression"],
            "input_lo": args["expected_input_lo"],
            "input_hi": args["expected_input_hi"],
            "tolerance": args["expected_tolerance"],
        }
    elif cert_schema == "jackal-int-cert v1":
        ev_expected, current_checker_expected = _load_pinned_int_cert_ids()
        if epoch == CURRENT_PROOF_RELEASE_EPOCH:
            checker = LAYOUT["int_cert_checker"]
            ck_expected = current_checker_expected
            proof_file_expected, proof_digest_expected = \
                _load_pinned_proof_ids("int-cert")
            proof_identity_path = LAYOUT["int_cert_proof_identity"]
        else:
            return _refuse("proof-compatibility", f"unsupported int-cert epoch {epoch!r}")
        expected_source_val = None
        expected_request = {
            "command": args["expected_command"],
            "expression": args["expected_expression"],
            "input_lo": args["expected_input_lo"],
            "input_hi": args["expected_input_hi"],
            "tolerance": args["expected_tolerance"],
        }
    else:
        # variant is optional in the envelope; missing = range (backward compat)
        variant = receipt.get("variant") or "range"
        if epoch in RANGE_ARCHIVAL_RELEASE_EPOCHS:
            archival_receipt_context = True
            checker, ck_expected = _archival_checker("range")
            if "archival_range_inventory" not in LAYOUT:
                return _refuse(
                    "archival-runtime-unavailable",
                    "archival_range_inventory",
                )
            inventory_path = LAYOUT["archival_range_inventory"]
            inventory_expected = _load_pinned_archival_inventory_id()
            proof_file_expected, proof_digest_expected = \
                _load_pinned_archival_proof_ids("range")
            proof_identity_path = LAYOUT["archival_range_proof_identity"]
        elif epoch == CURRENT_PROOF_RELEASE_EPOCH:
            checker = LAYOUT["checker"]
            _, ck_expected = _load_pinned_ids()
            proof_file_expected, proof_digest_expected = \
                _load_pinned_proof_ids("range")
            proof_identity_path = LAYOUT["range_proof_identity"]
        else:
            return _refuse("proof-compatibility", f"unsupported range epoch {epoch!r}")
        expected_request = {
            "command": args["expected_command"],
            "expression": args["expected_expression"],
            "input_lo": args["expected_input_lo"],
            "input_hi": args["expected_input_hi"],
        }
        if variant in _VARIANT_PRODUCER_LABELS:
            label = _VARIANT_PRODUCER_LABELS[variant]
            ev_expected = _manifest_alias({label}, label)
            expected_source_val = None
        else:
            ev_expected, _current_checker_expected = _load_pinned_ids()
            expected_source_val = _load_pinned_source_id()
    receipt_plugin = receipt.get("identities", {}).get("plugin_sha256")
    archival_plugin = _manifest_alias(
        {"archival-plugin-hermes", "archival_plugin_hermes"},
        "archival plugin identity",
    )
    if receipt_plugin is None:
        expected_plugin = None
    elif cert_schema == "jackal-gaussian-integral-cert v1" and \
            receipt_plugin in {PLUGIN_HASH, archival_plugin}:
        # Gaussian checker/proof bytes and its v1.5 epoch are intentionally
        # unchanged, so both exact plugin generations are valid contexts.
        expected_plugin = receipt_plugin
    elif archival_receipt_context and receipt_plugin == archival_plugin:
        expected_plugin = archival_plugin
    elif not archival_receipt_context and receipt_plugin == PLUGIN_HASH:
        expected_plugin = PLUGIN_HASH
    else:
        return _refuse(
            "plugin-identity",
            "receipt plugin is not valid for the selected proof epoch",
        )
    try:
        result = vr.verify_receipt(
            receipt=receipt,
            checker=str(checker),
            expected_evaluator=ev_expected,
            expected_checker=ck_expected,
            inventory_path=inventory_path,
            expected_inventory_sha256=inventory_expected,
            proof_identity_path=proof_identity_path,
            expected_proof_identity_file=proof_file_expected,
            expected_proof_identity_digest=proof_digest_expected,
            expected_plugin=expected_plugin,
            expected_source=expected_source_val,
            expected_release_epoch=args["expected_release_epoch"],
            expected_request=expected_request,
        )
    except vr.ReceiptRefusal as r:
        return _refuse(r.cls, r.detail)
    return {"status": "verified", **result}

# -- pure-Q fragment adapters: sqrt/exp/ln/sin/cos/atan/tanh (v1.4.0–v1.5.0) --
#
# These tools route around `jackal-native` entirely: they invoke the pinned
# standalone Python producer for their variant (`tools/<variant>_producer.py`;
# sin_rat and cos_rat share `tools/sin_rat_producer.py` via `--op sin|cos`)
# with identity hashed pre/post, feed its canonical certificate bytes to the
# SAME pinned `jackal_cert_check` every other formal lane uses (also identity
# hashed pre/post), and only return a `status=formal-bounded` payload when
# the checker prints ACCEPT.  Producer identities are pinned in
# `MANIFEST.sha256` under `<variant>_producer` labels (`sin_rat_producer`
# covers both sin_rat and cos_rat).  Each tool admits only the exact
# expression form frozen in `formal_receipt` for its variant; every other
# expression refuses `plugin-fragment` / `producer-refused` without
# downgrade.  The payload embeds a full `jackal-formal-receipt-v1` envelope
# (variant marker set) with the base64 cert bytes and their SHA-256, so a
# downstream consumer can save, independently re-check, and round-trip the
# receipt through `jackal_verify_receipt`.


def _run_rational_producer(
    producer_path: Path, expected_producer_sha: str,
    expr: str, lo: str, hi: str, extra_args: list[str] | None = None,
) -> bytes:
    """Invoke a pure-Q producer with TOCTOU-stable identity + fail-closed refusal."""
    pre = hashlib.sha256(producer_path.read_bytes()).hexdigest()
    if pre != expected_producer_sha:
        raise PluginRefusal(
            "producer-identity", f"{producer_path.name}: {pre} != pinned {expected_producer_sha}"
        )
    proc = subprocess.run(
        [sys.executable, "-I", "-S", "-B", str(producer_path), "emit",
         *(extra_args or []),
         "--expression", expr, "--lower", lo, "--upper", hi],
        capture_output=True, timeout=60,
    )
    post = hashlib.sha256(producer_path.read_bytes()).hexdigest()
    if post != pre:
        raise PluginRefusal("producer-toctou", f"{producer_path.name} bytes changed across call")
    if proc.returncode != 0:
        raw = (proc.stderr.decode("utf-8", "replace").strip()
               or proc.stdout.decode("utf-8", "replace").strip())
        # Strip the producer's own `REFUSE ` prefix so the plugin surface
        # sees a clean detail line and downstream selects a stable class.
        detail = raw.split("\n")[0].removeprefix("REFUSE ")[:300]
        raise PluginRefusal("producer-refused", detail)
    return proc.stdout


def _run_checker_on_cert_bytes(
    cert_bytes: bytes, command: str, expr: str, lo: str, hi: str,
    expected_checker_sha: str,
) -> tuple[str, str]:
    """Feed a producer cert to the pinned `jackal_cert_check` with request framing."""
    checker_path = LAYOUT["checker"]
    pre = hashlib.sha256(checker_path.read_bytes()).hexdigest()
    if pre != expected_checker_sha:
        raise PluginRefusal("checker-identity", f"{pre} != pinned {expected_checker_sha}")
    with tempfile.NamedTemporaryFile("wb", suffix=".cert", delete=False) as f:
        f.write(cert_bytes)
        cert_path = f.name
    try:
        proc = subprocess.run(
            [str(checker_path), cert_path, command, expr, lo, hi],
            capture_output=True, text=True, timeout=60,
        )
    finally:
        try:
            os.unlink(cert_path)
        except OSError:
            pass
    post = hashlib.sha256(checker_path.read_bytes()).hexdigest()
    if post != pre:
        raise PluginRefusal("checker-toctou", "checker bytes changed across call")
    if proc.returncode != 0:
        detail = ((proc.stdout + proc.stderr).strip().split("\n")[0])[:300]
        raise PluginRefusal("checker-rejected", detail)
    if "ACCEPT" not in proc.stdout:
        raise PluginRefusal("checker-no-accept", proc.stdout.strip()[:300])
    return proc.stdout.strip(), pre


def _parse_cert_enclosure(cert_bytes: bytes) -> tuple[str, str]:
    """Extract the `output <lo> <hi>` header field from a canonical cert."""
    text = cert_bytes.decode("utf-8", "replace")
    m = re.search(r"(?m)^output\s+(\S+)\s+(\S+)\s*$", text)
    if not m:
        raise PluginRefusal("plugin-cert-shape", "no `output` line in emitted cert")
    return m.group(1), m.group(2)


def _rational_bound_result(
    *, variant: str, admitted_expr: str, producer_key: str,
    producer_manifest_label: str, expr: str, lo: str, hi: str,
    extra_producer_args: list[str] | None = None,
) -> dict[str, Any]:
    """Common body for the pure-ℚ rational-fragment bound tools.

    Emits a full `jackal-formal-receipt-v1` envelope with `variant` set
    (`sqrt_rat` / `exp_rat` / `ln_rat` / `sin_rat` / `cos_rat` / `atan_rat`
    / `tanh_rat`), so downstream can round-trip through
    `jackal_verify_receipt` (v1.4.2+).
    """
    if variant not in RATIONAL_VARIANTS:
        raise PluginRefusal("plugin-fragment", f"unknown variant {variant!r}")
    if expr.replace(" ", "") != admitted_expr:
        raise PluginRefusal(
            "plugin-fragment",
            f"{variant} admits ONLY `{admitted_expr}`; got {expr!r}",
        )
    expected_producer = _manifest_alias({producer_manifest_label}, producer_manifest_label)
    _, expected_checker = _load_pinned_ids()
    producer_path = LAYOUT[producer_key]
    cert_bytes = _run_rational_producer(producer_path, expected_producer,
                                        expr, lo, hi, extra_producer_args)
    encl_lo, encl_hi = _parse_cert_enclosure(cert_bytes)
    checker_out, checker_sha = _run_checker_on_cert_bytes(
        cert_bytes, "range-bound-cert", expr, lo, hi, expected_checker,
    )
    # Assemble the canonical envelope so jackal_verify_receipt can round-trip.
    canon_lo = _canonical_rat(lo)
    canon_hi = _canonical_rat(hi)
    req_commit = _request_commitment_b64("range-bound-cert", expr, lo, hi)
    proof_binding = load_proof_identity_binding(LAYOUT["range_proof_identity"])
    inv_bytes = LAYOUT["inventory"].read_bytes()
    inv_sha = hashlib.sha256(inv_bytes).hexdigest()
    receipt = build_variant_formal_receipt(
        variant=variant,
        release_epoch=CURRENT_PROOF_RELEASE_EPOCH,
        request={"command": "range-bound-cert", "expression": expr,
                 "input_lo": lo, "input_hi": hi},
        enclosure=(encl_lo, encl_hi),
        cert_bytes=cert_bytes,
        producer_sha256=expected_producer,
        checker_sha256=checker_sha,
        canonical_lo=canon_lo,
        canonical_hi=canon_hi,
        request_commitment_b64=req_commit,
        coverage_inventory_sha256=inv_sha,
        proof_identity=proof_binding,
        plugin_sha256=PLUGIN_HASH,
    )
    return {
        "status": "formal-bounded",
        "variant": variant,
        "checker_rerun": "ACCEPT",
        "checker_output": checker_out,
        "receipt": receipt,
    }


def tool_sqrt_rat_bound(args: dict[str, Any]) -> dict[str, Any]:
    """Emit a pure-Q sqrt(x) enclosure or refuse (v1.4.0 fragment extension)."""
    _validate_args(args, ["expression", "input_lo", "input_hi"])
    return _rational_bound_result(
        variant="sqrt_rat",
        admitted_expr="sqrt(x)",
        producer_key="sqrt_rat_producer",
        producer_manifest_label="sqrt_rat_producer",
        expr=args["expression"], lo=args["input_lo"], hi=args["input_hi"],
    )


def tool_exp_rat_bound(args: dict[str, Any]) -> dict[str, Any]:
    """Emit a pure-Q exp(x) enclosure or refuse (v1.4.1 fragment extension)."""
    _validate_args(args, ["expression", "input_lo", "input_hi"])
    return _rational_bound_result(
        variant="exp_rat",
        admitted_expr="exp(x)",
        producer_key="exp_rat_producer",
        producer_manifest_label="exp_rat_producer",
        expr=args["expression"], lo=args["input_lo"], hi=args["input_hi"],
    )


def tool_ln_rat_bound(args: dict[str, Any]) -> dict[str, Any]:
    """Emit a pure-Q ln(x) enclosure or refuse (v1.5.0 fragment extension)."""
    _validate_args(args, ["expression", "input_lo", "input_hi"])
    return _rational_bound_result(
        variant=LN_RAT_VARIANT,
        admitted_expr="ln(x)",
        producer_key="ln_rat_producer",
        producer_manifest_label="ln_rat_producer",
        expr=args["expression"], lo=args["input_lo"], hi=args["input_hi"],
    )


def tool_sin_rat_bound(args: dict[str, Any]) -> dict[str, Any]:
    """Emit a pure-Q sin(x) enclosure or refuse (v1.5.0 fragment extension)."""
    _validate_args(args, ["expression", "input_lo", "input_hi"])
    return _rational_bound_result(
        variant=SIN_RAT_VARIANT,
        admitted_expr="sin(x)",
        producer_key="sin_rat_producer",
        producer_manifest_label="sin_rat_producer",
        expr=args["expression"], lo=args["input_lo"], hi=args["input_hi"],
        extra_producer_args=["--op", "sin"],
    )


def tool_cos_rat_bound(args: dict[str, Any]) -> dict[str, Any]:
    """Emit a pure-Q cos(x) enclosure or refuse (v1.5.0 fragment extension)."""
    _validate_args(args, ["expression", "input_lo", "input_hi"])
    return _rational_bound_result(
        variant=COS_RAT_VARIANT,
        admitted_expr="cos(x)",
        producer_key="sin_rat_producer",
        producer_manifest_label="sin_rat_producer",
        expr=args["expression"], lo=args["input_lo"], hi=args["input_hi"],
        extra_producer_args=["--op", "cos"],
    )


def tool_atan_rat_bound(args: dict[str, Any]) -> dict[str, Any]:
    """Emit a pure-Q atan(x) enclosure or refuse (v1.5.0 fragment extension)."""
    _validate_args(args, ["expression", "input_lo", "input_hi"])
    return _rational_bound_result(
        variant=ATAN_RAT_VARIANT,
        admitted_expr="atan(x)",
        producer_key="atan_rat_producer",
        producer_manifest_label="atan_rat_producer",
        expr=args["expression"], lo=args["input_lo"], hi=args["input_hi"],
    )


def tool_tanh_rat_bound(args: dict[str, Any]) -> dict[str, Any]:
    """Emit a pure-Q tanh enclosure via its composite defining expression, or
    refuse (v1.5.0 fragment extension).

    `tanh` is not an engine grammar token: the receipt binds the literal
    composite expression frozen in `formal_receipt.TANH_COMPOSITE_EXPRESSION`
    and the tanh reading is a documented mathematical identity.  Producer
    budget: |x| <= 20.
    """
    _validate_args(args, ["expression", "input_lo", "input_hi"])
    return _rational_bound_result(
        variant=TANH_RAT_VARIANT,
        admitted_expr=TANH_COMPOSITE_EXPRESSION,
        producer_key="tanh_rat_producer",
        producer_manifest_label="tanh_rat_producer",
        expr=args["expression"], lo=args["input_lo"], hi=args["input_hi"],
    )


# -- weaker-lane adapters (non-formal; status passthrough, never inflated) ----
#
# Each adapter invokes the PINNED evaluator binary directly (identity hashed
# before and after, exactly like the release gate) and returns the engine's
# verbatim output plus a machine-readable epistemic class.  The class is
# derived from the COVERAGE INVENTORY row for the lane — never hardcoded to a
# stronger value, never `formal-*`.  If the engine's own printed `status=`
# disagrees with the inventory row, the adapter REFUSES rather than pick one
# (`plugin-lane-status-divergence`).  These lanes carry NO certificate and NO
# theorem: their receipts are honest evidence of what was computed and by
# which exact binary, not proofs.

_WEAK_LANE_TOOLS: dict[str, dict[str, Any]] = {
    "jackal_exact": {
        "lane": "rat",
        "args": ["expression"],
        "argv": lambda a: ["rat", a["expression"]],
    },
    "jackal_evaluate": {
        "lane": "eval",
        "args": ["expression"],
        "argv": lambda a: ["eval", a["expression"]],
    },
    "jackal_diff": {
        "lane": "diff",
        "args": ["expression"],
        "argv": lambda a: ["diff", a["expression"]],
    },
    "jackal_integrate": {
        "lane": "integrate",
        "args": ["expression", "input_lo", "input_hi", "panels"],
        "argv": lambda a: ["integrate", a["expression"], a["input_lo"],
                            a["input_hi"], a["panels"]],
    },
    "jackal_integrate_adaptive": {
        "lane": "integrate-adaptive",
        "args": ["expression", "input_lo", "input_hi", "tolerance"],
        "argv": lambda a: ["integrate-adaptive", a["expression"], a["input_lo"],
                            a["input_hi"], a["tolerance"]],
    },
    "jackal_integrate_bound": {
        "lane": "integrate-bound",
        "args": ["expression", "input_lo", "input_hi", "tolerance"],
        "argv": lambda a: ["integrate-bound", a["expression"], a["input_lo"],
                            a["input_hi"], a["tolerance"]],
    },
    "jackal_solve": {
        "lane": "solve",
        "args": ["expression", "input_lo", "input_hi"],
        "argv": lambda a: ["solve", a["expression"], a["input_lo"], a["input_hi"]],
    },
    # -- exact CAS / number-theory lanes (§490 v1.5.0) ------------------------
    # Engine-computed `status=exact` lanes.  Where the engine emits one, the
    # final stdout line carries a `jackal-exact-cert-v1` certificate
    # (`exact-cert={...}`) that `tools/exact_verify.py` re-checks by full
    # independent recomputation (canon/alg-sign/alg-cmp/divides carry no or a
    # partial certificate).  NOT formal: no Lean checker involvement; the
    # inventory row class is `exact` and passthrough never inflates it.
    "jackal_canon": {
        "lane": "canon",
        "args": ["expression"],
        "argv": lambda a: ["canon", a["expression"]],
    },
    "jackal_poly_canon": {
        "lane": "poly-canon",
        "args": ["expression"],
        "argv": lambda a: ["poly-canon", a["expression"]],
    },
    "jackal_poly_eq": {
        "lane": "poly-eq",
        "args": ["lhs", "rhs"],
        "argv": lambda a: ["poly-eq", a["lhs"], a["rhs"]],
    },
    "jackal_poly_gcd": {
        "lane": "poly-gcd",
        "args": ["lhs", "rhs"],
        "argv": lambda a: ["poly-gcd", a["lhs"], a["rhs"]],
    },
    "jackal_ratfunc_canon": {
        "lane": "ratfunc-canon",
        "args": ["expression"],
        "argv": lambda a: ["ratfunc-canon", a["expression"]],
    },
    "jackal_roots_isolate": {
        "lane": "roots-isolate",
        "args": ["expression"],
        "argv": lambda a: ["roots-isolate", a["expression"]],
    },
    "jackal_alg_sign": {
        "lane": "alg-sign",
        "args": ["expression", "point"],
        "argv": lambda a: ["alg-sign", a["expression"], a["point"]],
    },
    "jackal_alg_cmp": {
        "lane": "alg-cmp",
        "args": ["p", "a1", "b1", "q", "a2", "b2"],
        "argv": lambda a: ["alg-cmp", a["p"], a["a1"], a["b1"],
                            a["q"], a["a2"], a["b2"]],
    },
    "jackal_xgcd": {
        "lane": "xgcd",
        "args": ["a", "b"],
        "argv": lambda a: ["xgcd", a["a"], a["b"]],
    },
    "jackal_mod_pow": {
        "lane": "mod-pow",
        "args": ["base", "exp", "mod"],
        "argv": lambda a: ["mod-pow", a["base"], a["exp"], a["mod"]],
    },
    "jackal_mod_inv": {
        "lane": "mod-inv",
        "args": ["a", "m"],
        "argv": lambda a: ["mod-inv", a["a"], a["m"]],
    },
    "jackal_crt": {
        "lane": "crt",
        "args": ["args"],
        "argv": lambda a: ["crt", *a["args"].split()],
    },
    "jackal_divides": {
        "lane": "divides",
        "args": ["a", "b"],
        "argv": lambda a: ["divides", a["a"], a["b"]],
    },
    "jackal_prime_cert": {
        "lane": "prime-cert",
        "args": ["n"],
        "argv": lambda a: ["prime-cert", a["n"]],
    },
}

# Epistemic classes a weaker lane may legitimately print.  `formal-*` is
# structurally impossible here: it is not in this set, and the inventory rows
# for these lanes never carry it.
_WEAK_ALLOWED_STATUSES = {"exact", "checked", "estimated", "bounded", "model-based"}


def _lane_inventory_row(lane: str) -> dict[str, Any]:
    inv = fsg.load_inventory(verify_integrity=False)
    row = inv["by_op"].get(lane)
    if row is None:
        raise PluginRefusal("plugin-lane-unregistered",
                            f"no coverage-inventory row for lane {lane!r}")
    return row


def _parse_engine_fields(stdout_text: str) -> dict[str, str]:
    """Collect `key=value` tokens from the engine's metadata lines."""
    fields: dict[str, str] = {}
    for line in stdout_text.splitlines():
        if line.startswith("exact-cert="):
            # The exact-lane certificate is one raw JSON object whose string
            # fields may contain spaces or `=`; carry the whole line verbatim
            # so downstream can hand it to `tools/exact_verify.py` unchanged.
            fields.setdefault("exact_cert", line[len("exact-cert="):])
            continue
        for token in line.split():
            if "=" in token:
                key, _, value = token.partition("=")
                if key and key not in fields:
                    fields[key] = value
    return fields


def _run_pinned_evaluator(argv: list[str]) -> tuple[str, str]:
    """Invoke the pinned evaluator with identity hashed pre/post (TOCTOU)."""
    expected, _ = _load_pinned_ids()
    eval_path = str(LAYOUT["evaluator"])
    pre = hashlib.sha256(Path(eval_path).read_bytes()).hexdigest()
    if pre != expected:
        raise PluginRefusal("evaluator-identity", f"{pre} != pinned {expected}")
    proc = subprocess.run([eval_path, *argv], capture_output=True, text=True,
                          timeout=600)
    post = hashlib.sha256(Path(eval_path).read_bytes()).hexdigest()
    if post != pre:
        raise PluginRefusal("evaluator-toctou", "evaluator bytes changed across call")
    if proc.returncode != 0:
        raw_detail = (proc.stderr.strip() or proc.stdout.strip())
        # The engine's named refusal reason is the `ANUBIS_PANIC: <reason>`
        # line; the surrounding Rust panic preamble/backtrace hint is noise.
        detail = next(
            (ln.split("ANUBIS_PANIC: ", 1)[1]
             for ln in raw_detail.splitlines() if "ANUBIS_PANIC: " in ln),
            raw_detail.split("\n")[0],
        )[:300]
        raise PluginRefusal("evaluator-refused", detail)
    return proc.stdout, pre


def _make_weak_tool(tool_name: str, spec: dict[str, Any]):
    lane = spec["lane"]

    def tool(args: dict[str, Any]) -> dict[str, Any]:
        _validate_args(args, list(spec["args"]))
        row = _lane_inventory_row(lane)
        allowed = row["allowed_status"]
        if allowed not in _WEAK_ALLOWED_STATUSES:
            raise PluginRefusal("plugin-lane-status",
                                f"inventory row {lane!r} allows {allowed!r} which is "
                                "outside the weaker-lane class set")
        stdout_text, evaluator_sha = _run_pinned_evaluator(spec["argv"](args))
        fields = _parse_engine_fields(stdout_text)
        printed = fields.get("status")
        if printed is not None and printed != allowed:
            # The engine's own printed class must equal the registry row —
            # divergence is refused, never resolved by picking the stronger.
            raise PluginRefusal(
                "plugin-lane-status-divergence",
                f"engine printed status={printed!r} but inventory row {lane!r} "
                f"allows {allowed!r}")
        return {
            "status": allowed,
            "lane": lane,
            "formal": False,
            "engine_output": stdout_text.rstrip("\n"),
            "fields": fields,
            "assurance": fields.get("assurance", row.get("description", "")),
            "identities": {"evaluator_sha256": evaluator_sha},
            "non_claims": [
                "NOT formal-bounded: this lane carries no Lean-checked certificate",
                "The epistemic class above is the STRONGEST claim this result supports",
                row.get("description", ""),
            ],
        }

    tool.__name__ = f"tool_{tool_name}"
    return tool


# -- claim-bundle evidence kernel (v1.6.0, additive) ---------------------------

def _claim_component(label: str) -> tuple[Path, str]:
    """Resolve a claim-kernel component and its manifest pin (fail closed)."""
    path = LAYOUT[label]
    pin = _MANIFEST_ROWS.get(label)
    if not pin:
        raise PluginRefusal("plugin-identity",
                            f"manifest row {label!r} missing")
    live = hashlib.sha256(path.read_bytes()).hexdigest()
    if live != pin:
        raise PluginRefusal("plugin-identity",
                            f"{label} bytes do not match the manifest pin")
    return path, pin


def _claim_toctou(label: str, path: Path, pin: str) -> None:
    if hashlib.sha256(path.read_bytes()).hexdigest() != pin:
        raise PluginRefusal("plugin-identity", f"{label} changed mid-call")


def tool_jackal_claim(args: dict[str, Any]) -> dict[str, Any]:
    """Compile a structured claim request into a jackal-claim-bundle-v1
    through the deterministic policy router, or refuse.

    On success, returns:
        {"status": "ok", "root": ..., "bundle_digest_sha256": ...,
         "rendering": {...}, "route_trace": [...], "bundle": {...}}
    """
    _validate_args(args, [], object_keys=["request"])
    router_path, router_pin = _claim_component("claim_router")
    kernel_path, kernel_pin = _claim_component("claim_kernel")
    with tempfile.TemporaryDirectory(prefix="jackal-plugin-claim-") as td:
        req_path = os.path.join(td, "request.json")
        bundle_path = os.path.join(td, "bundle.json")
        with open(req_path, "w", encoding="utf-8") as handle:
            json.dump(args["request"], handle, sort_keys=True)
        try:
            proc = subprocess.run(
                [sys.executable, "-I", "-S", "-B", str(router_path),
                 "claim", "--request", req_path,
                 "--emit-bundle", bundle_path],
                capture_output=True, text=True, timeout=900)
        except subprocess.TimeoutExpired:
            return _refuse("plugin-subprocess", "claim router timeout")
        _claim_toctou("claim_router", router_path, router_pin)
        _claim_toctou("claim_kernel", kernel_path, kernel_pin)
        stdout = proc.stdout or ""
        if proc.returncode != 0:
            reason, detail = "plugin-claim-refused", stdout.strip()[:300]
            for line in stdout.splitlines():
                if line.startswith("status=refused"):
                    parts = line.split("reason=", 1)
                    if len(parts) == 2:
                        reason = parts[1].split()[0]
                    if 'detail="' in line:
                        detail = line.split('detail="', 1)[1].rstrip('"')
                    break
            return _refuse(reason, detail)
        try:
            bundle = _strict_json_loads(
                Path(bundle_path).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            return _refuse("plugin-claim-bundle", str(exc)[:200])
    fields: dict[str, str] = {}
    trace: list[Any] = []
    for line in stdout.splitlines():
        if line.startswith("route_trace="):
            trace = json.loads(line[len("route_trace="):])
        elif "=" in line and not line.startswith("bundle="):
            key, _, value = line.partition("=")
            fields[key] = value
    return {
        "status": "ok",
        "root": fields.get("root", bundle.get("root", "")),
        "bundle_digest_sha256": bundle.get("bundle_digest_sha256", ""),
        "rendering": bundle.get("rendering"),
        "route_trace": trace,
        "bundle": bundle,
    }


def tool_jackal_verify_bundle(args: dict[str, Any]) -> dict[str, Any]:
    """Independently replay a claim bundle against caller-pinned
    expectations through the standalone dependency-free verifier.

    Returns {"status": "verified"|"refused"|"indeterminate", ...} — never
    a bare badge; the full axis/rendering report rides in "report".
    """
    allowed = {"bundle", "expected_release_epoch",
               "expected_policy_sha256", "expected_root_proposition",
               "verification_time_unix", "expected_nonce"}
    required = allowed - {"expected_nonce"}
    if not isinstance(args, dict):
        raise PluginRefusal("plugin-args-schema",
                            "arguments must be an object")
    if not required <= set(args) or not set(args) <= allowed:
        raise PluginRefusal(
            "plugin-args-schema",
            f"missing/extra fields: {sorted(set(args) ^ required)}")
    if not isinstance(args["bundle"], dict):
        raise PluginRefusal("plugin-args-schema", "bundle must be an object")
    if not isinstance(args["expected_root_proposition"], dict):
        raise PluginRefusal("plugin-args-schema",
                            "expected_root_proposition must be an object")
    for key in ("expected_release_epoch", "expected_policy_sha256",
                "verification_time_unix"):
        if not isinstance(args[key], str) or not args[key]:
            raise PluginRefusal("plugin-args-schema",
                                f"missing/invalid field: {key!r}")
    if not re.fullmatch(r"0|[1-9][0-9]*", args["verification_time_unix"]):
        raise PluginRefusal(
            "plugin-args-schema",
            "verification_time_unix must be a nonnegative integer token")
    verifier_path, verifier_pin = _claim_component("claim_verifier")
    inf_path, inf_pin = _claim_component("claim_inference_registry")
    unit_path, unit_pin = _claim_component("claim_unit_registry")
    ev_expected, ck_expected = _load_pinned_ids()
    proof_file_expected, proof_digest_expected = \
        _load_pinned_proof_ids("range")
    gaussian_producer_expected, gaussian_checker_expected = \
        _load_pinned_gaussian_ids()
    gaussian_proof_file_expected, gaussian_proof_digest_expected = \
        _load_pinned_proof_ids("gaussian")
    int_producer_expected, int_checker_expected = \
        _load_pinned_int_cert_ids()
    int_proof_file_expected, int_proof_digest_expected = \
        _load_pinned_proof_ids("int-cert")
    with tempfile.TemporaryDirectory(prefix="jackal-plugin-claim-") as td:
        bundle_path = os.path.join(td, "bundle.json")
        prop_path = os.path.join(td, "root_prop.json")
        with open(bundle_path, "w", encoding="utf-8") as handle:
            json.dump(args["bundle"], handle, indent=1, sort_keys=True)
        with open(prop_path, "w", encoding="utf-8") as handle:
            json.dump(args["expected_root_proposition"], handle,
                      sort_keys=True)
        argv = [sys.executable, "-I", "-S", "-B", str(verifier_path),
                "--bundle", bundle_path,
                "--expected-release-epoch", args["expected_release_epoch"],
                "--expected-policy-sha256", args["expected_policy_sha256"],
                "--expected-root-proposition", prop_path,
                "--expected-inference-registry", str(inf_path),
                "--expected-inference-registry-sha256", inf_pin,
                "--expected-unit-registry", str(unit_path),
                "--expected-unit-registry-sha256", unit_pin,
                "--expected-environment-epoch", ev_expected,
                "--verification-time-unix", args["verification_time_unix"],
                "--receipt-verifier", str(LAYOUT["verifier"]),
                "--exact-verifier", str(LAYOUT["exact_verifier"]),
                "--checker", str(LAYOUT["checker"]),
                "--expected-checker", ck_expected,
                "--expected-evaluator", ev_expected,
                "--inventory", str(LAYOUT["inventory"]),
                "--expected-inventory",
                _load_pinned_inventory_id(),
                "--proof-identity", str(LAYOUT["range_proof_identity"]),
                "--expected-proof-identity-file", proof_file_expected,
                "--expected-proof-identity-digest", proof_digest_expected,
                "--gaussian-checker", str(LAYOUT["gaussian_checker"]),
                "--expected-gaussian-checker",
                gaussian_checker_expected,
                "--gaussian-proof-identity",
                str(LAYOUT["gaussian_proof_identity"]),
                "--expected-gaussian-proof-identity-file",
                gaussian_proof_file_expected,
                "--expected-gaussian-proof-identity-digest",
                gaussian_proof_digest_expected,
                "--int-cert-checker", str(LAYOUT["int_cert_checker"]),
                "--expected-int-cert-checker", int_checker_expected,
                "--int-cert-proof-identity",
                str(LAYOUT["int_cert_proof_identity"]),
                "--expected-int-cert-proof-identity-file",
                int_proof_file_expected,
                "--expected-int-cert-proof-identity-digest",
                int_proof_digest_expected]
        if "archival_range_checker" in LAYOUT and \
                "archival_range_inventory" in LAYOUT:
            archival_checker, archival_checker_expected = \
                _archival_checker("range")
            archival_proof_file_expected, archival_proof_digest_expected = \
                _load_pinned_archival_proof_ids("range")
            argv += [
                "--archival-range-checker", str(archival_checker),
                "--expected-archival-range-checker",
                archival_checker_expected,
                "--archival-range-proof-identity",
                str(LAYOUT["archival_range_proof_identity"]),
                "--expected-archival-range-proof-identity-file",
                archival_proof_file_expected,
                "--expected-archival-range-proof-identity-digest",
                archival_proof_digest_expected,
                "--archival-range-inventory",
                str(LAYOUT["archival_range_inventory"]),
                "--expected-archival-range-inventory",
                _load_pinned_archival_inventory_id(),
            ]
        if "expected_nonce" in args:
            if not isinstance(args["expected_nonce"], str):
                raise PluginRefusal("plugin-args-schema",
                                    "expected_nonce must be a string")
            argv += ["--expected-nonce", args["expected_nonce"]]
        for label in ("sqrt_rat_producer", "exp_rat_producer",
                      "ln_rat_producer", "sin_rat_producer",
                      "atan_rat_producer", "tanh_rat_producer"):
            pin = _MANIFEST_ROWS.get(label)
            if pin:
                argv += ["--trusted-producer", pin]
        argv += ["--trusted-producer", gaussian_producer_expected]
        argv += ["--trusted-producer", int_producer_expected]
        try:
            proc = subprocess.run(argv, capture_output=True, text=True,
                                  timeout=3600)
        except subprocess.TimeoutExpired:
            return _refuse("plugin-subprocess", "claim verifier timeout")
        _claim_toctou("claim_verifier", verifier_path, verifier_pin)
    stdout = proc.stdout or ""
    verdict, reason, detail = "", "", ""
    for line in stdout.splitlines():
        if line.startswith("claim-verify="):
            verdict = line.split("=", 2)[1].split()[0]
            if "reason=" in line:
                reason = line.split("reason=", 1)[1].split()[0]
            if 'detail="' in line:
                detail = line.split('detail="', 1)[1].rstrip('"')
            break
    if verdict == "verified":
        return {"status": "verified", "verdict": "verified",
                "report": stdout.splitlines()}
    if verdict == "indeterminate":
        return {"status": "indeterminate", "reason": reason,
                "detail": detail, "report": stdout.splitlines()}
    return {"status": "refused", "reason": reason or "claim-verify-failed",
            "detail": detail, "report": stdout.splitlines()}


TOOLS = {
    "jackal_range_bound":       tool_range_bound,
    "jackal_gaussian_integral": tool_gaussian_integral,
    "jackal_integrate_bound_cert": tool_integrate_bound_cert,
    "jackal_sqrt_rat_bound":    tool_sqrt_rat_bound,
    "jackal_exp_rat_bound":     tool_exp_rat_bound,
    "jackal_ln_rat_bound":      tool_ln_rat_bound,
    "jackal_sin_rat_bound":     tool_sin_rat_bound,
    "jackal_cos_rat_bound":     tool_cos_rat_bound,
    "jackal_atan_rat_bound":    tool_atan_rat_bound,
    "jackal_tanh_rat_bound":    tool_tanh_rat_bound,
    "jackal_verify_receipt":    tool_verify_receipt,
    "jackal_claim":             tool_jackal_claim,
    "jackal_verify_bundle":     tool_jackal_verify_bundle,
}
for _tool_name, _spec in _WEAK_LANE_TOOLS.items():
    TOOLS[_tool_name] = _make_weak_tool(_tool_name, _spec)


def _dispatch(method: str, params: Any) -> dict[str, Any]:
    try:
        _startup_gate()
        if method not in TOOLS:
            return _refuse("plugin-unknown-tool", method)
        if not isinstance(params, dict):
            return _refuse("plugin-args-schema", "params must be an object")
        result = TOOLS[method](params)
        _startup_gate()
        return result
    except PluginRefusal as p:
        return _refuse(p.reason, p.detail)
    except Exception as e:  # noqa: BLE001
        return _refuse("plugin-internal", f"{type(e).__name__}: {e}")


# -- stdio JSON-RPC 2.0 transport (MCP-friendly) -------------------------------

def _rpc_ok(rid: Any, result: dict[str, Any]) -> str:
    return json.dumps({"jsonrpc": "2.0", "id": rid, "result": result},
                      sort_keys=True, separators=(",", ":"))


def _rpc_err(rid: Any, code: int, message: str, data: Any = None) -> str:
    err = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return json.dumps({"jsonrpc": "2.0", "id": rid, "error": err},
                      sort_keys=True, separators=(",", ":"))


def _serve_stdio() -> int:
    """Line-delimited JSON-RPC 2.0.  One request per line; one reply per line.

    Recognised methods:
        list_tools()                       -> tool manifest
        <tool-name>(<args-object>)          -> tool result
    """
    tools_manifest = _strict_json_loads((PLUGIN_DIR / "tools.json").read_bytes())
    try:
        _startup_gate()
    except PluginRefusal as p:
        sys.stdout.write(_rpc_err(None, -32000, f"{p.reason}: {p.detail}") + "\n")
        return 1
    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue
        try:
            req = _strict_json_loads(raw)
            if not isinstance(req, dict):
                raise ValueError("request must be an object")
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as e:
            sys.stdout.write(_rpc_err(None, -32700, f"parse error: {e}") + "\n")
            sys.stdout.flush()
            continue
        rid = req.get("id")
        method = req.get("method")
        params = req.get("params", {})
        if method == "list_tools":
            sys.stdout.write(_rpc_ok(rid, tools_manifest) + "\n")
        else:
            sys.stdout.write(_rpc_ok(rid, _dispatch(method, params)) + "\n")
        sys.stdout.flush()
    return 0


def _serve_call(tool: str, arg_json: str) -> int:
    try:
        _startup_gate()
    except PluginRefusal as p:
        sys.stdout.write(json.dumps({"status": "refused", "reason": p.reason,
                                     "detail": p.detail}, sort_keys=True) + "\n")
        return 1
    try:
        params = _strict_json_loads(arg_json)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as e:
        sys.stdout.write(json.dumps({"status": "refused", "reason": "plugin-args-schema",
                                     "detail": f"parse error: {e}"}, sort_keys=True) + "\n")
        return 1
    result = _dispatch(tool, params)
    sys.stdout.write(json.dumps(result, sort_keys=True, indent=2) + "\n")
    return 0 if result.get("status") in {
        "formal-bounded", "verified",
        # Weaker-lane classes: success at their honest epistemic level.
        "exact", "checked", "estimated", "bounded", "model-based",
    } else 1


def _serve_http(port: int, host: str) -> int:
    """Tiny HTTP wrapper: POST /tools/<name> JSON body -> JSON reply."""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    try:
        _startup_gate()
    except PluginRefusal as p:
        sys.stderr.write(f"startup-refuse {p.reason}: {p.detail}\n")
        return 1

    tools_manifest = _strict_json_loads((PLUGIN_DIR / "tools.json").read_bytes())

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):  # silence access log
            return

        def _send_json(self, code: int, obj: dict[str, Any]) -> None:
            payload = json.dumps(obj, sort_keys=True, indent=2).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self):  # noqa: N802
            if self.path in ("/tools", "/"):
                self._send_json(200, tools_manifest)
            else:
                self._send_json(404, {"status": "refused", "reason": "plugin-http-notfound"})

        def do_POST(self):  # noqa: N802
            if not self.path.startswith("/tools/"):
                self._send_json(404, {"status": "refused", "reason": "plugin-http-notfound"})
                return
            tool = self.path[len("/tools/"):]
            try:
                n = int(self.headers.get("Content-Length", "0") or 0)
            except ValueError:
                self._send_json(400, {"status": "refused", "reason": "plugin-http-length"})
                return
            if n < 0 or n > 4 * 1024 * 1024:
                self._send_json(413, {"status": "refused", "reason": "plugin-http-length"})
                return
            body = self.rfile.read(n) if n else b"{}"
            try:
                params = _strict_json_loads(body or b"{}")
            except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as e:
                self._send_json(400, {"status": "refused", "reason": "plugin-args-schema",
                                      "detail": f"parse error: {e}"})
                return
            self._send_json(200, _dispatch(tool, params))

    server = ThreadingHTTPServer((host, port), Handler)
    server.serve_forever()
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="JACKAL Hermes plugin server")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("stdio", help="line-delimited JSON-RPC 2.0")
    call = sub.add_parser("call", help="one-shot tool invocation")
    call.add_argument("tool")
    call.add_argument("args_json")
    http = sub.add_parser("http", help="POST /tools/<name>")
    http.add_argument("--port", type=int, default=8181)
    http.add_argument("--host", default="127.0.0.1")
    sub.add_parser("selftest", help="print bundle-hash and pinned value")
    ns = ap.parse_args(argv)
    if ns.cmd == "stdio":
        return _serve_stdio()
    if ns.cmd == "call":
        return _serve_call(ns.tool, ns.args_json)
    if ns.cmd == "http":
        return _serve_http(ns.port, ns.host)
    if ns.cmd == "selftest":
        try:
            _startup_gate()
        except PluginRefusal as p:
            print(f"plugin_hermes.selftest=refused reason={p.reason} detail={p.detail}")
            return 1
        print(f"plugin_hermes.bundle_sha256={PLUGIN_HASH}")
        print(f"plugin_hermes.pinned_sha256={PLUGIN_HASH_PINNED or '<none>'}")
        print(f"plugin_hermes.identity_match={'true' if PLUGIN_HASH == PLUGIN_HASH_PINNED else 'false'}")
        print(f"evaluator={LAYOUT['evaluator']}")
        print(f"checker={LAYOUT['checker']}")
        print(f"gaussian_producer={LAYOUT['gaussian_producer']}")
        print(f"gaussian_checker={LAYOUT['gaussian_checker']}")
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
