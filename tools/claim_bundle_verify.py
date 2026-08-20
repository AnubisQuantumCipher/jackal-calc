#!/usr/bin/env python3
"""Independent verifier for `jackal-claim-bundle-v1` (v1.6.0 epoch).

Dependency-free replay verifier: trusts neither the planner, router,
plugin, renderer, nor producer.  Parses with duplicate-key rejection and
strict budgets, recomputes every canonical byte and hash, revalidates the
DAG, dispatches embedded legacy evidence through the EXISTING independent
verifiers (`tools/receipt_verify.py`, `tools/exact_verify.py`),
recomputes machine-int and unit mathematics itself, re-evaluates every
registered inference rule from canonical parent propositions, recomputes
the full assurance-axis propagation (small compositional algebra: meet +
rule caps; flags AND; residuals union), enforces kernel-mandated
consequence-class floors and the caller-pinned policy, recomputes the
deterministic rendering, and returns `verified`, `refused`, or
`indeterminate` with a stable reason class — never a bare badge.

Exit codes: 0 verified, 1 refused, 2 CLI misuse, 3 indeterminate,
126 interpreter not isolated.

Run: python3 -I -S -B tools/claim_bundle_verify.py --bundle <file|-> ...
Contract: release/claim/SPEC.md section 10.
"""
from __future__ import annotations

import sys

if not (sys.flags.isolated and sys.flags.no_site):
    sys.stderr.write(
        "status=refused reason=python-not-isolated "
        "detail=\"requires python3 -I -S -B\"\n")
    sys.exit(126)

import argparse           # noqa: E402
import base64             # noqa: E402
import hashlib            # noqa: E402
import json               # noqa: E402
import re                 # noqa: E402
import subprocess         # noqa: E402
import tempfile           # noqa: E402
import unicodedata        # noqa: E402
from fractions import Fraction   # noqa: E402
from pathlib import Path  # noqa: E402

SCHEMA_BUNDLE = "jackal-claim-bundle-v1"
SCHEMA_NODE = "jackal-claim-node-v1"
SCHEMA_POLICY = "jackal-claim-policy-v1"
SCHEMA_MACHINE = "jackal-machine-int-cert-v1"

# ------------------------------------------------------------------ budgets
MAX_BUNDLE_BYTES = 4 * 1024 * 1024
MAX_NODES = 128
MAX_DEPTH = 32
MAX_PARENTS = 16
MAX_PROP_NODES = 512
MAX_PROP_DEPTH = 64
MAX_STRING_BYTES = 4096
MAX_INT_DIGITS = 4096
MAX_ASSUMPTIONS = 64
MAX_CONJUNCTS = 16
MAX_EVIDENCE_BYTES = 1 << 20
MAX_JSON_INT = 1 << 53

KEY_RE = re.compile(r"^[A-Za-z0-9_.:/\-]{1,64}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
VAR_RE = re.compile(r"^[a-z][a-z0-9_]{0,15}$")
INT_TOKEN_RE = re.compile(r"^(0|-?[1-9][0-9]*)$")
RAT_TOKEN_RE = re.compile(r"^(0|-?[1-9][0-9]*)(/([1-9][0-9]*[0-9]*))?$")
MACHINE_FN_RE = re.compile(
    r"^m\.(add|sub|mul|and|or|xor|not|shl|shr_logical|shr_arith|rotl|rotr"
    r"|neg|convert|eq|lt|le|gt|ge)\.w(8|16|32|64)\.(s|u)\.(wrap|checked)$")
MACHINE_OVERFLOW_RE = re.compile(
    r"^m\.overflow\.(add|sub|mul|neg|shl|convert)\.w(8|16|32|64)"
    r"\.(s|u)\.checked$")
EXACT_OPAQUE_RE = re.compile(
    r"^exact:(poly-canon|poly-eq|poly-gcd|ratfunc-canon|roots-isolate)$")

# ------------------------------------------------------------- vocabularies
PROV_ORDER = ["unknown", "supplied", "integrity-bound", "observed",
              "authenticated-source", "measured"]
MODEL_ORDER = ["unknown", "assumed", "calibrated", "empirically-validated"]
MODEL_IDENTITY = "not-applicable"
MATH_ORDER = ["refused", "indeterminate", "estimated", "model-based",
              "checked", "bounded", "formal-bounded", "exact"]
MATH_RANKS = {"refused": 0, "indeterminate": 1, "estimated": 2,
              "model-based": 2, "checked": 3, "bounded": 4,
              "formal-bounded": 5, "exact": 6}
IMPL_ORDER = ["unknown", "directly-trusted", "campaign-tested",
              "independently-recomputed", "checker-derived",
              "source-native-refined"]
ARTIFACT_FLAGS = ["content_addressed", "reproducible_built",
                  "authenticated", "transparency_logged"]
PRODUCER_EMITTABLE_PROV = {"unknown", "supplied", "integrity-bound"}

RESIDUALS = [
    "no-source-native-refinement",
    "no-replay-prevention-without-external-nonce-store",
    "no-probability-distributions-from-intervals",
    "no-real-world-input-truth",
    "no-universal-soundness-bounded-fragments-only",
    "transparency-metadata-is-not-mathematical-evidence",
]

RULE_IDS = {
    "input_declare", "evidence_admit", "and_intro", "equality_substitute",
    "interval_add", "interval_sub", "interval_mul", "interval_div",
    "unit_convert_linear", "unit_convert_affine",
    "threshold_from_enclosure", "robust_decision", "model_condition",
    "provenance_passthrough", "artifact_attestation_attach",
}

# Rules that transform propositions cap implementation at
# independently-recomputed; the three passthrough rules preserve axes.
PRESERVE_RULES = {"model_condition", "provenance_passthrough",
                  "artifact_attestation_attach"}
IMPL_CAP_DEFAULT = "independently-recomputed"
MATH_CAPS = {"interval_add": "bounded", "interval_sub": "bounded",
             "interval_mul": "bounded", "interval_div": "bounded"}

NODE_KEYS = {
    "schema", "id", "proposition", "env", "assumptions", "evidence",
    "producer", "checker", "release_epoch", "parents", "rule", "assurance",
    "freshness", "residual_non_claims", "decision", "display",
}
BUNDLE_KEYS = {
    "schema", "release_epoch", "engine_identity", "registries", "policy",
    "nodes", "root", "rendering", "bundle_digest_sha256",
}
POLICY_KEYS = {"schema", "policy_id", "accept", "require", "allow_fallback"}
POLICY_ACCEPT_KEYS = {"input_provenance", "model_validity", "mathematical",
                      "implementation", "artifact_required_flags"}
POLICY_REQUIRE_KEYS = {"max_nodes", "max_depth", "require_nonce",
                       "max_age_seconds", "decision_margin_min",
                       "max_enclosure_width", "forbid_rules"}
ASSURANCE_KEYS = {"input_provenance", "model_validity", "mathematical",
                  "implementation", "artifact"}
FRESHNESS_KEYS = {"source_version", "emitted_at_unix", "max_age_seconds",
                  "expires_at_unix", "nonce", "environment_epoch"}
DECISION_KEYS = {"decision_id", "action", "comparison", "threshold",
                 "margin", "consequence_class"}
EVIDENCE_KINDS = {"formal-receipt", "exact-cert", "machine-int-cert"}
MACHINE_KEYS = {"schema", "width", "signed", "op", "mode", "operands",
                "shift", "math_result", "machine_result", "overflow",
                "semantics"}
MACHINE_OPS = {"add", "sub", "mul", "and", "or", "xor", "not", "shl",
               "shr_logical", "shr_arith", "rotl", "rotr", "neg",
               "convert", "eq", "lt", "le", "gt", "ge"}
MACHINE_SHIFT_OPS = {"shl", "shr_logical", "shr_arith", "rotl", "rotr"}
MACHINE_OVERFLOWABLE = {"add", "sub", "mul", "neg", "shl", "convert"}
MACHINE_UNARY = {"not", "neg", "convert"} | MACHINE_SHIFT_OPS
APP_FNS = {"gcd": (2, 2), "mod_inv": (2, 2), "mod_pow": (3, 3),
           "crt_solve": (4, 32), "formal.range": (2, 2),
           "formal.gaussian_integral": (3, 3),
           "formal.integral": (3, 3)}
PRED_ARITIES = {"denominator_nonzero": (1, 1), "threshold_robust": (3, 3),
                "prime": (1, 1), "composite": (1, 1),
                "formal.range_enclosure": (3, 3)}

CONSEQUENCE_FLOORS = {
    "informational": {
        "mathematical_min": "estimated",
        "implementation_min": "directly-trusted",
        "input_provenance_min": "unknown",
        "model_validity_allowed": {"not-applicable", "unknown", "assumed",
                                   "calibrated", "empirically-validated"},
        "margin_positive": False,
    },
    "advisory": {
        "mathematical_min": "checked",
        "implementation_min": "directly-trusted",
        "input_provenance_min": "supplied",
        "model_validity_allowed": {"not-applicable", "unknown", "assumed",
                                   "calibrated", "empirically-validated"},
        "margin_positive": False,
    },
    "decision-boundary": {
        "mathematical_min": "bounded",
        "implementation_min": "independently-recomputed",
        "input_provenance_min": "supplied",
        "model_validity_allowed": {"not-applicable", "assumed",
                                   "calibrated", "empirically-validated"},
        "margin_positive": True,
    },
    "safety-critical": {
        "mathematical_min": "formal-bounded",
        "implementation_min": "independently-recomputed",
        "input_provenance_min": "supplied",
        "model_validity_allowed": {"not-applicable", "calibrated",
                                   "empirically-validated"},
        "margin_positive": True,
    },
}

ATTESTATION_KIND_FOR_FLAG = {
    "content_addressed": "sha256",
    "reproducible_built": "reproducible-build",
    "authenticated": "signature",
    "transparency_logged": "transparency-inclusion-proof",
}

REASON_CLASSES = (
    "assurance-launder", "assurance-schema", "artifact-upgrade",
    "bundle-budget", "bundle-fields", "bundle-json", "bundle-schema",
    "consequence-floor", "digest-mismatch", "duplicate-key",
    "environment-mismatch", "epoch-mismatch", "evidence-encoding",
    "evidence-hash-mismatch", "evidence-kind", "evidence-producer-untrusted",
    "evidence-prop-mismatch", "evidence-verify-failed", "float-forbidden",
    "freshness-expired", "freshness-premature", "freshness-schema",
    "freshness-stale",
    "graph-cycle", "implementation-upgrade", "int-budget",
    "interval-div-zero", "interval-endpoints", "legacy-dispatch-failed",
    "legacy-verifier-unavailable", "machine-cert-invalid",
    "machine-overflow-claim", "machine-shift-range", "machine-width",
    "model-upgrade", "node-duplicate-id", "node-fields",
    "node-id-mismatch", "node-schema", "nonce-mismatch", "nonce-missing",
    "orphan-node", "parent-duplicate", "parent-missing", "parent-order",
    "policy-pin-mismatch", "policy-schema", "policy-violation",
    "prop-budget", "prop-schema", "provenance-upgrade",
    "rat-not-canonical", "receipt-context-unsupported",
    "registry-inference-mismatch",
    "registry-semantics-mismatch", "registry-unit-mismatch",
    "render-mismatch", "residual-missing", "root-missing",
    "root-proposition-mismatch", "rule-arity", "rule-invalid",
    "rule-params", "rule-unknown", "string-budget",
    "threshold-not-established", "unicode-forbidden",
    "unit-affine-forbidden", "unit-alias-forbidden", "unit-dim-mismatch",
    "unit-unknown", "unknown-field", "verifier-internal",
)


class Refusal(Exception):
    def __init__(self, cls: str, detail: str = "") -> None:
        assert cls in REASON_CLASSES, cls
        super().__init__(detail)
        self.cls = cls
        self.detail = detail


class Indeterminate(Exception):
    def __init__(self, cls: str, detail: str = "") -> None:
        super().__init__(detail)
        self.cls = cls
        self.detail = detail


# ------------------------------------------------------------- strict JSON
def _reject_dup(pairs):
    seen = set()
    out = {}
    for key, value in pairs:
        if key in seen:
            raise Refusal("duplicate-key", key)
        seen.add(key)
        out[key] = value
    return out


def _reject_float(_tok):
    raise Refusal("float-forbidden", _tok)


def _reject_const(tok):
    raise Refusal("float-forbidden", tok)


def strict_loads(raw: bytes, *, what: str = "bundle") -> object:
    if len(raw) > MAX_BUNDLE_BYTES:
        raise Refusal("bundle-budget", f"{what} exceeds {MAX_BUNDLE_BYTES}")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise Refusal("bundle-json", f"{what}: not utf-8: {exc}") from None
    try:
        return json.loads(text, object_pairs_hook=_reject_dup,
                          parse_float=_reject_float,
                          parse_constant=_reject_const)
    except Refusal:
        raise
    except json.JSONDecodeError as exc:
        raise Refusal("bundle-json", f"{what}: {exc}") from None


def canonical_bytes(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def sha_hex(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


# --------------------------------------------------------- generic walkers
def check_string(s: str, *, budget_exempt: bool = False) -> None:
    if not budget_exempt and len(s.encode("utf-8")) > MAX_STRING_BYTES:
        raise Refusal("string-budget", f"{len(s)} chars")
    if "\u2028" in s or "\u2029" in s:
        raise Refusal("unicode-forbidden", "U+2028/U+2029")
    for ch in s:
        o = ord(ch)
        if o < 0x20 or 0x7F <= o <= 0x9F:
            raise Refusal("unicode-forbidden", f"control U+{o:04X}")
    if unicodedata.normalize("NFC", s) != s:
        raise Refusal("unicode-forbidden", "not NFC")


def walk_document(obj, path: str = "$") -> None:
    if isinstance(obj, dict):
        for key, value in obj.items():
            if not isinstance(key, str) or not KEY_RE.match(key):
                raise Refusal("unicode-forbidden", f"bad key at {path}")
            walk_document(value, f"{path}.{key}")
    elif isinstance(obj, list):
        for i, value in enumerate(obj):
            walk_document(value, f"{path}[{i}]")
    elif isinstance(obj, str):
        exempt = path.endswith(".payload_b64")
        check_string(obj, budget_exempt=exempt)
        if exempt and len(obj) > 2 * MAX_EVIDENCE_BYTES:
            raise Refusal("bundle-budget", "payload_b64 length")
    elif isinstance(obj, bool) or obj is None:
        pass
    elif isinstance(obj, int):
        if abs(obj) > MAX_JSON_INT:
            raise Refusal("int-budget", f"{path}")
    else:  # pragma: no cover - floats rejected at parse
        raise Refusal("float-forbidden", path)


def parse_rat(tok, *, what: str = "token") -> Fraction:
    if not isinstance(tok, str):
        raise Refusal("prop-schema", f"{what}: rational must be a string")
    if len(tok) > MAX_INT_DIGITS + MAX_INT_DIGITS + 1:
        raise Refusal("int-budget", what)
    m = RAT_TOKEN_RE.match(tok)
    if not m:
        raise Refusal("rat-not-canonical", f"{what}: {tok[:40]!r}")
    num = int(m.group(1))
    den = int(m.group(3)) if m.group(3) else 1
    if m.group(3) is not None:
        if den <= 1:
            raise Refusal("rat-not-canonical", f"{what}: denominator {den}")
        if m.group(3).lstrip("0") != m.group(3):
            raise Refusal("rat-not-canonical", f"{what}: leading zero den")
        from math import gcd
        if gcd(abs(num), den) != 1:
            raise Refusal("rat-not-canonical", f"{what}: not reduced")
    frac = Fraction(num, den)
    return frac


def rat_token(fr: Fraction) -> str:
    return str(fr.numerator) if fr.denominator == 1 else \
        f"{fr.numerator}/{fr.denominator}"


def parse_int_token(tok, *, what: str = "int") -> int:
    if not isinstance(tok, str) or not INT_TOKEN_RE.match(tok):
        raise Refusal("rat-not-canonical", f"{what}: {str(tok)[:40]!r}")
    if len(tok) > MAX_INT_DIGITS:
        raise Refusal("int-budget", what)
    return int(tok)


# ------------------------------------------------------------- registries
class UnitRegistry:
    def __init__(self, doc: dict) -> None:
        if doc.get("schema") != "jackal-unit-registry-v1":
            raise Refusal("registry-semantics-mismatch", "unit schema")
        if doc.get("dimension_order") != ["s", "m", "kg", "A", "K",
                                          "mol", "cd"]:
            raise Refusal("registry-semantics-mismatch", "dimension order")
        self.units: dict[str, dict] = {}
        for uid, row in doc.get("units", {}).items():
            dim = row.get("dim")
            if (not isinstance(dim, list) or len(dim) != 7
                    or not all(isinstance(e, int)
                               and not isinstance(e, bool)
                               and abs(e) <= 16 for e in dim)):
                raise Refusal("registry-semantics-mismatch", f"dim {uid}")
            scale = parse_rat(row.get("scale"), what=f"unit {uid} scale")
            if scale <= 0:
                raise Refusal("registry-semantics-mismatch",
                              f"scale {uid}")
            kind = row.get("kind")
            if kind not in ("linear", "affine"):
                raise Refusal("registry-semantics-mismatch", f"kind {uid}")
            offset = None
            if kind == "affine":
                offset = parse_rat(row.get("offset"),
                                   what=f"unit {uid} offset")
            self.units[uid] = {"dim": tuple(dim), "scale": scale,
                               "offset": offset, "kind": kind}
        self.aliases: dict[str, str] = {}
        for alias, target in doc.get("aliases", {}).items():
            if target not in self.units:
                raise Refusal("registry-semantics-mismatch",
                              f"alias {alias}")
            if alias in self.units:
                raise Refusal("registry-semantics-mismatch",
                              f"alias collides {alias}")
            self.aliases[alias] = target

    def resolve(self, uid: str) -> dict:
        if uid in self.units:
            return self.units[uid]
        if uid in self.aliases:
            raise Refusal("unit-alias-forbidden",
                          f"{uid} -> {self.aliases[uid]}")
        raise Refusal("unit-unknown", uid)


def load_registries(args) -> tuple[dict, UnitRegistry, bytes, bytes]:
    inf_path = Path(args.expected_inference_registry)
    unit_path = Path(args.expected_unit_registry)
    try:
        inf_raw = inf_path.read_bytes()
        unit_raw = unit_path.read_bytes()
    except OSError as exc:
        raise Indeterminate("registry-unreadable", str(exc)) from None
    if sha_hex(inf_raw) != args.expected_inference_registry_sha256:
        raise Refusal("registry-inference-mismatch", "file vs pin")
    if sha_hex(unit_raw) != args.expected_unit_registry_sha256:
        raise Refusal("registry-unit-mismatch", "file vs pin")
    inf_doc = strict_loads(inf_raw, what="inference registry")
    unit_doc = strict_loads(unit_raw, what="unit registry")
    if inf_doc.get("schema") != "jackal-inference-registry-v1":
        raise Refusal("registry-semantics-mismatch", "inference schema")
    if set(inf_doc.get("rules", {}).keys()) != RULE_IDS:
        raise Refusal("registry-semantics-mismatch", "rule set drift")
    cc = inf_doc.get("consequence_classes", {})
    if set(cc.keys()) != set(CONSEQUENCE_FLOORS.keys()):
        raise Refusal("registry-semantics-mismatch", "consequence classes")
    for name, floor in CONSEQUENCE_FLOORS.items():
        row = cc[name]
        if (row.get("mathematical_min") != floor["mathematical_min"]
                or row.get("implementation_min")
                != floor["implementation_min"]
                or row.get("input_provenance_min")
                != floor["input_provenance_min"]
                or set(row.get("model_validity_allowed", []))
                != floor["model_validity_allowed"]
                or bool(row.get("margin_positive"))
                != floor["margin_positive"]):
            raise Refusal("registry-semantics-mismatch",
                          f"floor {name} drift")
    expected_rules = {
        "input_declare": ("checked", "directly-trusted", False),
        "evidence_admit": (None, None, False),
        "and_intro": (None, "independently-recomputed", False),
        "equality_substitute": (None, "independently-recomputed", False),
        "interval_add": ("bounded", "independently-recomputed", False),
        "interval_sub": ("bounded", "independently-recomputed", False),
        "interval_mul": ("bounded", "independently-recomputed", False),
        "interval_div": ("bounded", "independently-recomputed", False),
        "unit_convert_linear": (None, "independently-recomputed", False),
        "unit_convert_affine": (None, "independently-recomputed", False),
        "threshold_from_enclosure": (None, "independently-recomputed",
                                     False),
        "robust_decision": (None, "independently-recomputed", False),
        "model_condition": (None, None, True),
        "provenance_passthrough": (None, None, True),
        "artifact_attestation_attach": (None, None, True),
    }
    for rule_id, (math_cap, impl_cap, preserve) in expected_rules.items():
        row = inf_doc["rules"][rule_id]
        if row.get("mathematical_cap") != math_cap:
            raise Refusal("registry-semantics-mismatch",
                          f"rule {rule_id} mathematical_cap drift")
        if row.get("implementation_cap") != impl_cap:
            raise Refusal("registry-semantics-mismatch",
                          f"rule {rule_id} implementation_cap drift")
        if bool(row.get("axis_preserve")) != preserve:
            raise Refusal("registry-semantics-mismatch",
                          f"rule {rule_id} axis_preserve drift")
    return inf_doc, UnitRegistry(unit_doc), inf_raw, unit_raw


# --------------------------------------------------------- proposition IR
class PropInfo:
    """Validation context result for one proposition tree."""

    def __init__(self) -> None:
        self.count = 0
        self.vars: set[str] = set()


def dims_zero(dim: tuple) -> bool:
    return all(e == 0 for e in dim)


def validate_term(node, info: PropInfo, units: UnitRegistry,
                  env_vars: dict, depth: int = 0) -> str:
    """Validates a TERM; returns a coarse sort: 'num' | 'bitvec' | 'str'
    | 'bool'."""
    info.count += 1
    if info.count > MAX_PROP_NODES:
        raise Refusal("prop-budget", "node count")
    if depth > MAX_PROP_DEPTH:
        raise Refusal("prop-budget", "depth")
    if not isinstance(node, dict) or "t" not in node:
        raise Refusal("prop-schema", "term must be a tagged object")
    t = node["t"]
    keys = set(node.keys())
    if t == "bool":
        if keys != {"t", "v"} or not isinstance(node["v"], bool):
            raise Refusal("prop-schema", "bool")
        return "bool"
    if t == "rat":
        if keys != {"t", "v"}:
            raise Refusal("prop-schema", "rat")
        parse_rat(node["v"], what="rat literal")
        return "num"
    if t == "str":
        if keys != {"t", "v"} or not isinstance(node["v"], str):
            raise Refusal("prop-schema", "str")
        return "str"
    if t == "interval":
        validate_interval(node, units=None)
        return "interval"
    if t == "bitvec":
        if keys != {"t", "width", "signed", "v"}:
            raise Refusal("prop-schema", "bitvec keys")
        w = node["width"]
        if w not in (8, 16, 32, 64) or isinstance(w, bool):
            raise Refusal("prop-schema", "bitvec width")
        if not isinstance(node["signed"], bool):
            raise Refusal("prop-schema", "bitvec signed")
        v = parse_int_token(node["v"], what="bitvec value")
        lo, hi = machine_range(w, node["signed"])
        if not (lo <= v <= hi):
            raise Refusal("prop-schema", f"bitvec value {v} out of range")
        return "bitvec"
    if t == "var":
        if keys != {"t", "name"}:
            raise Refusal("prop-schema", "var keys")
        name = node["name"]
        if not isinstance(name, str) or not VAR_RE.match(name):
            raise Refusal("prop-schema", f"var name {name!r}")
        if name not in env_vars:
            raise Refusal("prop-schema", f"undeclared var {name}")
        info.vars.add(name)
        return "num"
    if t == "app":
        if keys != {"t", "fn", "args"}:
            raise Refusal("prop-schema", "app keys")
        fn = node["fn"]
        args = node["args"]
        if not isinstance(fn, str) or not isinstance(args, list):
            raise Refusal("prop-schema", "app shape")
        for a in args:
            validate_term(a, info, units, env_vars, depth + 1)
        if fn in APP_FNS:
            lo_a, hi_a = APP_FNS[fn]
            if not (lo_a <= len(args) <= hi_a):
                raise Refusal("prop-schema", f"app {fn} arity")
            if fn == "crt_solve" and len(args) % 2 != 0:
                raise Refusal("prop-schema", "crt_solve arity parity")
            return "num"
        if MACHINE_FN_RE.match(fn):
            return "num"
        raise Refusal("prop-schema", f"unknown app fn {fn}")
    if t in ("add", "sub", "mul", "div"):
        if keys != {"t", "lhs", "rhs"}:
            raise Refusal("prop-schema", f"{t} keys")
        validate_term(node["lhs"], info, units, env_vars, depth + 1)
        validate_term(node["rhs"], info, units, env_vars, depth + 1)
        return "num"
    if t == "neg":
        if keys != {"t", "arg"}:
            raise Refusal("prop-schema", "neg keys")
        validate_term(node["arg"], info, units, env_vars, depth + 1)
        return "num"
    raise Refusal("prop-schema", f"unexpected term tag {t!r}")


def validate_interval(node, units: UnitRegistry | None) -> tuple:
    if (not isinstance(node, dict)
            or set(node.keys()) != {"t", "lo", "hi"}
            or node.get("t") != "interval"):
        raise Refusal("prop-schema", "interval shape")
    lo = parse_rat(node["lo"], what="interval lo")
    hi = parse_rat(node["hi"], what="interval hi")
    if lo > hi:
        raise Refusal("interval-endpoints", f"{node['lo']} > {node['hi']}")
    return lo, hi


def validate_prop(prop, units: UnitRegistry, env_vars: dict,
                  info: PropInfo | None = None, depth: int = 0) -> PropInfo:
    """Validates a PROPOSITION tree."""
    if info is None:
        info = PropInfo()
    info.count += 1
    if info.count > MAX_PROP_NODES:
        raise Refusal("prop-budget", "node count")
    if depth > MAX_PROP_DEPTH:
        raise Refusal("prop-budget", "depth")
    if not isinstance(prop, dict) or "t" not in prop:
        raise Refusal("prop-schema", "proposition must be tagged")
    t = prop["t"]
    keys = set(prop.keys())
    if t == "in":
        if keys not in ({"t", "arg", "set"}, {"t", "arg", "set", "unit"}):
            raise Refusal("prop-schema", "in keys")
        validate_term(prop["arg"], info, units, env_vars, depth + 1)
        validate_interval(prop["set"], units)
        if "unit" in prop:
            if not isinstance(prop["unit"], str):
                raise Refusal("prop-schema", "unit must be a string")
            units.resolve(prop["unit"])
        return info
    if t == "eq" or t in ("lt", "le", "gt", "ge"):
        if keys != {"t", "lhs", "rhs"}:
            raise Refusal("prop-schema", f"{t} keys")
        validate_term(prop["lhs"], info, units, env_vars, depth + 1)
        validate_term(prop["rhs"], info, units, env_vars, depth + 1)
        return info
    if t == "and":
        if keys != {"t", "args"} or not isinstance(prop["args"], list):
            raise Refusal("prop-schema", "and shape")
        if not (2 <= len(prop["args"]) <= MAX_CONJUNCTS):
            raise Refusal("prop-budget", "conjunct count")
        for sub in prop["args"]:
            validate_prop(sub, units, env_vars, info, depth + 1)
        return info
    if t == "pred":
        if keys != {"t", "name", "args"}:
            raise Refusal("prop-schema", "pred keys")
        name = prop["name"]
        args = prop["args"]
        if not isinstance(name, str) or not isinstance(args, list):
            raise Refusal("prop-schema", "pred shape")
        for a in args:
            validate_term(a, info, units, env_vars, depth + 1)
        if name in PRED_ARITIES:
            lo_a, hi_a = PRED_ARITIES[name]
            if not (lo_a <= len(args) <= hi_a):
                raise Refusal("prop-schema", f"pred {name} arity")
            return info
        if MACHINE_OVERFLOW_RE.match(name) or EXACT_OPAQUE_RE.match(name):
            return info
        raise Refusal("prop-schema", f"unknown pred {name!r}")
    raise Refusal("prop-schema", f"unexpected proposition tag {t!r}")


# --------------------------------------------------------------- machine
def machine_range(width: int, signed: bool) -> tuple[int, int]:
    if signed:
        return -(1 << (width - 1)), (1 << (width - 1)) - 1
    return 0, (1 << width) - 1


def m_to_bits(v: int, w: int) -> int:
    return v % (1 << w)


def m_from_bits(b: int, w: int, signed: bool) -> int:
    if signed and b >= (1 << (w - 1)):
        return b - (1 << w)
    return b


def verify_machine_cert(raw: bytes) -> dict:
    """Full independent recomputation of jackal-machine-int-cert-v1."""
    cert = strict_loads(raw, what="machine cert")
    if not isinstance(cert, dict) or set(cert.keys()) != MACHINE_KEYS:
        raise Refusal("machine-cert-invalid", "key set")
    if canonical_bytes(cert) != raw:
        raise Refusal("evidence-encoding", "machine cert not canonical")
    if cert["schema"] != SCHEMA_MACHINE:
        raise Refusal("machine-cert-invalid", "schema")
    if cert["semantics"] != "two-complement-v1":
        raise Refusal("machine-cert-invalid", "semantics")
    w = cert["width"]
    if w not in (8, 16, 32, 64) or isinstance(w, bool):
        raise Refusal("machine-cert-invalid", "width")
    signed = cert["signed"]
    if not isinstance(signed, bool):
        raise Refusal("machine-cert-invalid", "signed")
    op = cert["op"]
    if op not in MACHINE_OPS:
        raise Refusal("machine-cert-invalid", f"op {op!r}")
    mode = cert["mode"]
    if mode not in ("wrap", "checked"):
        raise Refusal("machine-cert-invalid", "mode")
    operands = cert["operands"]
    want_n = 1 if op in MACHINE_UNARY else 2
    if not isinstance(operands, list) or len(operands) != want_n:
        raise Refusal("machine-cert-invalid", "operand count")
    vals = [parse_int_token(v, what="operand") for v in operands]
    lo_r, hi_r = machine_range(w, signed)
    if op != "convert":
        for v in vals:
            if not (lo_r <= v <= hi_r):
                raise Refusal("machine-width",
                              f"operand {v} outside {w}-bit "
                              f"{'signed' if signed else 'unsigned'}")
    shift_tok = cert["shift"]
    shift = None
    if op in MACHINE_SHIFT_OPS:
        if shift_tok is None:
            raise Refusal("machine-cert-invalid", "shift required")
        shift = parse_int_token(shift_tok, what="shift")
        if not (0 <= shift < w):
            raise Refusal("machine-shift-range", f"shift {shift}")
    elif shift_tok is not None:
        raise Refusal("machine-cert-invalid", "shift forbidden")
    # recompute
    if op in ("add", "sub", "mul"):
        a, b = vals
        math = {"add": a + b, "sub": a - b, "mul": a * b}[op]
    elif op == "neg":
        math = -vals[0]
    elif op in ("and", "or", "xor"):
        a, b = (m_to_bits(vals[0], w), m_to_bits(vals[1], w))
        bits = {"and": a & b, "or": a | b, "xor": a ^ b}[op]
        math = m_from_bits(bits, w, signed)
    elif op == "not":
        math = m_from_bits(m_to_bits(vals[0], w) ^ ((1 << w) - 1), w,
                           signed)
    elif op == "shl":
        math = vals[0] * (1 << shift)
    elif op == "shr_logical":
        math = m_from_bits(m_to_bits(vals[0], w) >> shift, w, signed)
    elif op == "shr_arith":
        math = vals[0] >> shift
    elif op in ("rotl", "rotr"):
        bits = m_to_bits(vals[0], w)
        s = shift % w
        if s:
            if op == "rotl":
                bits = ((bits << s) | (bits >> (w - s))) & ((1 << w) - 1)
            else:
                bits = ((bits >> s) | (bits << (w - s))) & ((1 << w) - 1)
        math = m_from_bits(bits, w, signed)
    elif op == "convert":
        math = vals[0]
    else:  # comparisons
        a, b = vals
        math = int({"eq": a == b, "lt": a < b, "le": a <= b,
                    "gt": a > b, "ge": a >= b}[op])
    machine = m_from_bits(m_to_bits(math, w), w, signed)
    if op in ("eq", "lt", "le", "gt", "ge"):
        machine = math
    overflow = math != machine
    if parse_int_token(cert["math_result"], what="math_result") != math:
        raise Refusal("machine-cert-invalid",
                      f"math_result: expected {math}")
    if parse_int_token(cert["machine_result"],
                       what="machine_result") != machine:
        raise Refusal("machine-cert-invalid",
                      f"machine_result: expected {machine}")
    if not isinstance(cert["overflow"], bool) or \
            cert["overflow"] != overflow:
        raise Refusal("machine-cert-invalid",
                      f"overflow flag: expected {overflow}")
    if overflow and op not in MACHINE_OVERFLOWABLE:
        raise Refusal("machine-cert-invalid", "overflow impossible op")
    return cert


def machine_fn(cert: dict) -> str:
    return (f"m.{cert['op']}.w{cert['width']}."
            f"{'s' if cert['signed'] else 'u'}.{cert['mode']}")


def machine_eq_prop(cert: dict) -> dict:
    w, s = cert["width"], cert["signed"]
    if cert["op"] == "convert":
        args: list[dict] = [{"t": "rat", "v": v} for v in cert["operands"]]
    else:
        args = [{"t": "bitvec", "width": w, "signed": s, "v": v}
                for v in cert["operands"]]
    if cert["shift"] is not None:
        args.append({"t": "rat", "v": cert["shift"]})
    return {"t": "eq",
            "lhs": {"t": "app", "fn": machine_fn(cert), "args": args},
            "rhs": {"t": "bitvec", "width": w, "signed": s,
                    "v": cert["machine_result"]}}


def machine_overflow_prop(cert: dict) -> dict:
    w, s = cert["width"], cert["signed"]
    if cert["op"] == "convert":
        args: list[dict] = [{"t": "rat", "v": v} for v in cert["operands"]]
    else:
        args = [{"t": "bitvec", "width": w, "signed": s, "v": v}
                for v in cert["operands"]]
    return {"t": "pred",
            "name": (f"m.overflow.{cert['op']}.w{w}."
                     f"{'s' if s else 'u'}.checked"),
            "args": args}


# ------------------------------------------------------- assurance algebra
def rank(order: list[str], value: str) -> int:
    return order.index(value)


def meet_ordered(values: list[str], order: list[str],
                 ranks: dict | None = None) -> str:
    if ranks is None:
        best = min(values, key=lambda v: order.index(v))
        return best
    return min(values, key=lambda v: (ranks[v], order.index(v)))


def meet_model(values: list[str]) -> str:
    real = [v for v in values if v != MODEL_IDENTITY]
    if not real:
        return MODEL_IDENTITY
    return meet_ordered(real, MODEL_ORDER)


def validate_assurance_vocab(a: dict) -> None:
    if not isinstance(a, dict) or set(a.keys()) != ASSURANCE_KEYS:
        raise Refusal("assurance-schema", "assurance keys")
    if a["input_provenance"] not in PROV_ORDER:
        raise Refusal("assurance-schema", "input_provenance value")
    if a["model_validity"] not in MODEL_ORDER + [MODEL_IDENTITY]:
        raise Refusal("assurance-schema", "model_validity value")
    if a["mathematical"] not in MATH_ORDER:
        raise Refusal("assurance-schema", "mathematical value")
    if a["implementation"] not in IMPL_ORDER:
        raise Refusal("assurance-schema", "implementation value")
    art = a["artifact"]
    if (not isinstance(art, dict)
            or set(art.keys()) != set(ARTIFACT_FLAGS)
            or not all(isinstance(v, bool) for v in art.values())):
        raise Refusal("assurance-schema", "artifact flags")
    if a["implementation"] == "source-native-refined":
        raise Refusal("implementation-upgrade",
                      "source-native-refined is never granted in v1")


def check_axis_equality(declared: dict, computed: dict,
                        context: str) -> None:
    if declared["mathematical"] != computed["mathematical"]:
        raise Refusal("assurance-launder",
                      f"{context}: mathematical declared "
                      f"{declared['mathematical']} != computed "
                      f"{computed['mathematical']}")
    if declared["input_provenance"] != computed["input_provenance"]:
        raise Refusal("provenance-upgrade",
                      f"{context}: input_provenance declared "
                      f"{declared['input_provenance']} != computed "
                      f"{computed['input_provenance']}")
    if declared["model_validity"] != computed["model_validity"]:
        raise Refusal("model-upgrade",
                      f"{context}: model_validity declared "
                      f"{declared['model_validity']} != computed "
                      f"{computed['model_validity']}")
    if declared["implementation"] != computed["implementation"]:
        raise Refusal("implementation-upgrade",
                      f"{context}: implementation declared "
                      f"{declared['implementation']} != computed "
                      f"{computed['implementation']}")
    if declared["artifact"] != computed["artifact"]:
        raise Refusal("artifact-upgrade",
                      f"{context}: artifact flags declared "
                      f"{declared['artifact']} != computed "
                      f"{computed['artifact']}")


def expected_residuals(parents: list[dict]) -> list[str]:
    out = list(RESIDUALS)
    for p in parents:
        for r in p["residual_non_claims"]:
            if r not in out:
                out.append(r)
    return out


# ------------------------------------------------------------ legacy dispatch
RANGE_RECEIPT_VARIANTS = {
    "range", "sqrt_rat", "exp_rat", "ln_rat", "sin_rat", "cos_rat",
    "atan_rat", "tanh_rat",
}
CURRENT_RANGE_RECEIPT_EPOCH = "v1.7.2"
ARCHIVAL_RANGE_RECEIPT_EPOCH = "v1.5.0"
GAUSSIAN_RECEIPT_EPOCH = "v1.5.0"
INT_CERT_RECEIPT_EPOCH = "v1.7.2"


class ReceiptContext:
    """One closed checker/proof tuple selected by variant and epoch.

    The CLI cannot add arbitrary contexts: it can only populate the four
    named tuples below, and selection never consults receipt-supplied paths
    or digests.
    """

    def __init__(self, *, label: str, checker, expected_checker,
                 inventory, expected_inventory,
                 proof_identity, expected_proof_identity_file,
                 expected_proof_identity_digest) -> None:
        self.label = label
        self.checker = checker
        self.expected_checker = expected_checker
        self.inventory = inventory
        self.expected_inventory = expected_inventory
        self.proof_identity = proof_identity
        self.expected_proof_identity_file = expected_proof_identity_file
        self.expected_proof_identity_digest = \
            expected_proof_identity_digest


class LegacyContext:
    def __init__(self, args) -> None:
        self.receipt_verifier = args.receipt_verifier
        self.exact_verifier = args.exact_verifier
        self.expected_evaluator = args.expected_evaluator
        self.inventory = args.inventory
        self.expected_inventory = args.expected_inventory
        self.current_range = ReceiptContext(
            label="current-range-v172",
            checker=args.checker,
            expected_checker=args.expected_checker,
            inventory=args.inventory,
            expected_inventory=args.expected_inventory,
            proof_identity=args.proof_identity,
            expected_proof_identity_file=args.expected_proof_identity_file,
            expected_proof_identity_digest=
                args.expected_proof_identity_digest)
        self.gaussian = ReceiptContext(
            label="gaussian-v150",
            checker=args.gaussian_checker,
            expected_checker=args.expected_gaussian_checker,
            inventory=args.inventory,
            expected_inventory=args.expected_inventory,
            proof_identity=args.gaussian_proof_identity,
            expected_proof_identity_file=
                args.expected_gaussian_proof_identity_file,
            expected_proof_identity_digest=
                args.expected_gaussian_proof_identity_digest)
        self.current_int_cert = ReceiptContext(
            label="current-int-cert-v172",
            checker=args.int_cert_checker,
            expected_checker=args.expected_int_cert_checker,
            inventory=args.inventory,
            expected_inventory=args.expected_inventory,
            proof_identity=args.int_cert_proof_identity,
            expected_proof_identity_file=
                args.expected_int_cert_proof_identity_file,
            expected_proof_identity_digest=
                args.expected_int_cert_proof_identity_digest)
        self.archival_range = ReceiptContext(
            label="archival-range-v150",
            checker=args.archival_range_checker,
            expected_checker=args.expected_archival_range_checker,
            inventory=args.archival_range_inventory,
            expected_inventory=args.expected_archival_range_inventory,
            proof_identity=args.archival_range_proof_identity,
            expected_proof_identity_file=
                args.expected_archival_range_proof_identity_file,
            expected_proof_identity_digest=
                args.expected_archival_range_proof_identity_digest)
        self.trusted_producers = set(args.trusted_producer or [])
        if args.expected_evaluator:
            self.trusted_producers.add(args.expected_evaluator)

    def receipt_context(self, *, variant: str,
                        release_epoch: str) -> ReceiptContext:
        if variant == "gaussian":
            if release_epoch != GAUSSIAN_RECEIPT_EPOCH:
                raise Refusal(
                    "receipt-context-unsupported",
                    f"gaussian/{release_epoch!r} is not an admitted tuple")
            return self.gaussian
        if variant == "int_cert":
            if release_epoch != INT_CERT_RECEIPT_EPOCH:
                raise Refusal(
                    "receipt-context-unsupported",
                    f"int_cert/{release_epoch!r} is not an admitted tuple")
            return self.current_int_cert
        if variant in RANGE_RECEIPT_VARIANTS:
            if release_epoch == CURRENT_RANGE_RECEIPT_EPOCH:
                return self.current_range
            if release_epoch == ARCHIVAL_RANGE_RECEIPT_EPOCH:
                return self.archival_range
            raise Refusal(
                "receipt-context-unsupported",
                f"{variant}/{release_epoch!r} is not an admitted tuple")
        raise Refusal("receipt-context-unsupported",
                      f"variant {variant!r} is not claim-admissible")

    def require_receipt_infra(self, selected: ReceiptContext) -> None:
        needed = [self.receipt_verifier, selected.checker,
                  selected.expected_checker, selected.inventory,
                  selected.expected_inventory, selected.proof_identity,
                  selected.expected_proof_identity_file,
                  selected.expected_proof_identity_digest]
        if any(v in (None, "") for v in needed):
            raise Indeterminate(
                "legacy-verifier-unavailable",
                f"formal-receipt evidence requires the complete "
                f"{selected.label} checker/proof tuple plus inventory pins")

    def require_exact_infra(self) -> None:
        if self.exact_verifier in (None, ""):
            raise Indeterminate("legacy-verifier-unavailable",
                                "exact-cert evidence requires "
                                "--exact-verifier")


def dispatch_receipt(ctx: LegacyContext, payload: bytes,
                     params: dict) -> dict:
    """Runs the EXISTING receipt_verify.py; returns parsed stdout fields."""
    receipt = strict_loads(payload, what="receipt payload")
    if not isinstance(receipt, dict):
        raise Refusal("evidence-verify-failed", "receipt not an object")
    req = params.get("expected_request")
    if not isinstance(req, dict):
        raise Refusal("rule-params", "expected_request missing")
    for key in ("command", "expression", "input_lo", "input_hi"):
        if key not in req:
            raise Refusal("rule-params", f"expected_request.{key} missing")
    epoch = params.get("expected_release_epoch")
    if not isinstance(epoch, str):
        raise Refusal("rule-params", "expected_release_epoch missing")
    variant = receipt.get("variant", "range")
    if not isinstance(variant, str):
        raise Refusal("receipt-context-unsupported", "variant is not a string")
    selected = ctx.receipt_context(variant=variant,
                                   release_epoch=epoch)
    ctx.require_receipt_infra(selected)
    idents = params.get("expected_identities")
    if (not isinstance(idents, dict)
            or set(idents.keys()) != {"evaluator_sha256", "checker_sha256"}):
        raise Refusal("rule-params", "expected_identities shape")
    evaluator = idents["evaluator_sha256"]
    if evaluator not in ctx.trusted_producers:
        raise Refusal("evidence-producer-untrusted", str(evaluator)[:64])
    if idents["checker_sha256"] != selected.expected_checker:
        raise Refusal("evidence-verify-failed",
                      f"params checker != pinned {selected.label} checker")
    with tempfile.TemporaryDirectory(prefix="jackal-claim-verify-") as td:
        rpath = Path(td) / "receipt.json"
        rpath.write_bytes(payload)
        argv = [sys.executable, "-I", "-S", "-B",
                str(ctx.receipt_verifier),
                "--receipt", str(rpath),
                "--checker", str(selected.checker),
                "--expected-evaluator", evaluator,
                "--expected-checker", selected.expected_checker,
                "--expected-release-epoch", epoch,
                "--expected-command", req["command"],
                "--expected-expression", req["expression"],
                "--expected-input-lo", req["input_lo"],
                "--expected-input-hi", req["input_hi"],
                "--inventory", str(selected.inventory),
                "--expected-inventory", selected.expected_inventory,
                "--proof-identity", str(selected.proof_identity),
                "--expected-proof-identity-file",
                selected.expected_proof_identity_file,
                "--expected-proof-identity-digest",
                selected.expected_proof_identity_digest]
        if "tolerance" in req:
            argv += ["--expected-tolerance", req["tolerance"]]
        try:
            proc = subprocess.run(argv, capture_output=True, text=True,
                                  timeout=3600)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise Refusal("legacy-dispatch-failed", str(exc)) from None
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()[:200]
        raise Refusal("evidence-verify-failed", detail)
    out: dict[str, str] = {}
    for line in (proc.stdout or "").splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            out[key.strip()] = value.strip()
    if "status=verified verdict=ACCEPT" not in (proc.stdout or ""):
        raise Refusal("evidence-verify-failed", "no verified status line")
    return {"receipt": receipt, "stdout_fields": out,
            "expected_checker": selected.expected_checker,
            "context": selected.label,
            "stdout": proc.stdout or ""}


def derive_receipt_prop(receipt: dict) -> dict:
    variant = receipt.get("variant", "range")
    req = receipt["request"]
    result = receipt["result"]
    domain = {"t": "interval", "lo": req["canonical_lo"],
              "hi": req["canonical_hi"]}
    enclosure = {"t": "interval", "lo": result["enclosure_lo"],
                 "hi": result["enclosure_hi"]}
    if variant == "gaussian":
        return {"t": "in",
                "arg": {"t": "app", "fn": "formal.gaussian_integral",
                        "args": [{"t": "str", "v": req["expression"]},
                                 domain,
                                 {"t": "rat",
                                  "v": req["canonical_tolerance"]}]},
                "set": enclosure}
    if variant == "int_cert":
        return {"t": "in",
                "arg": {"t": "app", "fn": "formal.integral",
                        "args": [{"t": "str", "v": req["expression"]},
                                 domain,
                                 {"t": "rat",
                                  "v": req["canonical_tolerance"]}]},
                "set": enclosure}
    return {"t": "in",
            "arg": {"t": "app", "fn": "formal.range",
                    "args": [{"t": "str", "v": req["expression"]}, domain]},
            "set": enclosure}


def dispatch_exact(ctx: LegacyContext, payload: bytes) -> dict:
    ctx.require_exact_infra()
    cert = strict_loads(payload, what="exact cert")
    if canonical_bytes(cert) != payload:
        raise Refusal("evidence-encoding", "exact cert not canonical")
    with tempfile.TemporaryDirectory(prefix="jackal-claim-verify-") as td:
        cpath = Path(td) / "cert.json"
        cpath.write_bytes(payload)
        try:
            proc = subprocess.run(
                [sys.executable, "-I", "-S", "-B",
                 str(ctx.exact_verifier), str(cpath)],
                capture_output=True, text=True, timeout=600)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise Refusal("legacy-dispatch-failed", str(exc)) from None
    stdout = proc.stdout or ""
    if proc.returncode != 0 or "exact-verify=ACCEPT" not in stdout:
        raise Refusal("evidence-verify-failed",
                      (stdout or proc.stderr or "").strip()[:200])
    m = re.search(r"cert_sha256=([0-9a-f]{64})", stdout)
    if not m or m.group(1) != sha_hex(payload):
        raise Refusal("evidence-verify-failed", "cert hash echo mismatch")
    return cert


def derive_exact_prop(cert: dict) -> dict:
    kind = cert["kind"]
    claim = cert["claim"]

    def num(tok: str) -> dict:
        return {"t": "rat", "v": tok}

    def point(app_fn: str, args: list[dict], value: str) -> dict:
        return {"t": "in", "arg": {"t": "app", "fn": app_fn, "args": args},
                "set": {"t": "interval", "lo": value, "hi": value}}

    if kind == "xgcd":
        return point("gcd", [num(claim["a"]), num(claim["b"])], claim["g"])
    if kind == "mod-inv":
        return point("mod_inv", [num(claim["a"]), num(claim["m"])],
                     claim["inv"])
    if kind == "mod-pow":
        return point("mod_pow", [num(claim["base"]), num(claim["exp"]),
                                 num(claim["mod"])], claim["r"])
    if kind == "crt":
        args: list[dict] = []
        for residue in claim["residues"]:
            args.append(num(residue["r"]))
            args.append(num(residue["m"]))
        return point("crt_solve", args, claim["x"])
    if kind == "prime":
        return {"t": "pred", "name": "prime", "args": [num(claim["n"])]}
    if kind == "composite":
        return {"t": "pred", "name": "composite",
                "args": [num(claim["n"])]}
    return {"t": "pred", "name": f"exact:{kind}",
            "args": [{"t": "str",
                      "v": canonical_bytes(claim).decode("utf-8")}]}


ADAPTER_AXES = {
    "formal-receipt": {
        "input_provenance": "supplied",
        "model_validity": "assumed",
        "mathematical": "formal-bounded",
        "implementation": "checker-derived",
        "artifact": {"content_addressed": True, "reproducible_built": False,
                     "authenticated": False, "transparency_logged": False},
    },
    "exact-cert": {
        "input_provenance": "supplied",
        "model_validity": "not-applicable",
        "mathematical": "exact",
        "implementation": "independently-recomputed",
        "artifact": {"content_addressed": True, "reproducible_built": False,
                     "authenticated": False, "transparency_logged": False},
    },
    "machine-int-cert": {
        "input_provenance": "supplied",
        "model_validity": "not-applicable",
        "mathematical": "exact",
        "implementation": "independently-recomputed",
        "artifact": {"content_addressed": True, "reproducible_built": False,
                     "authenticated": False, "transparency_logged": False},
    },
}

EVIDENCE_PARAM_KEYS = {
    "formal-receipt": {"evidence_kind", "expected_request",
                       "expected_release_epoch", "expected_identities"},
    "exact-cert": {"evidence_kind"},
    "machine-int-cert": {"evidence_kind"},
}


# ------------------------------------------------------------- unit helpers
def prop_unit_info(prop: dict, units: UnitRegistry):
    """For an in-proposition: (unit_id|None, unit_row|None)."""
    uid = prop.get("unit")
    if uid is None:
        return None, None
    return uid, units.resolve(uid)


def scaled_interval(lo: Fraction, hi: Fraction, row) -> tuple:
    if row is None:
        return lo, hi
    return lo * row["scale"], hi * row["scale"]


# ------------------------------------------------------------ rule engine
def hull_op(op: str, a: tuple, b: tuple) -> tuple:
    lo1, hi1 = a
    lo2, hi2 = b
    if op == "add":
        return lo1 + lo2, hi1 + hi2
    if op == "sub":
        return lo1 - hi2, hi1 - lo2
    if op == "mul":
        prods = [lo1 * lo2, lo1 * hi2, hi1 * lo2, hi1 * hi2]
        return min(prods), max(prods)
    if op == "div":
        recips = [1 / lo2, 1 / hi2]
        prods = [lo1 * r for r in recips] + [hi1 * r for r in recips]
        return min(prods), max(prods)
    raise Refusal("verifier-internal", f"hull op {op}")


def require_in_prop(prop: dict, context: str) -> None:
    if prop.get("t") != "in":
        raise Refusal("rule-invalid", f"{context}: parent must be an "
                                      "enclosure (in) proposition")


class RuleEngine:
    def __init__(self, units: UnitRegistry, by_id: dict) -> None:
        self.units = units
        self.by_id = by_id

    def computed_axes(self, node: dict, parents: list[dict]) -> dict:
        rule_id = node["rule"]["id"]
        math = meet_ordered([p["assurance"]["mathematical"]
                             for p in parents], MATH_ORDER, MATH_RANKS)
        cap = MATH_CAPS.get(rule_id)
        if cap is not None and MATH_RANKS[cap] < MATH_RANKS[math]:
            math = cap
        impl = meet_ordered([p["assurance"]["implementation"]
                             for p in parents], IMPL_ORDER)
        if rule_id not in PRESERVE_RULES:
            if IMPL_ORDER.index(IMPL_CAP_DEFAULT) < IMPL_ORDER.index(impl):
                impl = IMPL_CAP_DEFAULT
        prov = meet_ordered([p["assurance"]["input_provenance"]
                             for p in parents], PROV_ORDER)
        model = meet_model([p["assurance"]["model_validity"]
                            for p in parents])
        art = {}
        for flag in ARTIFACT_FLAGS:
            art[flag] = all(p["assurance"]["artifact"][flag]
                            for p in parents)
        return {"input_provenance": prov, "model_validity": model,
                "mathematical": math, "implementation": impl,
                "artifact": art}

    def merged_env(self, parents: list[dict]) -> dict:
        vars_: dict = {}
        for p in parents:
            vars_.update(p["env"]["vars"])
        return {"vars": vars_}

    def merged_assumptions(self, parents: list[dict],
                           extra: list[str] | None = None) -> list[str]:
        out: list[str] = []
        for p in parents:
            for a in p["assumptions"]:
                if a not in out:
                    out.append(a)
        for a in (extra or []):
            if a not in out:
                out.append(a)
        return out

    # ---- individual rules -------------------------------------------
    def eval_rule(self, node: dict, parents: list[dict]) -> None:
        rule_id = node["rule"]["id"]
        params = node["rule"]["params"]
        handler = {
            "and_intro": self.rule_and_intro,
            "equality_substitute": self.rule_equality_substitute,
            "interval_add": self.rule_interval,
            "interval_sub": self.rule_interval,
            "interval_mul": self.rule_interval,
            "interval_div": self.rule_interval,
            "unit_convert_linear": self.rule_unit_convert,
            "unit_convert_affine": self.rule_unit_convert,
            "threshold_from_enclosure": self.rule_threshold,
            "robust_decision": self.rule_robust_decision,
            "model_condition": self.rule_model_condition,
            "provenance_passthrough": self.rule_passthrough,
            "artifact_attestation_attach": self.rule_attach,
        }[rule_id]
        handler(node, parents, params)

    def check_params(self, node: dict, expected: set,
                     optional: set = frozenset()) -> None:
        params = node["rule"]["params"]
        if not isinstance(params, dict):
            raise Refusal("rule-params", "params must be an object")
        keys = set(params.keys())
        if not expected <= keys or not keys <= (expected | optional):
            raise Refusal("rule-params",
                          f"{node['rule']['id']}: params {sorted(keys)} "
                          f"!= {sorted(expected)}")

    def default_derived_checks(self, node: dict, parents: list[dict],
                               extra_assumptions: list[str] | None = None,
                               ) -> None:
        computed = self.computed_axes(node, parents)
        check_axis_equality(node["assurance"], computed,
                            node["rule"]["id"])
        if node["env"] != self.merged_env(parents):
            raise Refusal("rule-invalid", "env must be the parent merge")
        if node["assumptions"] != self.merged_assumptions(
                parents, extra_assumptions):
            raise Refusal("rule-invalid",
                          "assumptions must be the parent merge")
        want_res = expected_residuals(parents)
        if node["residual_non_claims"] != want_res:
            raise Refusal("residual-missing",
                          "residual_non_claims must be the fixed set plus "
                          "parent residuals")

    def rule_and_intro(self, node, parents, params) -> None:
        self.check_params(node, set())
        if not (2 <= len(parents) <= MAX_CONJUNCTS):
            raise Refusal("rule-arity", "and_intro parents")
        want = {"t": "and",
                "args": [p["proposition"] for p in parents]}
        if node["proposition"] != want:
            raise Refusal("rule-invalid",
                          "and_intro conclusion must be the ordered "
                          "conjunction of parent propositions")
        self.default_derived_checks(node, parents)

    def rule_equality_substitute(self, node, parents, params) -> None:
        self.check_params(node, set())
        if len(parents) != 2:
            raise Refusal("rule-arity", "equality_substitute parents")
        eq_prop, target = parents[0]["proposition"], \
            parents[1]["proposition"]
        if eq_prop.get("t") != "eq":
            raise Refusal("rule-invalid", "parent 1 must be an eq")
        lhs, rhs = eq_prop["lhs"], eq_prop["rhs"]

        def substitute(tree):
            if tree == lhs:
                return rhs
            if isinstance(tree, dict):
                return {k: substitute(v) for k, v in tree.items()}
            if isinstance(tree, list):
                return [substitute(v) for v in tree]
            return tree

        if node["proposition"] != substitute(target):
            raise Refusal("rule-invalid",
                          "conclusion must be the exact substitution")
        self.default_derived_checks(node, parents)

    def rule_interval(self, node, parents, params) -> None:
        self.check_params(node, set())
        if len(parents) != 2:
            raise Refusal("rule-arity", "interval rule parents")
        op = node["rule"]["id"].split("_", 1)[1]
        p1, p2 = parents[0]["proposition"], parents[1]["proposition"]
        require_in_prop(p1, "interval rule")
        require_in_prop(p2, "interval rule")
        u1, row1 = prop_unit_info(p1, self.units)
        u2, row2 = prop_unit_info(p2, self.units)
        for row, uid in ((row1, u1), (row2, u2)):
            if row is not None and row["kind"] == "affine":
                raise Refusal("unit-affine-forbidden",
                              f"affine unit {uid} in interval arithmetic")
        i1 = validate_interval(p1["set"], self.units)
        i2 = validate_interval(p2["set"], self.units)
        if op in ("add", "sub"):
            if u1 != u2:
                raise Refusal("unit-dim-mismatch",
                              f"add/sub units {u1!r} vs {u2!r}")
            result_unit = u1
            result_row = row1
            j1, j2 = i1, i2
        else:
            if op == "div" and i2[0] <= 0 <= i2[1]:
                raise Refusal("interval-div-zero",
                              f"denominator [{p2['set']['lo']},"
                              f"{p2['set']['hi']}] contains zero")
            if u1 is None and u2 is None:
                result_unit, result_row = None, None
                j1, j2 = i1, i2
            elif row1 is not None and row2 is not None \
                    and dims_zero(row2["dim"]):
                result_unit, result_row = u1, row1
                j1 = i1
                j2 = scaled_interval(i2[0], i2[1], row2)
            elif row1 is not None and row2 is not None \
                    and dims_zero(row1["dim"]):
                result_unit, result_row = u2, row2
                j1 = scaled_interval(i1[0], i1[1], row1)
                j2 = i2
            elif row1 is not None and row2 is None:
                result_unit, result_row = u1, row1
                j1, j2 = i1, i2
            elif row1 is None and row2 is not None:
                result_unit, result_row = u2, row2
                j1, j2 = i1, i2
            else:
                # both dimensioned: drop to SI-coherent unitless
                result_unit, result_row = None, None
                j1 = scaled_interval(i1[0], i1[1], row1)
                j2 = scaled_interval(i2[0], i2[1], row2)
        if op == "div" and (j2[0] <= 0 <= j2[1]):
            raise Refusal("interval-div-zero", "denominator contains zero")
        h = hull_op(op, j1, j2)
        prop = node["proposition"]
        require_in_prop(prop, "interval conclusion")
        want_arg = {"t": op, "lhs": p1["arg"], "rhs": p2["arg"]}
        if prop["arg"] != want_arg:
            raise Refusal("rule-invalid",
                          "conclusion term must combine the parent terms")
        want_unit = result_unit
        if prop.get("unit") != want_unit and not (
                "unit" not in prop and want_unit is None):
            raise Refusal("rule-invalid",
                          f"conclusion unit {prop.get('unit')!r} != "
                          f"{want_unit!r}")
        got = validate_interval(prop["set"], self.units)
        want = h
        if result_row is not None and op in ("mul", "div"):
            want = (h[0] / result_row["scale"], h[1] / result_row["scale"])
        if got != want:
            raise Refusal("rule-invalid",
                          f"conclusion interval [{rat_token(got[0])},"
                          f"{rat_token(got[1])}] != exact hull "
                          f"[{rat_token(want[0])},{rat_token(want[1])}]")
        self.default_derived_checks(node, parents)

    def rule_unit_convert(self, node, parents, params) -> None:
        self.check_params(node, {"target_unit"})
        if len(parents) != 1:
            raise Refusal("rule-arity", "unit_convert parents")
        affine_rule = node["rule"]["id"] == "unit_convert_affine"
        parent_prop = parents[0]["proposition"]
        require_in_prop(parent_prop, "unit_convert")
        src_uid, src_row = prop_unit_info(parent_prop, self.units)
        if src_uid is None:
            raise Refusal("rule-invalid", "parent carries no unit")
        target_uid = node["rule"]["params"]["target_unit"]
        target_row = self.units.resolve(target_uid)
        if src_row["dim"] != target_row["dim"]:
            raise Refusal("unit-dim-mismatch",
                          f"{src_uid} -> {target_uid}")
        lo, hi = validate_interval(parent_prop["set"], self.units)
        involves_affine = (src_row["kind"] == "affine"
                           or target_row["kind"] == "affine")
        if affine_rule:
            if not involves_affine:
                raise Refusal("rule-invalid",
                              "affine rule over linear units")
            if lo != hi:
                raise Refusal("unit-affine-forbidden",
                              "affine conversion admits point values only")
        elif involves_affine:
            raise Refusal("unit-affine-forbidden",
                          f"{src_uid} -> {target_uid} requires the "
                          "affine rule")
        src_off = src_row["offset"] or Fraction(0)
        dst_off = target_row["offset"] or Fraction(0)
        si_lo = lo * src_row["scale"] + src_off
        si_hi = hi * src_row["scale"] + src_off
        want_lo = (si_lo - dst_off) / target_row["scale"]
        want_hi = (si_hi - dst_off) / target_row["scale"]
        prop = node["proposition"]
        require_in_prop(prop, "unit_convert conclusion")
        if prop["arg"] != parent_prop["arg"]:
            raise Refusal("rule-invalid",
                          "conversion must not change the term")
        if prop.get("unit") != target_uid:
            raise Refusal("rule-invalid", "conclusion unit != target")
        got = validate_interval(prop["set"], self.units)
        if got != (want_lo, want_hi):
            raise Refusal("rule-invalid",
                          f"converted interval != exact rescale "
                          f"[{rat_token(want_lo)},{rat_token(want_hi)}]")
        self.default_derived_checks(node, parents)

    def rule_threshold(self, node, parents, params) -> None:
        self.check_params(node, {"op", "threshold"})
        if len(parents) != 1:
            raise Refusal("rule-arity", "threshold parents")
        parent_prop = parents[0]["proposition"]
        require_in_prop(parent_prop, "threshold")
        if "unit" in parent_prop:
            raise Refusal("rule-invalid",
                          "threshold_from_enclosure requires a unitless "
                          "enclosure; convert first")
        op = node["rule"]["params"]["op"]
        if op not in ("lt", "le", "gt", "ge"):
            raise Refusal("rule-params", f"op {op!r}")
        threshold = parse_rat(node["rule"]["params"]["threshold"],
                              what="threshold")
        lo, hi = validate_interval(parent_prop["set"], self.units)
        established = {"lt": hi < threshold, "le": hi <= threshold,
                       "gt": lo > threshold, "ge": lo >= threshold}[op]
        if not established:
            raise Refusal("threshold-not-established",
                          f"enclosure [{rat_token(lo)},{rat_token(hi)}] "
                          f"does not establish {op} "
                          f"{node['rule']['params']['threshold']}")
        want = {"t": op, "lhs": parent_prop["arg"],
                "rhs": {"t": "rat",
                        "v": node["rule"]["params"]["threshold"]}}
        if node["proposition"] != want:
            raise Refusal("rule-invalid",
                          "threshold conclusion shape mismatch")
        self.default_derived_checks(node, parents)

    def rule_robust_decision(self, node, parents, params) -> None:
        self.check_params(node, {"decision_id", "action",
                                 "consequence_class"})
        if len(parents) != 1:
            raise Refusal("rule-arity", "robust_decision parents")
        thr = parents[0]
        if thr["rule"]["id"] != "threshold_from_enclosure":
            raise Refusal("rule-invalid",
                          "robust_decision parent must be a "
                          "threshold_from_enclosure node")
        cclass = node["rule"]["params"]["consequence_class"]
        if cclass not in CONSEQUENCE_FLOORS:
            raise Refusal("rule-params",
                          f"unknown consequence_class {cclass!r}")
        cmp_prop = thr["proposition"]
        op = cmp_prop["t"]
        threshold = parse_rat(cmp_prop["rhs"]["v"], what="threshold")
        encl = self.by_id[thr["parents"][0]]
        lo, hi = validate_interval(encl["proposition"]["set"], self.units)
        margin = (threshold - hi) if op in ("lt", "le") else \
            (lo - threshold)
        decision = node["decision"]
        if decision is None or set(decision.keys()) != DECISION_KEYS:
            raise Refusal("rule-invalid", "decision binding shape")
        want_decision = {
            "decision_id": node["rule"]["params"]["decision_id"],
            "action": node["rule"]["params"]["action"],
            "comparison": op,
            "threshold": cmp_prop["rhs"]["v"],
            "margin": rat_token(margin),
            "consequence_class": cclass,
        }
        if decision != want_decision:
            raise Refusal("rule-invalid",
                          f"decision binding mismatch: expected "
                          f"{want_decision}")
        want_prop = {"t": "pred", "name": "threshold_robust",
                     "args": [cmp_prop["lhs"], {"t": "str", "v": op},
                              cmp_prop["rhs"]]}
        if node["proposition"] != want_prop:
            raise Refusal("rule-invalid", "robust_decision proposition")
        strict_needed = op in ("lt", "gt")
        if margin < 0 or (strict_needed and margin <= 0):
            raise Refusal("rule-invalid", "margin not established")
        self.default_derived_checks(node, parents)
        floor = CONSEQUENCE_FLOORS[cclass]
        a = node["assurance"]
        if MATH_RANKS[a["mathematical"]] < \
                MATH_RANKS[floor["mathematical_min"]]:
            raise Refusal("consequence-floor",
                          f"{cclass} requires mathematical >= "
                          f"{floor['mathematical_min']}, got "
                          f"{a['mathematical']}")
        if IMPL_ORDER.index(a["implementation"]) < \
                IMPL_ORDER.index(floor["implementation_min"]):
            raise Refusal("consequence-floor",
                          f"{cclass} requires implementation >= "
                          f"{floor['implementation_min']}, got "
                          f"{a['implementation']}")
        if PROV_ORDER.index(a["input_provenance"]) < \
                PROV_ORDER.index(floor["input_provenance_min"]):
            raise Refusal("consequence-floor",
                          f"{cclass} requires input_provenance >= "
                          f"{floor['input_provenance_min']}, got "
                          f"{a['input_provenance']}")
        if a["model_validity"] not in floor["model_validity_allowed"]:
            raise Refusal("consequence-floor",
                          f"{cclass} forbids model_validity="
                          f"{a['model_validity']}")
        if floor["margin_positive"] and margin <= 0:
            raise Refusal("consequence-floor",
                          f"{cclass} requires a strictly positive margin")

    def rule_model_condition(self, node, parents, params) -> None:
        self.check_params(node, {"added_assumptions"})
        if len(parents) != 1:
            raise Refusal("rule-arity", "model_condition parents")
        parent = parents[0]
        added = node["rule"]["params"]["added_assumptions"]
        if (not isinstance(added, list)
                or not all(isinstance(a, str) for a in added)):
            raise Refusal("rule-params", "added_assumptions")
        if node["proposition"] != parent["proposition"]:
            raise Refusal("rule-invalid",
                          "model_condition must preserve the proposition")
        parent_model = parent["assurance"]["model_validity"]
        child_model = node["assurance"]["model_validity"]
        if parent_model == MODEL_IDENTITY:
            allowed = {"assumed"}
        else:
            allowed = {v for v in MODEL_ORDER
                       if MODEL_ORDER.index(v)
                       <= MODEL_ORDER.index(parent_model)}
        if child_model not in allowed:
            raise Refusal("model-upgrade",
                          f"model_validity {parent_model} -> "
                          f"{child_model}")
        for axis, cls in (("mathematical", "assurance-launder"),
                          ("input_provenance", "provenance-upgrade"),
                          ("implementation", "implementation-upgrade")):
            if node["assurance"][axis] != parent["assurance"][axis]:
                raise Refusal(cls, f"model_condition changed {axis}")
        if node["assurance"]["artifact"] != parent["assurance"]["artifact"]:
            raise Refusal("artifact-upgrade",
                          "model_condition changed artifact flags")
        if node["env"] != parent["env"]:
            raise Refusal("rule-invalid", "env must match parent")
        if node["assumptions"] != self.merged_assumptions([parent], added):
            raise Refusal("rule-invalid",
                          "assumptions must extend the parent's by "
                          "added_assumptions")
        if node["residual_non_claims"] != expected_residuals([parent]):
            raise Refusal("residual-missing", "residual set")

    def rule_passthrough(self, node, parents, params) -> None:
        self.check_params(node, set())
        if len(parents) != 1:
            raise Refusal("rule-arity", "provenance_passthrough parents")
        parent = parents[0]
        if node["proposition"] != parent["proposition"]:
            raise Refusal("rule-invalid",
                          "passthrough must preserve the proposition")
        p_prov = parent["assurance"]["input_provenance"]
        c_prov = node["assurance"]["input_provenance"]
        if PROV_ORDER.index(c_prov) > PROV_ORDER.index(p_prov):
            raise Refusal("provenance-upgrade",
                          f"{p_prov} -> {c_prov}")
        for axis, cls in (("mathematical", "assurance-launder"),
                          ("model_validity", "model-upgrade"),
                          ("implementation", "implementation-upgrade")):
            if node["assurance"][axis] != parent["assurance"][axis]:
                raise Refusal(cls, f"passthrough changed {axis}")
        if node["assurance"]["artifact"] != parent["assurance"]["artifact"]:
            raise Refusal("artifact-upgrade",
                          "passthrough changed artifact flags")
        if node["env"] != parent["env"]:
            raise Refusal("rule-invalid", "env must match parent")
        if node["assumptions"] != parent["assumptions"]:
            raise Refusal("rule-invalid", "assumptions must match parent")
        if node["residual_non_claims"] != expected_residuals([parent]):
            raise Refusal("residual-missing", "residual set")

    def rule_attach(self, node, parents, params) -> None:
        self.check_params(node, {"attestations"})
        if len(parents) != 1:
            raise Refusal("rule-arity", "attach parents")
        parent = parents[0]
        if node["proposition"] != parent["proposition"]:
            raise Refusal("rule-invalid",
                          "attach must preserve the proposition")
        for axis, cls in (("mathematical", "assurance-launder"),
                          ("model_validity", "model-upgrade"),
                          ("input_provenance", "provenance-upgrade"),
                          ("implementation", "implementation-upgrade")):
            if node["assurance"][axis] != parent["assurance"][axis]:
                raise Refusal(cls, f"attestation attach changed {axis}")
        attestations = node["rule"]["params"]["attestations"]
        if not isinstance(attestations, list):
            raise Refusal("rule-params", "attestations must be a list")
        kinds = set()
        for att in attestations:
            if (not isinstance(att, dict)
                    or set(att.keys()) != {"kind", "value"}
                    or not isinstance(att.get("kind"), str)
                    or not isinstance(att.get("value"), str)):
                raise Refusal("rule-params", "attestation record shape")
            kinds.add(att["kind"])
        for flag in ARTIFACT_FLAGS:
            p_flag = parent["assurance"]["artifact"][flag]
            c_flag = node["assurance"]["artifact"][flag]
            if c_flag == p_flag:
                continue
            if not c_flag:
                raise Refusal("artifact-upgrade",
                              f"attach may not clear {flag}")
            if ATTESTATION_KIND_FOR_FLAG[flag] not in kinds:
                raise Refusal("artifact-upgrade",
                              f"{flag} requires a "
                              f"{ATTESTATION_KIND_FOR_FLAG[flag]} record")
        if node["env"] != parent["env"]:
            raise Refusal("rule-invalid", "env must match parent")
        if node["assumptions"] != parent["assumptions"]:
            raise Refusal("rule-invalid", "assumptions must match parent")
        if node["residual_non_claims"] != expected_residuals([parent]):
            raise Refusal("residual-missing", "residual set")


# --------------------------------------------------------------- renderer
MATH_WORDING = {
    "exact": "Exact over the admitted integer/rational semantics",
    "formal-bounded": ("Formally enclosed under the named checker and "
                       "model assumptions"),
    "bounded": "Bounded enclosure composed via registered interval rules",
    "checked": "Checked result",
    "estimated": "Estimate without certified bound",
    "model-based": "Model-based result",
    "indeterminate": "Indeterminate",
    "refused": "Refused",
}
IMPL_WORDING = {
    "unknown": "implementation status unknown",
    "directly-trusted": "directly trusted implementation",
    "campaign-tested": "campaign-tested implementation",
    "independently-recomputed": "independently recomputed",
    "checker-derived": "implementation checker-derived",
    "source-native-refined": "source-native refined",
}
MODEL_WORDING = {
    "not-applicable": "no physical model involved",
    "unknown": "model validity unknown",
    "assumed": "conditional on the stated model assumptions",
    "calibrated": "calibrated model",
    "empirically-validated": "empirically validated model",
}


def render(root: dict) -> dict:
    a = root["assurance"]
    fresh = root["freshness"]
    parts = [
        MATH_WORDING[a["mathematical"]],
        IMPL_WORDING[a["implementation"]],
        f"input provenance {a['input_provenance']}",
        MODEL_WORDING[a["model_validity"]],
    ]
    token_parts = ["render-v1", a["mathematical"], a["input_provenance"],
                   a["model_validity"], a["implementation"]]
    if root["decision"] is not None:
        d = root["decision"]
        parts.append(
            f"decision {d['decision_id']} ({d['consequence_class']}) "
            f"robust with certified margin {d['margin']}")
        token_parts.append("decision")
    if fresh["nonce"] is not None:
        parts.append("nonce-bound")
        token_parts.append("nonce")
    if fresh["max_age_seconds"] is not None \
            or fresh["expires_at_unix"] is not None:
        parts.append("age-checked")
        token_parts.append("aged")
    if root["assumptions"]:
        parts.append("assumptions(" + str(len(root["assumptions"])) + "): "
                     + "; ".join(root["assumptions"]))
    parts.append("non-claims: " + "; ".join(root["residual_non_claims"]))
    return {"token": "/".join(token_parts),
            "permitted_text": ". ".join(parts) + "."}


# ------------------------------------------------------------ verification
def verify_bundle(args) -> tuple[str, list[str]]:
    """Returns (root_id, output_lines).  Raises Refusal/Indeterminate."""
    if args.bundle == "-":
        raw = sys.stdin.buffer.read(args.max_bundle_bytes + 1)
    else:
        try:
            raw = Path(args.bundle).read_bytes()
        except OSError as exc:
            raise Refusal("bundle-json", f"unreadable: {exc}") from None
    if len(raw) > args.max_bundle_bytes:
        raise Refusal("bundle-budget", "bundle bytes")

    inf_doc, units, _inf_raw, _unit_raw = load_registries(args)

    bundle = strict_loads(raw, what="bundle")
    if not isinstance(bundle, dict):
        raise Refusal("bundle-schema", "bundle must be an object")
    walk_document(bundle)
    keys = set(bundle.keys())
    if bundle.get("schema") != SCHEMA_BUNDLE:
        raise Refusal("bundle-schema", str(bundle.get("schema"))[:60])
    missing = BUNDLE_KEYS - keys
    if missing:
        raise Refusal("bundle-fields", f"missing {sorted(missing)}")
    extra = keys - BUNDLE_KEYS
    if extra:
        raise Refusal("unknown-field", f"bundle: {sorted(extra)}")

    if bundle["release_epoch"] != args.expected_release_epoch:
        raise Refusal("epoch-mismatch",
                      f"bundle {bundle['release_epoch']!r} != expected "
                      f"{args.expected_release_epoch!r}")

    engine = bundle["engine_identity"]
    if (not isinstance(engine, dict)
            or set(engine.keys()) != {"evaluator_sha256",
                                      "source_anb_sha256"}):
        raise Refusal("bundle-fields", "engine_identity shape")
    if engine["evaluator_sha256"] != args.expected_environment_epoch:
        raise Refusal("environment-mismatch", "engine evaluator")
    if not HEX64_RE.match(str(engine["source_anb_sha256"])):
        raise Refusal("bundle-fields", "source_anb_sha256")

    regs = bundle["registries"]
    if (not isinstance(regs, dict)
            or set(regs.keys()) != {"inference_registry_sha256",
                                    "unit_registry_sha256"}):
        raise Refusal("bundle-fields", "registries shape")
    if regs["inference_registry_sha256"] != \
            args.expected_inference_registry_sha256:
        raise Refusal("registry-inference-mismatch", "bundle vs pin")
    if regs["unit_registry_sha256"] != \
            args.expected_unit_registry_sha256:
        raise Refusal("registry-unit-mismatch", "bundle vs pin")

    # policy pin before policy validation
    policy = bundle["policy"]
    policy_sha = sha_hex(canonical_bytes(policy))
    expected_policy_sha = args.expected_policy_sha256
    if args.expected_policy:
        pol_raw = Path(args.expected_policy).read_bytes()
        expected_policy_sha = sha_hex(canonical_bytes(
            strict_loads(pol_raw, what="expected policy")))
    if expected_policy_sha is None:
        raise Indeterminate("policy-pin-missing",
                            "--expected-policy-sha256 or --expected-policy "
                            "is required")
    if policy_sha != expected_policy_sha:
        raise Refusal("policy-pin-mismatch",
                      f"{policy_sha[:16]} != {expected_policy_sha[:16]}")
    validate_policy(policy)

    nodes = bundle["nodes"]
    if not isinstance(nodes, list) or not nodes:
        raise Refusal("bundle-fields", "nodes must be a non-empty list")
    if len(nodes) > MAX_NODES:
        raise Refusal("bundle-budget", f"{len(nodes)} nodes")

    # -- shape pass + duplicate ids
    by_id: dict[str, dict] = {}
    index_of: dict[str, int] = {}
    for i, node in enumerate(nodes):
        if not isinstance(node, dict):
            raise Refusal("node-fields", f"node[{i}] not an object")
        nkeys = set(node.keys())
        if node.get("schema") != SCHEMA_NODE:
            raise Refusal("node-schema", str(node.get("schema"))[:60])
        missing = NODE_KEYS - nkeys
        if missing:
            raise Refusal("node-fields",
                          f"node[{i}] missing {sorted(missing)}")
        extra = nkeys - NODE_KEYS
        if extra:
            raise Refusal("unknown-field", f"node[{i}]: {sorted(extra)}")
        nid = node["id"]
        if not isinstance(nid, str) or not HEX64_RE.match(nid):
            raise Refusal("node-fields", f"node[{i}] id")
        if nid in by_id:
            if canonical_bytes(by_id[nid]) != canonical_bytes(node):
                raise Refusal("node-duplicate-id", nid[:16])
            raise Refusal("node-duplicate-id", f"repeated {nid[:16]}")
        by_id[nid] = node
        index_of[nid] = i

    root_id = bundle["root"]
    if root_id not in by_id:
        raise Refusal("root-missing", str(root_id)[:64])

    # -- graph shape on declared ids
    for i, node in enumerate(nodes):
        parents = node["parents"]
        if not isinstance(parents, list):
            raise Refusal("node-fields", "parents must be a list")
        if len(parents) > MAX_PARENTS:
            raise Refusal("bundle-budget", "parents")
        seen = set()
        for pid in parents:
            if pid == node["id"]:
                raise Refusal("graph-cycle", f"self-parent {pid[:16]}")
            if pid not in by_id:
                raise Refusal("parent-missing", str(pid)[:64])
            if pid in seen:
                raise Refusal("parent-duplicate", pid[:16])
            seen.add(pid)
            if index_of[pid] >= i:
                raise Refusal("parent-order",
                              f"parent {pid[:16]} not before node")

    # reachability closure from root
    reachable = set()
    stack = [root_id]
    while stack:
        nid = stack.pop()
        if nid in reachable:
            continue
        reachable.add(nid)
        stack.extend(by_id[nid]["parents"])
    orphans = set(by_id) - reachable
    if orphans:
        raise Refusal("orphan-node",
                      f"{len(orphans)} unreachable node(s)")

    # depth
    depth: dict[str, int] = {}
    for node in nodes:
        parents = node["parents"]
        depth[node["id"]] = 1 + max((depth[p] for p in parents), default=0)
    graph_depth = max(depth.values())
    if graph_depth > MAX_DEPTH:
        raise Refusal("bundle-budget", f"depth {graph_depth}")

    # -- deep validation per node
    engine_epoch = args.expected_environment_epoch
    for node in nodes:
        deep_validate_node(node, units, args, engine_epoch)

    # -- id recompute
    for node in nodes:
        body = {k: v for k, v in node.items() if k != "id"}
        want = sha_hex(canonical_bytes(body))
        if node["id"] != want:
            raise Refusal("node-id-mismatch",
                          f"declared {node['id'][:16]} != {want[:16]}")

    # -- bundle digest
    digest_body = {k: v for k, v in bundle.items()
                   if k != "bundle_digest_sha256"}
    want_digest = sha_hex(canonical_bytes(digest_body))
    if bundle["bundle_digest_sha256"] != want_digest:
        raise Refusal("digest-mismatch",
                      f"declared {str(bundle['bundle_digest_sha256'])[:16]}"
                      f" != {want_digest[:16]}")

    # -- root proposition pin
    root = by_id[root_id]
    rp = args.expected_root_proposition
    rp_path = Path(rp)
    rp_raw = rp_path.read_bytes() if rp_path.exists() else rp.encode()
    expected_prop = strict_loads(rp_raw, what="expected root proposition")
    if canonical_bytes(expected_prop) != canonical_bytes(
            root["proposition"]):
        raise Refusal("root-proposition-mismatch",
                      "caller-pinned root proposition differs")

    # -- nonce binding (root)
    root_nonce = root["freshness"]["nonce"]
    if args.expected_nonce is not None:
        if root_nonce is None:
            raise Refusal("nonce-missing",
                          "caller expects a nonce; root carries none")
        if root_nonce != args.expected_nonce:
            raise Refusal("nonce-mismatch", "root nonce differs")

    # -- evidence + rules (topological = list order)
    ctx = LegacyContext(args)
    engine_rules = RuleEngine(units, by_id)
    for node in nodes:
        rule_id = node["rule"]["id"]
        parents = [by_id[p] for p in node["parents"]]
        if rule_id not in RULE_IDS:
            raise Refusal("rule-unknown", rule_id[:60])
        if rule_id == "input_declare":
            verify_input_declare(node)
        elif rule_id == "evidence_admit":
            verify_evidence_admit(node, ctx)
        else:
            if not parents:
                raise Refusal("rule-arity",
                              f"{rule_id} requires parents")
            if node["evidence"] != {"kind": "none"}:
                raise Refusal("evidence-kind",
                              "derived nodes carry no evidence")
            engine_rules.eval_rule(node, parents)
        if rule_id != "robust_decision" and node["decision"] is not None:
            raise Refusal("rule-invalid",
                          "decision binding outside robust_decision")

    # -- policy on root
    enforce_policy(policy, bundle, root, by_id, graph_depth, args)

    # -- rendering
    computed_rendering = render(root)
    if bundle["rendering"] is not None:
        r = bundle["rendering"]
        if (not isinstance(r, dict)
                or set(r.keys()) != {"token", "permitted_text"}
                or r != computed_rendering):
            raise Refusal("render-mismatch",
                          "bundle rendering differs from deterministic "
                          "recompute")

    # -- success output
    a = root["assurance"]
    fresh = root["freshness"]
    lines = [
        "claim-verify=verified",
        f"bundle.digest={want_digest}",
        f"root={root_id}",
        f"root.proposition_sha256="
        f"{sha_hex(canonical_bytes(root['proposition']))}",
        f"nodes={len(nodes)} depth={graph_depth}",
        f"axes: input_provenance={a['input_provenance']} "
        f"model_validity={a['model_validity']} "
        f"mathematical={a['mathematical']} "
        f"implementation={a['implementation']}",
        "artifact: " + " ".join(
            f"{flag}={str(a['artifact'][flag]).lower()}"
            for flag in ARTIFACT_FLAGS),
        f"freshness: epoch={bundle['release_epoch']} "
        f"environment={engine_epoch[:16]} "
        f"nonce={'bound' if root_nonce is not None else 'none'}",
        f"assumptions={len(root['assumptions'])}",
        "residual_non_claims=" + "; ".join(root["residual_non_claims"]),
    ]
    if root["decision"] is not None:
        d = root["decision"]
        lines.append(
            f"decision: id={d['decision_id']} action={d['action']} "
            f"class={d['consequence_class']} margin={d['margin']}")
    lines.append(f"rendering.token={computed_rendering['token']}")
    lines.append("permitted_text=" + computed_rendering["permitted_text"])
    return root_id, lines


def validate_policy(policy: dict) -> None:
    if not isinstance(policy, dict) or \
            policy.get("schema") != SCHEMA_POLICY:
        raise Refusal("policy-schema", "schema")
    if set(policy.keys()) != POLICY_KEYS:
        raise Refusal("policy-schema", "keys")
    if not isinstance(policy["policy_id"], str):
        raise Refusal("policy-schema", "policy_id")
    accept = policy["accept"]
    if not isinstance(accept, dict) or \
            set(accept.keys()) != POLICY_ACCEPT_KEYS:
        raise Refusal("policy-schema", "accept keys")
    for axis, vocab in (("input_provenance", PROV_ORDER),
                        ("model_validity",
                         MODEL_ORDER + [MODEL_IDENTITY]),
                        ("mathematical", MATH_ORDER),
                        ("implementation", IMPL_ORDER)):
        vals = accept[axis]
        if (not isinstance(vals, list) or not vals
                or not all(v in vocab for v in vals)):
            raise Refusal("policy-schema", f"accept.{axis}")
    flags = accept["artifact_required_flags"]
    if not isinstance(flags, dict) or \
            not all(k in ARTIFACT_FLAGS and isinstance(v, bool)
                    for k, v in flags.items()):
        raise Refusal("policy-schema", "artifact_required_flags")
    require = policy["require"]
    if not isinstance(require, dict) or \
            set(require.keys()) != POLICY_REQUIRE_KEYS:
        raise Refusal("policy-schema", "require keys")
    for key in ("max_nodes", "max_depth", "max_age_seconds"):
        v = require[key]
        if v is not None and (isinstance(v, bool) or not isinstance(v, int)
                              or v < 0 or v > MAX_JSON_INT):
            raise Refusal("policy-schema", key)
    if not isinstance(require["require_nonce"], bool):
        raise Refusal("policy-schema", "require_nonce")
    for key in ("decision_margin_min", "max_enclosure_width"):
        if require[key] is not None:
            parse_rat(require[key], what=f"policy {key}")
    if (not isinstance(require["forbid_rules"], list)
            or not all(isinstance(r, str)
                       for r in require["forbid_rules"])):
        raise Refusal("policy-schema", "forbid_rules")
    if not isinstance(policy["allow_fallback"], bool):
        raise Refusal("policy-schema", "allow_fallback")


def deep_validate_node(node: dict, units: UnitRegistry, args,
                       engine_epoch: str) -> None:
    if node["release_epoch"] != args.expected_release_epoch:
        raise Refusal("epoch-mismatch",
                      f"node epoch {node['release_epoch']!r}")
    env = node["env"]
    if (not isinstance(env, dict) or set(env.keys()) != {"vars"}
            or not isinstance(env["vars"], dict)):
        raise Refusal("node-fields", "env shape")
    for name, dom in env["vars"].items():
        if not VAR_RE.match(name):
            raise Refusal("node-fields", f"env var {name!r}")
        validate_interval(dom, units)
    assumptions = node["assumptions"]
    if (not isinstance(assumptions, list)
            or len(assumptions) > MAX_ASSUMPTIONS
            or not all(isinstance(a, str) for a in assumptions)):
        raise Refusal("node-fields", "assumptions")
    residuals = node["residual_non_claims"]
    if (not isinstance(residuals, list)
            or not all(isinstance(r, str) for r in residuals)):
        raise Refusal("node-fields", "residual_non_claims")
    for required in RESIDUALS:
        if required not in residuals:
            raise Refusal("residual-missing", required)
    evidence = node["evidence"]
    if not isinstance(evidence, dict) or "kind" not in evidence:
        raise Refusal("node-fields", "evidence shape")
    if evidence["kind"] == "none":
        if set(evidence.keys()) != {"kind"}:
            raise Refusal("node-fields", "evidence none shape")
    else:
        if evidence["kind"] not in EVIDENCE_KINDS:
            raise Refusal("evidence-kind", str(evidence["kind"])[:40])
        if set(evidence.keys()) != {"kind", "payload_b64", "sha256"}:
            raise Refusal("node-fields", "evidence payload shape")
    for who in ("producer", "checker"):
        ident = node[who]
        if ident is not None:
            if (not isinstance(ident, dict)
                    or set(ident.keys()) != {"name", "sha256"}
                    or not isinstance(ident["name"], str)
                    or not HEX64_RE.match(str(ident["sha256"]))):
                raise Refusal("node-fields", f"{who} identity")
    rule = node["rule"]
    if (not isinstance(rule, dict) or set(rule.keys()) != {"id", "params"}
            or not isinstance(rule.get("id"), str)
            or not isinstance(rule.get("params"), dict)):
        raise Refusal("node-fields", "rule shape")
    validate_assurance_vocab(node["assurance"])
    fresh = node["freshness"]
    if not isinstance(fresh, dict) or set(fresh.keys()) != FRESHNESS_KEYS:
        raise Refusal("freshness-schema", "keys")
    if not isinstance(fresh["source_version"], str):
        raise Refusal("freshness-schema", "source_version")
    emitted = parse_int_token(fresh["emitted_at_unix"], what="emitted_at")
    if emitted < 0:
        raise Refusal("freshness-schema", "emitted_at negative")
    max_age = fresh["max_age_seconds"]
    if max_age is not None and (isinstance(max_age, bool)
                                or not isinstance(max_age, int)
                                or max_age < 0):
        raise Refusal("freshness-schema", "max_age_seconds")
    expires = fresh["expires_at_unix"]
    expires_val = None
    if expires is not None:
        expires_val = parse_int_token(expires, what="expires_at")
        if expires_val < 0:
            raise Refusal("freshness-schema", "expires_at negative")
        if expires_val < emitted:
            raise Refusal("freshness-schema",
                          f"expires_at {expires_val} precedes emitted_at "
                          f"{emitted}")
    nonce = fresh["nonce"]
    if nonce is not None and not isinstance(nonce, str):
        raise Refusal("freshness-schema", "nonce")
    if fresh["environment_epoch"] != engine_epoch:
        raise Refusal("environment-mismatch",
                      f"node environment {str(fresh['environment_epoch'])[:16]}")
    vtime = args.verification_time_unix
    # Chronology lower bounds: a well-formed bundle must not verify before
    # it was emitted, at a negative (pre-epoch) verification time, or with a
    # lifecycle whose expiry precedes emission.  Ordering matters: domain
    # violations refuse as freshness-schema; a valid-but-too-early check
    # refuses as freshness-premature; only then are the upper expiry/age
    # bounds evaluated (so vtime - emitted is always non-negative below).
    if vtime < 0:
        raise Refusal("freshness-schema",
                      f"verification time {vtime} is negative")
    if vtime < emitted:
        raise Refusal("freshness-premature",
                      f"verification time {vtime} precedes emitted_at "
                      f"{emitted}")
    if expires_val is not None and vtime > expires_val:
        raise Refusal("freshness-expired",
                      f"expired at {expires_val}, verification time {vtime}")
    if max_age is not None and vtime - emitted > max_age:
        raise Refusal("freshness-stale",
                      f"age {vtime - emitted}s > max {max_age}s")
    decision = node["decision"]
    if decision is not None:
        if (not isinstance(decision, dict)
                or set(decision.keys()) != DECISION_KEYS):
            raise Refusal("node-fields", "decision shape")
        for key in ("decision_id", "action", "comparison",
                    "consequence_class"):
            if not isinstance(decision[key], str):
                raise Refusal("node-fields", f"decision.{key}")
        parse_rat(decision["threshold"], what="decision threshold")
        parse_rat(decision["margin"], what="decision margin")
    display = node["display"]
    if (not isinstance(display, dict) or set(display.keys()) != {"text"}
            or not isinstance(display["text"], str)):
        raise Refusal("node-fields", "display shape")
    info = validate_prop(node["proposition"], units, env["vars"])
    declared = set(env["vars"].keys())
    if node["rule"]["id"] == "input_declare" and info.vars != declared:
        raise Refusal("prop-schema",
                      "input env must declare exactly the used variables")


def verify_input_declare(node: dict) -> None:
    if node["parents"]:
        raise Refusal("rule-arity", "input_declare takes no parents")
    if node["evidence"] != {"kind": "none"}:
        raise Refusal("evidence-kind", "input_declare carries no evidence")
    params = node["rule"]["params"]
    keys = set(params.keys())
    required = {"source_description", "declared_provenance"}
    if not required <= keys or not keys <= (required | {"source_id"}):
        raise Refusal("rule-params", f"input_declare params {sorted(keys)}")
    if not isinstance(params["source_description"], str):
        raise Refusal("rule-params", "source_description")
    declared = params["declared_provenance"]
    if declared not in PROV_ORDER:
        raise Refusal("rule-params", "declared_provenance")
    a = node["assurance"]
    if a["input_provenance"] != declared:
        raise Refusal("provenance-upgrade",
                      "assurance provenance != declared_provenance")
    if declared not in PRODUCER_EMITTABLE_PROV:
        raise Refusal("provenance-upgrade",
                      f"v1 producers may not declare {declared!r}")
    if MATH_RANKS[a["mathematical"]] > MATH_RANKS["checked"]:
        raise Refusal("assurance-launder",
                      "input_declare caps mathematical at checked")
    if IMPL_ORDER.index(a["implementation"]) > \
            IMPL_ORDER.index("directly-trusted"):
        raise Refusal("implementation-upgrade",
                      "input_declare caps implementation at "
                      "directly-trusted")
    if a["model_validity"] not in (MODEL_IDENTITY, "unknown", "assumed"):
        raise Refusal("model-upgrade",
                      "input_declare model_validity")
    if any(a["artifact"].values()):
        raise Refusal("artifact-upgrade",
                      "input_declare artifact flags must be all false")
    prop = node["proposition"]
    if prop["t"] == "in":
        if prop["arg"].get("t") != "var":
            raise Refusal("rule-invalid",
                          "input enclosure must be over a variable")
        name = prop["arg"]["name"]
        if node["env"]["vars"].get(name) != prop["set"]:
            raise Refusal("rule-invalid",
                          "env domain must equal the declared enclosure")
    elif prop["t"] == "eq":
        if prop["lhs"].get("t") != "var" or prop["rhs"].get("t") != "rat":
            raise Refusal("rule-invalid",
                          "input eq must bind a variable to a rational")
        name = prop["lhs"]["name"]
        v = prop["rhs"]["v"]
        if node["env"]["vars"].get(name) != {"t": "interval",
                                             "lo": v, "hi": v}:
            raise Refusal("rule-invalid",
                          "env domain must be the degenerate interval")
    else:
        raise Refusal("rule-invalid",
                      "input_declare admits in/eq propositions only")
    if node["assumptions"]:
        raise Refusal("rule-invalid", "input_declare assumptions empty")
    if node["residual_non_claims"] != RESIDUALS:
        raise Refusal("residual-missing", "input residual set")


def verify_evidence_admit(node: dict, ctx: LegacyContext) -> None:
    if node["parents"]:
        raise Refusal("rule-arity", "evidence_admit takes no parents")
    params = node["rule"]["params"]
    kind = params.get("evidence_kind")
    if kind not in EVIDENCE_KINDS:
        raise Refusal("rule-params", f"evidence_kind {kind!r}")
    if set(params.keys()) != EVIDENCE_PARAM_KEYS[kind]:
        raise Refusal("rule-params",
                      f"{kind} params {sorted(params.keys())}")
    evidence = node["evidence"]
    if evidence["kind"] != kind:
        raise Refusal("evidence-kind",
                      "params kind != evidence kind")
    try:
        payload = base64.b64decode(evidence["payload_b64"], validate=True)
    except Exception as exc:  # binascii.Error
        raise Refusal("evidence-encoding", str(exc)[:80]) from None
    if len(payload) > MAX_EVIDENCE_BYTES:
        raise Refusal("bundle-budget", "evidence payload")
    if sha_hex(payload) != evidence["sha256"]:
        raise Refusal("evidence-hash-mismatch",
                      "payload bytes do not match declared sha256")
    if kind == "formal-receipt":
        result = dispatch_receipt(ctx, payload, params)
        receipt = result["receipt"]
        want_prop = derive_receipt_prop(receipt)
        m = re.search(r"enclosure=\[([^,\]]+),([^\]]+)\]",
                      result["stdout"])
        if not m or [m.group(1), m.group(2)] != [
                receipt["result"]["enclosure_lo"],
                receipt["result"]["enclosure_hi"]]:
            raise Refusal("evidence-verify-failed",
                          "verifier enclosure echo mismatch")
        want_assumptions = [f"receipt:{a}" for a in receipt["assumptions"]]
        if node["assumptions"] != want_assumptions:
            raise Refusal("rule-invalid",
                          "receipt assumptions must be carried verbatim")
        if node["producer"] is None or node["checker"] is None or \
                node["producer"]["sha256"] != \
                receipt["identities"]["evaluator_sha256"] or \
                node["checker"]["sha256"] != result["expected_checker"]:
            raise Refusal("rule-invalid",
                          "receipt node must bind producer/checker "
                          "identities")
    elif kind == "exact-cert":
        cert = dispatch_exact(ctx, payload)
        want_prop = derive_exact_prop(cert)
        if node["assumptions"]:
            raise Refusal("rule-invalid",
                          "exact-cert nodes carry no assumptions")
        if node["producer"] is not None or node["checker"] is not None:
            raise Refusal("rule-invalid",
                          "exact-cert nodes bind no producer/checker")
    else:  # machine-int-cert
        cert = verify_machine_cert(payload)
        eq_form = machine_eq_prop(cert)
        overflow_form = machine_overflow_prop(cert)
        checked_overflow = cert["mode"] == "checked" and cert["overflow"]
        want_prop = overflow_form if checked_overflow else eq_form
        if node["proposition"] != want_prop:
            alternate = eq_form if checked_overflow else overflow_form
            if node["proposition"] == alternate:
                raise Refusal("machine-overflow-claim",
                              "proposition form does not match the "
                              "certificate mode/overflow state")
            raise Refusal("evidence-prop-mismatch",
                          "machine proposition mismatch")
        if node["assumptions"]:
            raise Refusal("rule-invalid",
                          "machine-int nodes carry no assumptions")
        if node["producer"] is not None or node["checker"] is not None:
            raise Refusal("rule-invalid",
                          "machine-int nodes bind no producer/checker")
    if canonical_bytes(node["proposition"]) != canonical_bytes(want_prop):
        raise Refusal("evidence-prop-mismatch",
                      "node proposition differs from the deterministic "
                      "derivation")
    computed = ADAPTER_AXES[kind]
    check_axis_equality(node["assurance"], computed, f"evidence {kind}")
    if node["env"] != {"vars": {}}:
        raise Refusal("rule-invalid", "evidence nodes declare no vars")
    if node["residual_non_claims"] != RESIDUALS:
        raise Refusal("residual-missing", "evidence residual set")


def enforce_policy(policy: dict, bundle: dict, root: dict, by_id: dict,
                   graph_depth: int, args) -> None:
    accept = policy["accept"]
    a = root["assurance"]
    for axis in ("input_provenance", "model_validity", "mathematical",
                 "implementation"):
        if a[axis] not in accept[axis]:
            raise Refusal("policy-violation",
                          f"root {axis}={a[axis]} not in accepted set "
                          f"{accept[axis]}")
    for flag, wanted in accept["artifact_required_flags"].items():
        if wanted and not a["artifact"][flag]:
            raise Refusal("policy-violation",
                          f"artifact flag {flag} required")
    require = policy["require"]
    if require["max_nodes"] is not None and \
            len(bundle["nodes"]) > require["max_nodes"]:
        raise Refusal("policy-violation", "max_nodes")
    if require["max_depth"] is not None and \
            graph_depth > require["max_depth"]:
        raise Refusal("policy-violation", "max_depth")
    if require["require_nonce"] and root["freshness"]["nonce"] is None:
        raise Refusal("policy-violation", "nonce required by policy")
    if require["max_age_seconds"] is not None:
        # deep_validate_node has already enforced vtime >= emitted for every
        # node (freshness-premature), so this policy age is non-negative.
        emitted = int(root["freshness"]["emitted_at_unix"])
        if args.verification_time_unix - emitted > \
                require["max_age_seconds"]:
            raise Refusal("policy-violation", "policy max age")
    if require["decision_margin_min"] is not None:
        if root["decision"] is None:
            raise Refusal("policy-violation",
                          "policy requires a decision binding")
        if parse_rat(root["decision"]["margin"], what="margin") < \
                parse_rat(require["decision_margin_min"], what="floor"):
            raise Refusal("policy-violation", "decision margin floor")
    if require["max_enclosure_width"] is not None:
        prop = root["proposition"]
        if prop.get("t") != "in":
            raise Refusal("policy-violation",
                          "width bound requires an enclosure root")
        width = parse_rat(prop["set"]["hi"], what="hi") - \
            parse_rat(prop["set"]["lo"], what="lo")
        if width > parse_rat(require["max_enclosure_width"], what="bound"):
            raise Refusal("policy-violation", "enclosure width")
    forbidden = set(require["forbid_rules"])
    if forbidden:
        for node in bundle["nodes"]:
            if node["rule"]["id"] in forbidden:
                raise Refusal("policy-violation",
                              f"rule {node['rule']['id']} forbidden")


# ------------------------------------------------------------------- CLI
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="claim_bundle_verify.py")
    p.add_argument("--bundle", required=True)
    p.add_argument("--expected-release-epoch", required=True)
    p.add_argument("--expected-policy")
    p.add_argument("--expected-policy-sha256")
    p.add_argument("--expected-root-proposition", required=True)
    p.add_argument("--expected-inference-registry", required=True)
    p.add_argument("--expected-inference-registry-sha256", required=True)
    p.add_argument("--expected-unit-registry", required=True)
    p.add_argument("--expected-unit-registry-sha256", required=True)
    p.add_argument("--expected-environment-epoch", required=True)
    p.add_argument("--verification-time-unix", required=True, type=int)
    p.add_argument("--expected-nonce")
    p.add_argument("--receipt-verifier")
    p.add_argument("--exact-verifier")
    p.add_argument("--checker")
    p.add_argument("--expected-checker")
    p.add_argument("--expected-evaluator")
    p.add_argument("--inventory")
    p.add_argument("--expected-inventory")
    p.add_argument("--proof-identity")
    p.add_argument("--expected-proof-identity-file")
    p.add_argument("--expected-proof-identity-digest")
    p.add_argument("--gaussian-checker")
    p.add_argument("--expected-gaussian-checker")
    p.add_argument("--gaussian-proof-identity")
    p.add_argument("--expected-gaussian-proof-identity-file")
    p.add_argument("--expected-gaussian-proof-identity-digest")
    p.add_argument("--int-cert-checker")
    p.add_argument("--expected-int-cert-checker")
    p.add_argument("--int-cert-proof-identity")
    p.add_argument("--expected-int-cert-proof-identity-file")
    p.add_argument("--expected-int-cert-proof-identity-digest")
    p.add_argument("--archival-range-checker")
    p.add_argument("--expected-archival-range-checker")
    p.add_argument("--archival-range-proof-identity")
    p.add_argument("--expected-archival-range-proof-identity-file")
    p.add_argument("--expected-archival-range-proof-identity-digest")
    p.add_argument("--archival-range-inventory")
    p.add_argument("--expected-archival-range-inventory")
    p.add_argument("--trusted-producer", action="append", default=[])
    p.add_argument("--max-bundle-bytes", type=int,
                   default=MAX_BUNDLE_BYTES)
    return p


def main(argv: list[str]) -> int:
    args = build_parser().parse_args(argv)
    try:
        _root, lines = verify_bundle(args)
    except Refusal as refusal:
        detail = refusal.detail.replace("\n", " ")[:300]
        print(f"claim-verify=refused reason={refusal.cls} "
              f"detail=\"{detail}\"")
        return 1
    except Indeterminate as ind:
        detail = ind.detail.replace("\n", " ")[:300]
        print(f"claim-verify=indeterminate reason={ind.cls} "
              f"detail=\"{detail}\"")
        return 3
    except (RecursionError, MemoryError):
        print("claim-verify=refused reason=bundle-budget "
              "detail=\"resource budget exceeded\"")
        return 1
    except Exception as exc:  # noqa: BLE001 - fail closed, never crash
        detail = f"{type(exc).__name__}: {exc}".replace("\n", " ")[:200]
        print(f"claim-verify=refused reason=verifier-internal "
              f"detail=\"{detail}\"")
        return 1
    for line in lines:
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
