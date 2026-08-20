#!/usr/bin/env python3
"""Hostile semantic control matrix for the claim-bundle evidence kernel.

Covers the mission-required families: serialization/schema, graph
identity, assurance laundering, units/uncertainty, freshness/replay/
provenance, machine arithmetic, legacy compatibility, and rendering.
Every negative case has a positive twin.  Each case builds a bundle
(hand-constructed with an INDEPENDENT local canonicalizer — a third
implementation besides producer and verifier), invokes
`tools/claim_bundle_verify.py` under `python3 -I -S -B`, and asserts the
exact verdict and stable refusal class.

Writes deterministic evidence to
release/evidence/claim_hostile_matrix_v160.json (no volatile content).

Run: python3 tests/claim_hostile_test.py            (uses ./jackal-native)
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unicodedata
from fractions import Fraction
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENGINE = os.environ.get("JACKAL_BIN") or str(ROOT / "jackal-native")
VERIFIER = ROOT / "tools/claim_bundle_verify.py"
RECEIPT_VERIFIER = ROOT / "tools/receipt_verify.py"
EXACT_VERIFIER = ROOT / "tools/exact_verify.py"
CHECKER = ROOT / "proofs/lean/.lake/build/bin/jackal_cert_check"
ARCHIVAL_RANGE_CHECKER = Path(os.environ.get(
    "JACKAL_V170_ARCHIVAL_RANGE_CHECKER",
    str(Path.home() / "Library/Application Support/JACKAL/runtimes/v1.7.0/"
                      "jackal_cert_check")))
INF_REG = ROOT / "release/claim/inference_registry_v1.json"
UNIT_REG = ROOT / "release/claim/unit_registry_v1.json"
INVENTORY = ROOT / "release/coverage/formal_coverage_inventory.json"
ARCHIVAL_RANGE_INVENTORY = Path(os.environ.get(
    "JACKAL_V170_ARCHIVAL_RANGE_INVENTORY",
    str(ARCHIVAL_RANGE_CHECKER.parent / "formal_coverage_inventory.json")))
PROOF_ID = ROOT / "release/evidence/range_proof_identity_v172.json"
ARCHIVAL_RANGE_PROOF_ID = ROOT / "release/evidence/range_proof_identity.json"
EVIDENCE_OUT = ROOT / "release/evidence/claim_hostile_matrix_v160.json"

sys.path.insert(0, str(ROOT / "tools"))
import formal_receipt as fr  # noqa: E402

EPOCH = "v1.6.0"
VTIME = 1786752000
EMITTED = "1786752000"

RESIDUALS = [
    "no-source-native-refinement",
    "no-replay-prevention-without-external-nonce-store",
    "no-probability-distributions-from-intervals",
    "no-real-world-input-truth",
    "no-universal-soundness-bounded-fragments-only",
    "transparency-metadata-is-not-mathematical-evidence",
]

ARTIFACT_FALSE = {"content_addressed": False, "reproducible_built": False,
                  "authenticated": False, "transparency_logged": False}
ARTIFACT_CA = {"content_addressed": True, "reproducible_built": False,
               "authenticated": False, "transparency_logged": False}


def canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def sha_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def sha_file(p: Path) -> str:
    return sha_hex(p.read_bytes())


ENV_EPOCH = sha_file(Path(ENGINE))
SRC_SHA = sha_file(ROOT / "jackal_calc.anb")
INF_SHA = sha_file(INF_REG)
UNIT_SHA = sha_file(UNIT_REG)
CHECKER_SHA = sha_file(CHECKER) if CHECKER.exists() else ""
ARCHIVAL_RANGE_CHECKER_SHA = sha_file(ARCHIVAL_RANGE_CHECKER)
INVENTORY_SHA = sha_file(INVENTORY)
ARCHIVAL_RANGE_INVENTORY_SHA = sha_file(ARCHIVAL_RANGE_INVENTORY)
PROOF_ID_SHA = sha_file(PROOF_ID)
PROOF_ID_DIGEST = json.loads(PROOF_ID.read_text())["identity_digest_sha256"]
ARCHIVAL_RANGE_PROOF_ID_SHA = sha_file(ARCHIVAL_RANGE_PROOF_ID)
ARCHIVAL_RANGE_PROOF_ID_DIGEST = json.loads(
    ARCHIVAL_RANGE_PROOF_ID.read_text())["identity_digest_sha256"]

ROWS: list[dict] = []


# ------------------------------------------------------------- builders
def node_id(node: dict) -> str:
    return sha_hex(canon({k: v for k, v in node.items() if k != "id"}))


def base_node(**over) -> dict:
    node = {
        "schema": "jackal-claim-node-v1",
        "proposition": None,
        "env": {"vars": {}},
        "assumptions": [],
        "evidence": {"kind": "none"},
        "producer": None,
        "checker": None,
        "release_epoch": EPOCH,
        "parents": [],
        "rule": {"id": "input_declare", "params": {}},
        "assurance": {
            "input_provenance": "supplied",
            "model_validity": "not-applicable",
            "mathematical": "checked",
            "implementation": "directly-trusted",
            "artifact": dict(ARTIFACT_FALSE),
        },
        "freshness": {
            "source_version": EPOCH,
            "emitted_at_unix": EMITTED,
            "max_age_seconds": None,
            "expires_at_unix": None,
            "nonce": None,
            "environment_epoch": ENV_EPOCH,
        },
        "residual_non_claims": list(RESIDUALS),
        "decision": None,
        "display": {"text": ""},
    }
    node.update(over)
    node["id"] = node_id(node)
    return node


def rehash(node: dict) -> dict:
    node["id"] = node_id(node)
    return node


def interval(lo: str, hi: str) -> dict:
    return {"t": "interval", "lo": lo, "hi": hi}


def var(name: str) -> dict:
    return {"t": "var", "name": name}


def rat(v: str) -> dict:
    return {"t": "rat", "v": v}


def in_prop(term: dict, lo: str, hi: str, unit: str | None = None) -> dict:
    prop = {"t": "in", "arg": term, "set": interval(lo, hi)}
    if unit is not None:
        prop["unit"] = unit
    return prop


def input_node(name: str, lo: str, hi: str, *, unit: str | None = None,
               math: str = "checked", source_id: str | None = None,
               **over) -> dict:
    params = {"source_description": f"test-supplied-{name}",
              "declared_provenance": "supplied"}
    if source_id is not None:
        params["source_id"] = source_id
    node = base_node(
        proposition=in_prop(var(name), lo, hi, unit),
        env={"vars": {name: interval(lo, hi)}},
        rule={"id": "input_declare", "params": params},
        **over)
    node["assurance"]["mathematical"] = math
    return rehash(node)


def merge_env(parents: list[dict]) -> dict:
    vars_: dict = {}
    for p in parents:
        vars_.update(p["env"]["vars"])
    return {"vars": vars_}


def axis_meet(parents: list[dict], axis: str, order: list[str],
              ranks: dict | None = None) -> str:
    vals = [p["assurance"][axis] for p in parents]
    if axis == "model_validity":
        vals = [v for v in vals if v != "not-applicable"]
        if not vals:
            return "not-applicable"
    if ranks is None:
        ranks = {v: i for i, v in enumerate(order)}
    best = min(vals, key=lambda v: (ranks[v], order.index(v)))
    return best


MATH_ORDER = ["refused", "indeterminate", "estimated", "model-based",
              "checked", "bounded", "formal-bounded", "exact"]
MATH_RANKS = {"refused": 0, "indeterminate": 1, "estimated": 2,
              "model-based": 2, "checked": 3, "bounded": 4,
              "formal-bounded": 5, "exact": 6}
IMPL_ORDER = ["unknown", "directly-trusted", "campaign-tested",
              "independently-recomputed", "checker-derived",
              "source-native-refined"]
PROV_ORDER = ["unknown", "supplied", "integrity-bound", "observed",
              "authenticated-source", "measured"]
MODEL_ORDER = ["unknown", "assumed", "calibrated", "empirically-validated"]


def math_min(a: str, b: str) -> str:
    return a if MATH_RANKS[a] <= MATH_RANKS[b] else b


def impl_min(a: str, b: str) -> str:
    ranks = {v: i for i, v in enumerate(IMPL_ORDER)}
    return a if ranks[a] <= ranks[b] else b


def artifact_and(parents: list[dict]) -> dict:
    out = {}
    for flag in ARTIFACT_FALSE:
        out[flag] = all(p["assurance"]["artifact"][flag] for p in parents)
    return out


def derived_node(rule_id: str, parents: list[dict], proposition: dict,
                 params: dict | None = None, *, math_cap: str | None = None,
                 impl_cap: str | None = "independently-recomputed",
                 preserve: bool = False, decision: dict | None = None,
                 assumptions_extra: list[str] | None = None,
                 **over) -> dict:
    math = axis_meet(parents, "mathematical", MATH_ORDER, MATH_RANKS)
    if math_cap is not None:
        math = math_min(math, math_cap)
    impl = axis_meet(parents, "implementation", IMPL_ORDER)
    if not preserve and impl_cap is not None:
        impl = impl_min(impl, impl_cap)
    prov = axis_meet(parents, "input_provenance", PROV_ORDER)
    model = axis_meet(parents, "model_validity", MODEL_ORDER)
    assumptions: list[str] = []
    for p in parents:
        for a in p["assumptions"]:
            if a not in assumptions:
                assumptions.append(a)
    for a in (assumptions_extra or []):
        if a not in assumptions:
            assumptions.append(a)
    node = base_node(
        proposition=proposition,
        env=merge_env(parents),
        assumptions=assumptions,
        parents=[p["id"] for p in parents],
        rule={"id": rule_id, "params": params or {}},
        decision=decision,
        **over)
    node["assurance"] = {
        "input_provenance": prov,
        "model_validity": model,
        "mathematical": math,
        "implementation": impl,
        "artifact": artifact_and(parents),
    }
    return rehash(node)


def hull(op: str, i1: dict, i2: dict) -> dict:
    lo1, hi1 = Fraction(i1["lo"]), Fraction(i1["hi"])
    lo2, hi2 = Fraction(i2["lo"]), Fraction(i2["hi"])
    if op == "add":
        lo, hi = lo1 + lo2, hi1 + hi2
    elif op == "sub":
        lo, hi = lo1 - hi2, hi1 - lo2
    elif op == "mul":
        prods = [lo1 * lo2, lo1 * hi2, hi1 * lo2, hi1 * hi2]
        lo, hi = min(prods), max(prods)
    elif op == "div":
        recips = [1 / lo2, 1 / hi2]
        prods = [lo1 * r for r in recips] + [hi1 * r for r in recips]
        lo, hi = min(prods), max(prods)
    else:
        raise ValueError(op)
    return interval(str(lo), str(hi))


def interval_op_node(op: str, p1: dict, p2: dict, *,
                     forged_set: dict | None = None,
                     unit_override: str | None | bool = False) -> dict:
    """Build an interval_{op} node.  Unit semantics mirror the kernel:
    add/sub keep the (identical) parent unit; mul/div with one
    dimensionless side keep the united side's unit; anything else drops
    to None.  `unit_override` forces the conclusion unit when not False.
    """
    t1 = p1["proposition"]["arg"]
    t2 = p2["proposition"]["arg"]
    u1 = p1["proposition"].get("unit")
    u2 = p2["proposition"].get("unit")
    if unit_override is not False:
        unit = unit_override
    elif op in ("add", "sub"):
        unit = u1 if u1 == u2 else None
    elif u1 == u2 is None:
        unit = None
    elif u1 is not None and u2 is None:
        unit = u1
    elif u1 is None and u2 is not None:
        unit = u2
    else:
        unit = None
    out_set = forged_set or hull(op, p1["proposition"]["set"],
                                 p2["proposition"]["set"])
    prop = {"t": "in",
            "arg": {"t": op, "lhs": t1, "rhs": t2},
            "set": out_set}
    if unit is not None:
        prop["unit"] = unit
    return derived_node(f"interval_{op}", [p1, p2], prop, math_cap="bounded")


def and_node(parents: list[dict], **over) -> dict:
    prop = {"t": "and", "args": [p["proposition"] for p in parents]}
    return derived_node("and_intro", parents, prop, **over)


def threshold_node(parent: dict, op: str, threshold: str) -> dict:
    prop = {"t": op, "lhs": parent["proposition"]["arg"],
            "rhs": rat(threshold)}
    return derived_node("threshold_from_enclosure", [parent], prop,
                        params={"op": op, "threshold": threshold})


def decision_node(thr: dict, encl: dict, *, decision_id: str = "d1",
                  action: str = "proceed",
                  cclass: str = "decision-boundary",
                  forge_margin: str | None = None) -> dict:
    """robust_decision over a threshold node; margin from the enclosure."""
    cmp_prop = thr["proposition"]
    op = cmp_prop["t"]
    tval = Fraction(cmp_prop["rhs"]["v"])
    lo = Fraction(encl["proposition"]["set"]["lo"])
    hi = Fraction(encl["proposition"]["set"]["hi"])
    margin = (tval - hi) if op in ("lt", "le") else (lo - tval)
    prop = {"t": "pred", "name": "threshold_robust",
            "args": [cmp_prop["lhs"], {"t": "str", "v": op},
                     cmp_prop["rhs"]]}
    decision = {
        "decision_id": decision_id,
        "action": action,
        "comparison": op,
        "threshold": cmp_prop["rhs"]["v"],
        "margin": forge_margin if forge_margin is not None else str(margin),
        "consequence_class": cclass,
    }
    return derived_node("robust_decision", [thr], prop,
                        params={"decision_id": decision_id,
                                "action": action,
                                "consequence_class": cclass},
                        decision=decision)


def default_policy(**over) -> dict:
    pol = {
        "schema": "jackal-claim-policy-v1",
        "policy_id": "hostile-test-policy",
        "accept": {
            "input_provenance": ["supplied", "integrity-bound"],
            "model_validity": ["not-applicable", "assumed"],
            "mathematical": ["checked", "bounded", "formal-bounded",
                             "exact"],
            "implementation": ["directly-trusted", "campaign-tested",
                               "independently-recomputed",
                               "checker-derived"],
            "artifact_required_flags": {},
        },
        "require": {
            "max_nodes": 128,
            "max_depth": 32,
            "require_nonce": False,
            "max_age_seconds": None,
            "decision_margin_min": None,
            "max_enclosure_width": None,
            "forbid_rules": [],
        },
        "allow_fallback": False,
    }
    pol.update(over)
    return pol


def bundle_of(nodes: list[dict], root: str, *, policy: dict | None = None,
              rendering=None, **over) -> dict:
    b = {
        "schema": "jackal-claim-bundle-v1",
        "release_epoch": EPOCH,
        "engine_identity": {"evaluator_sha256": ENV_EPOCH,
                            "source_anb_sha256": SRC_SHA},
        "registries": {"inference_registry_sha256": INF_SHA,
                       "unit_registry_sha256": UNIT_SHA},
        "policy": policy or default_policy(),
        "nodes": nodes,
        "root": root,
        "rendering": rendering,
    }
    b.update(over)
    b["bundle_digest_sha256"] = sha_hex(canon(
        {k: v for k, v in b.items() if k != "bundle_digest_sha256"}))
    return b


def redigest(b: dict) -> dict:
    b["bundle_digest_sha256"] = sha_hex(canon(
        {k: v for k, v in b.items() if k != "bundle_digest_sha256"}))
    return b


# ------------------------------------------------------------- verifier
def run_verify(bundle, *, root_prop=None, epoch=EPOCH, vtime=VTIME,
               nonce=None, env_epoch=None, policy=None,
               with_legacy=False, raw_bytes: bytes | None = None,
               timeout=600) -> tuple[str, str, str]:
    """Returns (verdict, reason, full stdout+stderr)."""
    with tempfile.TemporaryDirectory(prefix="jackal-claim-hostile-") as td:
        bpath = Path(td) / "bundle.json"
        if raw_bytes is not None:
            bpath.write_bytes(raw_bytes)
        else:
            bpath.write_text(json.dumps(bundle, indent=1, sort_keys=True))
        if root_prop is None and bundle is not None:
            by_id = {n.get("id"): n for n in bundle.get("nodes", [])
                     if isinstance(n, dict)}
            rootn = by_id.get(bundle.get("root"))
            root_prop = rootn["proposition"] if rootn else {"t": "bool",
                                                            "v": True}
        rpath = Path(td) / "root_prop.json"
        rpath.write_text(json.dumps(root_prop, sort_keys=True))
        pol = policy if policy is not None else (
            bundle["policy"] if bundle and "policy" in bundle
            else default_policy())
        argv = [sys.executable, "-I", "-S", "-B", str(VERIFIER),
                "--bundle", str(bpath),
                "--expected-release-epoch", epoch,
                "--expected-policy-sha256", sha_hex(canon(pol)),
                "--expected-root-proposition", str(rpath),
                "--expected-inference-registry", str(INF_REG),
                "--expected-inference-registry-sha256", INF_SHA,
                "--expected-unit-registry", str(UNIT_REG),
                "--expected-unit-registry-sha256", UNIT_SHA,
                "--expected-environment-epoch", env_epoch or ENV_EPOCH,
                "--verification-time-unix", str(vtime)]
        if nonce is not None:
            argv += ["--expected-nonce", nonce]
        if with_legacy:
            argv += ["--receipt-verifier", str(RECEIPT_VERIFIER),
                     "--exact-verifier", str(EXACT_VERIFIER),
                     "--checker", str(CHECKER),
                     "--expected-checker", CHECKER_SHA,
                     "--expected-evaluator", ENV_EPOCH,
                     "--inventory", str(INVENTORY),
                     "--expected-inventory", INVENTORY_SHA,
                     "--proof-identity", str(PROOF_ID),
                     "--expected-proof-identity-file", PROOF_ID_SHA,
                     "--expected-proof-identity-digest", PROOF_ID_DIGEST,
                     "--archival-range-checker",
                     str(ARCHIVAL_RANGE_CHECKER),
                     "--expected-archival-range-checker",
                     ARCHIVAL_RANGE_CHECKER_SHA,
                     "--archival-range-proof-identity",
                     str(ARCHIVAL_RANGE_PROOF_ID),
                     "--expected-archival-range-proof-identity-file",
                     ARCHIVAL_RANGE_PROOF_ID_SHA,
                     "--expected-archival-range-proof-identity-digest",
                     ARCHIVAL_RANGE_PROOF_ID_DIGEST,
                     "--archival-range-inventory",
                     str(ARCHIVAL_RANGE_INVENTORY),
                     "--expected-archival-range-inventory",
                     ARCHIVAL_RANGE_INVENTORY_SHA]
            for psha in _trusted_producers():
                argv += ["--trusted-producer", psha]
        p = subprocess.run(argv, capture_output=True, text=True,
                           timeout=timeout, cwd=ROOT)
        out = (p.stdout or "") + (p.stderr or "")
        verdict, reason = "", ""
        for line in out.splitlines():
            if line.startswith("claim-verify="):
                verdict = line.split("=", 2)[1].split()[0]
                if "reason=" in line:
                    reason = line.split("reason=", 1)[1].split()[0]
                break
        return verdict, reason, out


_PRODUCER_CACHE: list[str] = []


def _trusted_producers() -> list[str]:
    if not _PRODUCER_CACHE:
        for name in ("ln_rat_producer.py",):
            p = ROOT / "tools" / name
            if p.exists():
                _PRODUCER_CACHE.append(sha_file(p))
    return _PRODUCER_CACHE


def record(rid: str, ok: bool, expect: str, observed: str) -> None:
    ROWS.append({"id": rid, "ok": bool(ok), "expect": expect,
                 "observed": observed[:200]})
    print(f"{'PASS' if ok else 'FAIL'} {rid}"
          + ("" if ok else f" — expected {expect}, got {observed[:120]}"))


def expect_refused(rid: str, bundle, reason: str, **kw) -> None:
    verdict, got, _out = run_verify(bundle, **kw)
    ok = verdict == "refused" and got == reason
    record(rid, ok, f"refused/{reason}", f"{verdict}/{got}")


def expect_verified(rid: str, bundle, *, contains: list[str] | None = None,
                    **kw) -> None:
    verdict, got, out = run_verify(bundle, **kw)
    ok = verdict == "verified"
    if ok and contains:
        ok = all(s in out for s in contains)
    record(rid, ok, "verified", f"{verdict}/{got}")


# ---------------------------------------------------------- fixtures
def simple_bundle() -> dict:
    n = input_node("x", "1", "2")
    return bundle_of([n], n["id"])


def chain_bundle() -> tuple[dict, dict, dict, dict]:
    a = input_node("x", "1", "2")
    b = input_node("y", "3", "4")
    c = interval_op_node("add", a, b)
    return a, b, c, bundle_of([a, b, c], c["id"])


# ---------------------------------------------------------- families
def family_serialization() -> None:
    b = simple_bundle()
    expect_verified("S-pos-baseline", b)

    raw = json.dumps(b, sort_keys=True)
    dup = raw.replace('"release_epoch": "v1.6.0"',
                      '"release_epoch": "v1.6.0", "release_epoch": "v1.6.0"',
                      1)
    expect_refused("S-duplicate-key", None, "duplicate-key",
                   raw_bytes=dup.encode(), root_prop={"t": "bool", "v": True})

    m = copy.deepcopy(b)
    m["nodes"][0]["freshness"]["max_age_seconds"] = 1.5
    rehash(m["nodes"][0])
    m["root"] = m["nodes"][0]["id"]
    redigest(m)
    expect_refused("S-float-forbidden", m, "float-forbidden",
                   root_prop=m["nodes"][0]["proposition"])

    nan = json.dumps(b, sort_keys=True).replace(
        '"max_age_seconds": null', '"max_age_seconds": NaN', 1)
    expect_refused("S-nan-forbidden", None, "float-forbidden",
                   raw_bytes=nan.encode(), root_prop={"t": "bool", "v": True})

    m = copy.deepcopy(b)
    m["nodes"][0]["surprise"] = "field"
    rehash(m["nodes"][0])
    m["root"] = m["nodes"][0]["id"]
    redigest(m)
    expect_refused("S-unknown-field", m, "unknown-field",
                   root_prop=m["nodes"][0]["proposition"])

    m = copy.deepcopy(b)
    m["nodes"][0]["schema"] = "jackal-claim-node-v2"
    rehash(m["nodes"][0])
    m["root"] = m["nodes"][0]["id"]
    redigest(m)
    expect_refused("S-wrong-node-schema", m, "node-schema",
                   root_prop=m["nodes"][0]["proposition"])

    m = copy.deepcopy(b)
    m["schema"] = "jackal-claim-bundle-v2"
    redigest(m)
    expect_refused("S-wrong-bundle-schema", m, "bundle-schema")

    m = copy.deepcopy(b)
    m["nodes"][0]["proposition"]["set"]["lo"] = 1
    rehash(m["nodes"][0])
    m["root"] = m["nodes"][0]["id"]
    redigest(m)
    expect_refused("S-type-confusion-int-for-token", m, "prop-schema",
                   root_prop=m["nodes"][0]["proposition"])

    for tok, rid in [("01", "S-rep-leading-zero"), ("+1", "S-rep-plus"),
                     ("1/1", "S-rep-unreduced-den1"), ("2/4", "S-rep-unreduced"),
                     ("-0", "S-rep-negzero"), ("1.0", "S-rep-decimal")]:
        m = copy.deepcopy(b)
        m["nodes"][0]["proposition"]["set"]["hi"] = tok
        m["nodes"][0]["env"]["vars"]["x"]["hi"] = tok
        rehash(m["nodes"][0])
        m["root"] = m["nodes"][0]["id"]
        redigest(m)
        expect_refused(rid, m, "rat-not-canonical",
                       root_prop=m["nodes"][0]["proposition"])

    m = copy.deepcopy(b)
    m["nodes"][0]["display"]["text"] = "line\u2028sep"
    rehash(m["nodes"][0])
    m["root"] = m["nodes"][0]["id"]
    redigest(m)
    expect_refused("S-unicode-lineseparator", m, "unicode-forbidden",
                   root_prop=m["nodes"][0]["proposition"])

    m = copy.deepcopy(b)
    m["nodes"][0]["assumptions"] = [unicodedata.normalize("NFD", "café")]
    rehash(m["nodes"][0])
    m["root"] = m["nodes"][0]["id"]
    redigest(m)
    expect_refused("S-unicode-nonnfc", m, "unicode-forbidden",
                   root_prop=m["nodes"][0]["proposition"])

    nodes = [input_node("x", "1", "2")]
    for i in range(140):
        nodes.append(input_node(f"v{i}", "1", "2"))
    over = bundle_of(nodes, nodes[0]["id"])
    expect_refused("S-budget-node-count", over, "bundle-budget",
                   root_prop=nodes[0]["proposition"])

    deep: dict = rat("1")
    for _ in range(80):
        deep = {"t": "neg", "arg": deep}
    m = copy.deepcopy(b)
    m["nodes"][0]["proposition"] = {"t": "eq", "lhs": deep, "rhs": rat("1")}
    m["nodes"][0]["env"]["vars"] = {}
    rehash(m["nodes"][0])
    m["root"] = m["nodes"][0]["id"]
    redigest(m)
    expect_refused("S-budget-prop-depth", m, "prop-budget",
                   root_prop=m["nodes"][0]["proposition"])

    m = copy.deepcopy(b)
    m["nodes"][0]["display"]["text"] = "a" * 5000
    rehash(m["nodes"][0])
    m["root"] = m["nodes"][0]["id"]
    redigest(m)
    expect_refused("S-budget-string", m, "string-budget",
                   root_prop=m["nodes"][0]["proposition"])

    verdict, _r, out = run_verify(b)
    want = sha_hex(canon({k: v for k, v in b.items()
                          if k != "bundle_digest_sha256"}))
    ok = verdict == "verified" and f"bundle.digest={want}" in out
    record("S-canonical-roundtrip", ok, f"bundle.digest={want[:16]}",
           out[:160].replace("\n", " "))


def family_graph() -> None:
    a, bb, c, b = chain_bundle()
    expect_verified("G-pos-chain", b)

    # Self-parent: a node listing its own declared id among parents.
    # (Content addressing makes an honestly-hashed cycle unconstructible;
    # the graph-shape check must still fire on the declared edges.)
    m = copy.deepcopy(b)
    child = m["nodes"][2]
    child["parents"] = [child["id"], m["nodes"][1]["id"]]
    redigest(m)
    expect_refused("G-self-cycle", m, "graph-cycle",
                   root_prop=child["proposition"])

    m = copy.deepcopy(b)
    m["nodes"][2]["parents"] = ["0" * 64, m["nodes"][1]["id"]]
    redigest(m)
    expect_refused("G-missing-parent", m, "parent-missing",
                   root_prop=m["nodes"][2]["proposition"])

    m = copy.deepcopy(b)
    stray = input_node("z", "5", "6")
    m["nodes"].append(stray)
    redigest(m)
    expect_refused("G-orphan-node", m, "orphan-node",
                   root_prop=m["nodes"][2]["proposition"])

    m = copy.deepcopy(b)
    m["nodes"][2]["parents"] = [m["nodes"][0]["id"], m["nodes"][0]["id"]]
    redigest(m)
    expect_refused("G-duplicate-parent", m, "parent-duplicate",
                   root_prop=m["nodes"][2]["proposition"])

    m = copy.deepcopy(b)
    forged = copy.deepcopy(m["nodes"][1])
    forged["proposition"]["set"]["hi"] = "9"
    forged["id"] = m["nodes"][1]["id"]
    m["nodes"][1] = forged
    redigest(m)
    expect_refused("G-node-id-forged", m, "node-id-mismatch",
                   root_prop=m["nodes"][2]["proposition"])

    m = copy.deepcopy(b)
    dup = copy.deepcopy(m["nodes"][0])
    dup["assumptions"] = ["dup-bytes-differ"]
    dup["id"] = m["nodes"][0]["id"]
    m["nodes"].insert(1, dup)
    redigest(m)
    expect_refused("G-duplicate-id-different-bytes", m, "node-duplicate-id",
                   root_prop=m["nodes"][3]["proposition"])

    # Root swapped to a different (single-node) graph while the caller
    # still pins the original root proposition.
    m = copy.deepcopy(b)
    m["nodes"] = [m["nodes"][0]]
    m["root"] = m["nodes"][0]["id"]
    redigest(m)
    expect_refused("G-root-swap-prop-pin", m, "root-proposition-mismatch",
                   root_prop=c["proposition"])

    m = copy.deepcopy(b)
    m["root"] = "f" * 64
    redigest(m)
    expect_refused("G-root-missing", m, "root-missing",
                   root_prop=c["proposition"])

    m = copy.deepcopy(b)
    m["nodes"][2]["parents"] = [m["nodes"][1]["id"], m["nodes"][0]["id"]]
    redigest(m)
    expect_refused("G-parent-swap-stale-id", m, "node-id-mismatch",
                   root_prop=m["nodes"][2]["proposition"])

    m = copy.deepcopy(b)
    m["nodes"][2]["parents"] = [m["nodes"][1]["id"], m["nodes"][0]["id"]]
    rehash(m["nodes"][2])
    m["root"] = m["nodes"][2]["id"]
    redigest(m)
    expect_refused("G-parent-swap-rehash", m, "rule-invalid",
                   root_prop=m["nodes"][2]["proposition"])

    m = copy.deepcopy(b)
    m["nodes"][2]["rule"]["id"] = "interval_sub"
    rehash(m["nodes"][2])
    m["root"] = m["nodes"][2]["id"]
    redigest(m)
    expect_refused("G-rule-swap", m, "rule-invalid",
                   root_prop=m["nodes"][2]["proposition"])

    m = copy.deepcopy(b)
    m["nodes"][2]["rule"] = {"id": "probabilistic_propagate", "params": {}}
    rehash(m["nodes"][2])
    m["root"] = m["nodes"][2]["id"]
    redigest(m)
    expect_refused("G-rule-unknown", m, "rule-unknown",
                   root_prop=m["nodes"][2]["proposition"])

    m = copy.deepcopy(b)
    other_policy = default_policy(policy_id="swapped")
    m["policy"] = other_policy
    redigest(m)
    expect_refused("G-policy-swap", m, "policy-pin-mismatch",
                   policy=default_policy(),
                   root_prop=m["nodes"][2]["proposition"])

    m = copy.deepcopy(b)
    m["registries"]["inference_registry_sha256"] = "a" * 64
    redigest(m)
    expect_refused("G-registry-inference-swap", m,
                   "registry-inference-mismatch",
                   root_prop=m["nodes"][2]["proposition"])

    m = copy.deepcopy(b)
    m["registries"]["unit_registry_sha256"] = "b" * 64
    redigest(m)
    expect_refused("G-registry-unit-swap", m, "registry-unit-mismatch",
                   root_prop=m["nodes"][2]["proposition"])

    m = copy.deepcopy(b)
    m["bundle_digest_sha256"] = "c" * 64
    expect_refused("G-bundle-digest", m, "digest-mismatch",
                   root_prop=m["nodes"][2]["proposition"])

    m = copy.deepcopy(b)
    m["nodes"][2]["proposition"]["set"] = interval("0", "100")
    rehash(m["nodes"][2])
    m["root"] = m["nodes"][2]["id"]
    redigest(m)
    expect_refused("G-coordinated-widen-rehash", m, "rule-invalid",
                   root_prop=m["nodes"][2]["proposition"])


def family_laundering() -> None:
    a = input_node("x", "1", "2", math="estimated")
    bb = input_node("y", "3", "4", math="estimated")
    good = and_node([a, bb])
    expect_verified("L-pos-meet-estimated",
                    bundle_of([a, bb, good], good["id"],
                              policy=default_policy(accept={
                                  "input_provenance": ["supplied"],
                                  "model_validity": ["not-applicable"],
                                  "mathematical": ["estimated"],
                                  "implementation": [
                                      "directly-trusted",
                                      "independently-recomputed"],
                                  "artifact_required_flags": {}})))

    m = and_node([a, bb])
    m["assurance"]["mathematical"] = "exact"
    rehash(m)
    expect_refused("L-estimated-to-exact",
                   bundle_of([a, bb, m], m["id"]), "assurance-launder")

    c1 = input_node("x", "1", "2")
    c2 = input_node("y", "3", "4")
    m = and_node([c1, c2])
    m["assurance"]["mathematical"] = "formal-bounded"
    rehash(m)
    expect_refused("L-checked-to-formal",
                   bundle_of([c1, c2, m], m["id"]), "assurance-launder")

    p = input_node("x", "1", "2")
    mc_ok = derived_node("model_condition", [p], p["proposition"],
                         params={"added_assumptions":
                                 ["model:test-physical-model"]},
                         preserve=True,
                         assumptions_extra=["model:test-physical-model"])
    mc_ok["assurance"]["model_validity"] = "assumed"
    rehash(mc_ok)
    expect_verified("L-pos-model-condition",
                    bundle_of([p, mc_ok], mc_ok["id"],
                              policy=default_policy(accept={
                                  "input_provenance": ["supplied"],
                                  "model_validity": ["assumed"],
                                  "mathematical": ["checked"],
                                  "implementation": ["directly-trusted"],
                                  "artifact_required_flags": {}})))

    m = derived_node("model_condition", [p], p["proposition"],
                     params={"added_assumptions": ["model:extra"]},
                     preserve=True,
                     assumptions_extra=["model:extra"])
    m["assurance"]["model_validity"] = "empirically-validated"
    rehash(m)
    expect_refused("L-model-upgrade",
                   bundle_of([p, m], m["id"]), "model-upgrade")

    p = input_node("x", "1", "2")
    m = derived_node("provenance_passthrough", [p], p["proposition"],
                     preserve=True)
    m["assurance"]["input_provenance"] = "measured"
    rehash(m)
    expect_refused("L-provenance-upgrade",
                   bundle_of([p, m], m["id"]), "provenance-upgrade")

    p = input_node("x", "1", "2")
    m = derived_node("artifact_attestation_attach", [p], p["proposition"],
                     params={"attestations": [
                         {"kind": "sha256", "value": "d" * 64}]},
                     preserve=True)
    m["assurance"]["artifact"] = dict(ARTIFACT_CA)
    m["assurance"]["mathematical"] = "exact"
    rehash(m)
    expect_refused("L-signed-hash-to-math",
                   bundle_of([p, m], m["id"]), "assurance-launder")

    p = input_node("x", "1", "2")
    m = derived_node("provenance_passthrough", [p], p["proposition"],
                     preserve=True)
    m["assurance"]["implementation"] = "source-native-refined"
    rehash(m)
    expect_refused("L-source-native-never",
                   bundle_of([p, m], m["id"]), "implementation-upgrade")

    p1 = input_node("x", "1", "2")
    p2 = input_node("y", "3", "4")
    m = and_node([p1, p2])
    m["assurance"]["implementation"] = "checker-derived"
    rehash(m)
    expect_refused("L-implementation-upgrade",
                   bundle_of([p1, p2, m], m["id"]), "implementation-upgrade")

    p = input_node("x", "1", "2")
    p["residual_non_claims"] = RESIDUALS[:-1]
    rehash(p)
    expect_refused("L-omitted-residual",
                   bundle_of([p], p["id"]), "residual-missing")

    p = input_node("x", "1", "2")
    strict = default_policy(accept={
        "input_provenance": ["supplied"],
        "model_validity": ["not-applicable"],
        "mathematical": ["formal-bounded"],
        "implementation": ["checker-derived"],
        "artifact_required_flags": {}})
    expect_refused("L-fallback-disabled-policy",
                   bundle_of([p], p["id"], policy=strict),
                   "policy-violation")


def family_units() -> None:
    d1 = input_node("d", "10", "12", unit="m")
    d2 = input_node("e", "1", "2", unit="m")
    ok = interval_op_node("add", d1, d2)
    expect_verified("U-pos-compatible-add",
                    bundle_of([d1, d2, ok], ok["id"]))

    t1 = input_node("t", "1", "2", unit="s")
    bad = interval_op_node("add", d1, t1)
    expect_refused("U-incompatible-add",
                   bundle_of([d1, t1, bad], bad["id"]), "unit-dim-mismatch")

    c1 = input_node("c", "20", "25", unit="degC")
    c2 = input_node("f", "2", "3", unit="one")
    bad = interval_op_node("mul", c1, c2)
    expect_refused("U-affine-mul",
                   bundle_of([c1, c2, bad], bad["id"]),
                   "unit-affine-forbidden")

    s1 = input_node("s", "1", "2")
    bad = interval_op_node("add", d1, s1)
    expect_refused("U-dimensionless-confusion",
                   bundle_of([d1, s1, bad], bad["id"]), "unit-dim-mismatch")

    al = input_node("a", "1", "2", unit="celsius")
    expect_refused("U-alias-in-bundle",
                   bundle_of([al], al["id"]), "unit-alias-forbidden")

    uk = input_node("u", "1", "2", unit="furlong")
    expect_refused("U-unknown-unit",
                   bundle_of([uk], uk["id"]), "unit-unknown")

    sw = input_node("x", "1", "2")
    sw["proposition"]["set"] = {"t": "interval", "lo": "2", "hi": "1"}
    sw["env"]["vars"]["x"] = {"t": "interval", "lo": "1", "hi": "2"}
    rehash(sw)
    expect_refused("U-endpoint-swap",
                   bundle_of([sw], sw["id"]), "interval-endpoints")

    n1 = input_node("n", "1", "2")
    dz = input_node("z", "-1", "1")
    bad = interval_op_node("div", n1, dz, forged_set=interval("-2", "2"))
    expect_refused("U-div-zero-crossing",
                   bundle_of([n1, dz, bad], bad["id"]), "interval-div-zero")

    # Two readings of the SAME source (shared source_id, distinct vars).
    # v1 never narrows: claiming cancellation refuses; the outward hull
    # verifies.  (Referencing one node twice refuses parent-duplicate.)
    x1 = input_node("x1", "0", "1", source_id="sensor-a")
    x2 = input_node("x2", "0", "1", source_id="sensor-a")
    forged = interval_op_node("sub", x1, x2, forged_set=interval("0", "0"))
    expect_refused("U-false-independence-narrow",
                   bundle_of([x1, x2, forged], forged["id"]), "rule-invalid")

    honest = interval_op_node("sub", x1, x2)
    expect_verified("U-pos-dependency-outward",
                    bundle_of([x1, x2, honest], honest["id"]))

    p = input_node("x", "1", "2")
    thr = threshold_node(p, "lt", "3/2")
    expect_refused("U-threshold-inside-interval",
                   bundle_of([p, thr], thr["id"]),
                   "threshold-not-established")

    thr_ok = threshold_node(p, "lt", "5/2")
    expect_verified("U-pos-threshold",
                    bundle_of([p, thr_ok], thr_ok["id"]))

    conv = derived_node(
        "unit_convert_linear", [d1],
        in_prop(d1["proposition"]["arg"], "1000", "1200", "cm"),
        params={"target_unit": "cm"})
    expect_verified("U-pos-linear-convert",
                    bundle_of([d1, conv], conv["id"]))

    bad_conv = derived_node(
        "unit_convert_linear", [d1],
        in_prop(d1["proposition"]["arg"], "10", "12", "s"),
        params={"target_unit": "s"})
    expect_refused("U-convert-dim-mismatch",
                   bundle_of([d1, bad_conv], bad_conv["id"]),
                   "unit-dim-mismatch")

    c25 = input_node("c", "25", "25", unit="degC")
    aff_ok = derived_node(
        "unit_convert_affine", [c25],
        in_prop(c25["proposition"]["arg"], "5963/20", "5963/20", "K"),
        params={"target_unit": "K"})
    expect_verified("U-pos-affine-point-convert",
                    bundle_of([c25, aff_ok], aff_ok["id"]))

    cw = input_node("c", "20", "25", unit="degC")
    aff_bad = derived_node(
        "unit_convert_affine", [cw],
        in_prop(cw["proposition"]["arg"], "5863/20", "5963/20", "K"),
        params={"target_unit": "K"})
    expect_refused("U-affine-interval-convert",
                   bundle_of([cw, aff_bad], aff_bad["id"]),
                   "unit-affine-forbidden")


def family_decisions() -> None:
    # Checked-input decisions: floors mandate refusal above 'advisory'.
    p = input_node("x", "1", "2")
    thr = threshold_node(p, "lt", "5/2")

    d_info = decision_node(thr, p, cclass="informational")
    expect_verified("D-pos-informational",
                    bundle_of([p, thr, d_info], d_info["id"]))

    d_adv = decision_node(thr, p, cclass="advisory")
    expect_verified("D-pos-advisory",
                    bundle_of([p, thr, d_adv], d_adv["id"]))

    d_db = decision_node(thr, p, cclass="decision-boundary")
    expect_refused("D-floor-checked-not-bounded",
                   bundle_of([p, thr, d_db], d_db["id"]),
                   "consequence-floor")

    d_bad = decision_node(thr, p, cclass="catastrophic")
    expect_refused("D-unknown-consequence-class",
                   bundle_of([p, thr, d_bad], d_bad["id"]), "rule-params")

    thr_eq = threshold_node(p, "le", "2")
    d_zero = decision_node(thr_eq, p, cclass="advisory",
                           forge_margin="0")
    expect_verified("D-pos-advisory-zero-margin",
                    bundle_of([p, thr_eq, d_zero], d_zero["id"]))

    d_forged = decision_node(thr, p, cclass="advisory",
                             forge_margin="99")
    expect_refused("D-forged-margin",
                   bundle_of([p, thr, d_forged], d_forged["id"]),
                   "rule-invalid")


def family_freshness() -> None:
    b = simple_bundle()
    expect_refused("F-wrong-epoch", b, "epoch-mismatch", epoch="v1.6.1")

    n = input_node("x", "1", "2")
    n["freshness"]["environment_epoch"] = "e" * 64
    rehash(n)
    expect_refused("F-stale-environment",
                   bundle_of([n], n["id"]), "environment-mismatch")

    n = input_node("x", "1", "2")
    n["freshness"]["emitted_at_unix"] = str(VTIME - 1000)
    n["freshness"]["expires_at_unix"] = str(VTIME - 10)
    rehash(n)
    expect_refused("F-expired",
                   bundle_of([n], n["id"]), "freshness-expired")

    n = input_node("x", "1", "2")
    n["freshness"]["max_age_seconds"] = 5
    n["freshness"]["emitted_at_unix"] = str(VTIME - 100)
    rehash(n)
    expect_refused("F-stale-age",
                   bundle_of([n], n["id"]), "freshness-stale")

    n = input_node("x", "1", "2")
    n["freshness"]["max_age_seconds"] = 500
    n["freshness"]["emitted_at_unix"] = str(VTIME - 100)
    rehash(n)
    expect_verified("F-pos-age-ok", bundle_of([n], n["id"]))

    # ---- chronology lower bounds (SIGNOFF proposal): the verifier must
    #      reject verification-before-emission, negative verification time,
    #      and contradictory emitted/expires lifecycles -- not only upper
    #      age/expiry bounds.  RED on pre-fix bytes: the false-accept rows
    #      below VERIFY (F-expires-negative pre-fix refused under the wrong
    #      class) because only one-sided bounds were enforced.
    n = input_node("x", "1", "2")
    n["freshness"]["emitted_at_unix"] = str(VTIME + 100)
    rehash(n)
    expect_refused("F-premature-future-emit",
                   bundle_of([n], n["id"]), "freshness-premature")

    n = input_node("x", "1", "2")
    rehash(n)
    expect_refused("F-negative-vtime",
                   bundle_of([n], n["id"]), "freshness-schema", vtime=-1)

    n = input_node("x", "1", "2")
    n["freshness"]["emitted_at_unix"] = str(VTIME)
    n["freshness"]["expires_at_unix"] = str(VTIME - 100)
    rehash(n)
    expect_refused("F-expires-before-emit",
                   bundle_of([n], n["id"]), "freshness-schema",
                   vtime=VTIME - 100)

    n = input_node("x", "1", "2")
    n["freshness"]["expires_at_unix"] = "-5"
    rehash(n)
    expect_refused("F-expires-negative",
                   bundle_of([n], n["id"]), "freshness-schema")

    n = input_node("x", "1", "2")
    n["freshness"]["emitted_at_unix"] = str(VTIME)
    rehash(n)
    expect_verified("F-emit-eq-vtime-ok", bundle_of([n], n["id"]),
                    vtime=VTIME)

    n = input_node("x", "1", "2")
    n["freshness"]["emitted_at_unix"] = str(VTIME)
    n["freshness"]["expires_at_unix"] = str(VTIME)
    rehash(n)
    expect_verified("F-expiry-eq-emit-eq-vtime-ok",
                    bundle_of([n], n["id"]), vtime=VTIME)

    # A -> B -> A restoration on the chronology gate.
    n = input_node("x", "1", "2")
    n["freshness"]["emitted_at_unix"] = str(VTIME)
    rehash(n)
    expect_verified("F-aba-a1", bundle_of([n], n["id"]), vtime=VTIME)
    n = input_node("x", "1", "2")
    n["freshness"]["emitted_at_unix"] = str(VTIME + 100)
    rehash(n)
    expect_refused("F-aba-b", bundle_of([n], n["id"]),
                   "freshness-premature", vtime=VTIME)
    n = input_node("x", "1", "2")
    n["freshness"]["emitted_at_unix"] = str(VTIME)
    rehash(n)
    expect_verified("F-aba-a2", bundle_of([n], n["id"]), vtime=VTIME)

    n = input_node("x", "1", "2")
    n["freshness"]["nonce"] = "abc123"
    rehash(n)
    expect_verified("F-pos-nonce", bundle_of([n], n["id"]), nonce="abc123")
    expect_refused("F-nonce-mismatch", bundle_of([n], n["id"]),
                   "nonce-mismatch", nonce="zzz999")

    b = simple_bundle()
    expect_refused("F-nonce-missing", b, "nonce-missing", nonce="required1")

    n = input_node("x", "1", "2")
    n["release_epoch"] = "v1.5.0"
    rehash(n)
    expect_refused("F-node-epoch-drift",
                   bundle_of([n], n["id"]), "epoch-mismatch")

    p = input_node("x", "1", "2")
    m = derived_node("artifact_attestation_attach", [p], p["proposition"],
                     params={"attestations": []}, preserve=True)
    m["assurance"]["artifact"] = {"content_addressed": False,
                                  "reproducible_built": False,
                                  "authenticated": False,
                                  "transparency_logged": True}
    rehash(m)
    expect_refused("F-transparency-no-record",
                   bundle_of([p, m], m["id"]), "artifact-upgrade")

    n = input_node("x", "1", "2")
    n["rule"]["params"]["declared_provenance"] = "observed"
    n["assurance"]["input_provenance"] = "observed"
    rehash(n)
    expect_refused("F-issuer-as-observed",
                   bundle_of([n], n["id"]), "provenance-upgrade")


# ---------------------------------------------------------- machine ints
def to_bits(v: int, w: int) -> int:
    return v % (1 << w)


def from_bits(b: int, w: int, signed: bool) -> int:
    if signed and b >= (1 << (w - 1)):
        return b - (1 << w)
    return b


def machine_cert(op: str, width: int, signed: bool, mode: str,
                 operands: list[int], shift: int | None = None,
                 forge: dict | None = None) -> dict:
    w = width
    if op in ("add", "sub", "mul"):
        a, c = operands
        math = {"add": a + c, "sub": a - c, "mul": a * c}[op]
    elif op == "neg":
        math = -operands[0]
    elif op in ("and", "or", "xor"):
        a, c = (to_bits(operands[0], w), to_bits(operands[1], w))
        bits = {"and": a & c, "or": a | c, "xor": a ^ c}[op]
        math = from_bits(bits, w, signed)
    elif op == "not":
        math = from_bits(to_bits(operands[0], w) ^ ((1 << w) - 1), w, signed)
    elif op == "shl":
        math = operands[0] * (1 << (shift or 0))
    elif op == "shr_logical":
        math = from_bits(to_bits(operands[0], w) >> (shift or 0), w, signed)
    elif op == "shr_arith":
        math = operands[0] >> (shift or 0)
    elif op in ("rotl", "rotr"):
        bits = to_bits(operands[0], w)
        s = (shift or 0) % w
        if op == "rotl":
            bits = ((bits << s) | (bits >> (w - s))) & ((1 << w) - 1) \
                if s else bits
        else:
            bits = ((bits >> s) | (bits << (w - s))) & ((1 << w) - 1) \
                if s else bits
        math = from_bits(bits, w, signed)
    elif op == "convert":
        math = operands[0]
    elif op in ("eq", "lt", "le", "gt", "ge"):
        a, c = operands
        math = int({"eq": a == c, "lt": a < c, "le": a <= c,
                    "gt": a > c, "ge": a >= c}[op])
    else:
        raise ValueError(op)
    machine = from_bits(to_bits(math, w), w, signed)
    if op in ("eq", "lt", "le", "gt", "ge"):
        machine = math
    cert = {
        "schema": "jackal-machine-int-cert-v1",
        "width": width,
        "signed": signed,
        "op": op,
        "mode": mode,
        "operands": [str(v) for v in operands],
        "shift": str(shift) if shift is not None else None,
        "math_result": str(math),
        "machine_result": str(machine),
        "overflow": math != machine,
        "semantics": "two-complement-v1",
    }
    if forge:
        cert.update(forge)
    return cert


def mfn(op: str, w: int, signed: bool, mode: str) -> str:
    return f"m.{op}.w{w}.{'s' if signed else 'u'}.{mode}"


def bitvec(w: int, signed: bool, v: int) -> dict:
    return {"t": "bitvec", "width": w, "signed": signed, "v": str(v)}


def machine_node(cert: dict, prop: dict) -> dict:
    raw = canon(cert)
    node = base_node(
        proposition=prop,
        evidence={"kind": "machine-int-cert",
                  "payload_b64": base64.b64encode(raw).decode(),
                  "sha256": sha_hex(raw)},
        rule={"id": "evidence_admit",
              "params": {"evidence_kind": "machine-int-cert"}},
    )
    node["assurance"] = {
        "input_provenance": "supplied",
        "model_validity": "not-applicable",
        "mathematical": "exact",
        "implementation": "independently-recomputed",
        "artifact": dict(ARTIFACT_CA),
    }
    return rehash(node)


def eq_prop(cert: dict) -> dict:
    w, s = cert["width"], cert["signed"]
    if cert["op"] == "convert":
        args: list[dict] = [rat(v) for v in cert["operands"]]
    else:
        args = [bitvec(w, s, int(v)) for v in cert["operands"]]
    if cert["shift"] is not None:
        args.append(rat(cert["shift"]))
    return {"t": "eq",
            "lhs": {"t": "app",
                    "fn": mfn(cert["op"], w, s, cert["mode"]),
                    "args": args},
            "rhs": bitvec(w, s, int(cert["machine_result"]))}


def overflow_prop(cert: dict) -> dict:
    w, s = cert["width"], cert["signed"]
    args = [bitvec(w, s, int(v)) if cert["op"] != "convert"
            else rat(v) for v in cert["operands"]]
    return {"t": "pred",
            "name": f"m.overflow.{cert['op']}.w{w}."
                    f"{'s' if s else 'u'}.checked",
            "args": args}


def family_machine() -> None:
    c = machine_cert("add", 8, False, "wrap", [200, 100])
    n = machine_node(c, eq_prop(c))
    expect_verified("M-pos-wrap-add", bundle_of([n], n["id"]))

    c = machine_cert("neg", 8, True, "checked", [-128])
    n = machine_node(c, overflow_prop(c))
    expect_verified("M-pos-checked-overflow-fact", bundle_of([n], n["id"]))

    c = machine_cert("mul", 16, True, "checked", [300, 50])
    n = machine_node(c, eq_prop(c))
    expect_verified("M-pos-checked-in-range", bundle_of([n], n["id"]))

    c = machine_cert("add", 8, False, "wrap", [300, 1])
    n = machine_node(c, eq_prop({**c, "operands": ["200", "100"],
                                 "machine_result": "44"}))
    expect_refused("M-width-confusion", bundle_of([n], n["id"]),
                   "machine-width")

    c = machine_cert("add", 8, False, "checked", [200, 100],
                     forge={"overflow": False, "machine_result": "300"})
    prop = {"t": "eq",
            "lhs": {"t": "app", "fn": mfn("add", 8, False, "checked"),
                    "args": [bitvec(8, False, 200), bitvec(8, False, 100)]},
            "rhs": bitvec(8, False, 44)}
    n = machine_node(c, prop)
    expect_refused("M-checked-overflow-accepted", bundle_of([n], n["id"]),
                   "machine-cert-invalid")

    c = machine_cert("add", 8, False, "checked", [200, 100])
    n = machine_node(c, eq_prop(c))
    expect_refused("M-checked-claiming-value", bundle_of([n], n["id"]),
                   "machine-overflow-claim")

    c = machine_cert("add", 8, False, "wrap", [200, 100])
    n = machine_node(c, overflow_prop({**c, "mode": "checked"}))
    expect_refused("M-wrap-claiming-overflow-pred",
                   bundle_of([n], n["id"]), "machine-overflow-claim")

    c = machine_cert("shl", 8, False, "wrap", [3], shift=8)
    n = machine_node(c, eq_prop(c))
    expect_refused("M-shift-width-or-more", bundle_of([n], n["id"]),
                   "machine-shift-range")

    c = machine_cert("shl", 8, False, "wrap", [3], shift=2)
    c["shift"] = "-1"
    n = machine_node(c, eq_prop(c))
    expect_refused("M-shift-negative", bundle_of([n], n["id"]),
                   "machine-shift-range")

    c = machine_cert("shr_arith", 8, True, "wrap", [-2], shift=1)
    c["math_result"] = "127"
    c["machine_result"] = "127"
    n = machine_node(c, eq_prop(c))
    expect_refused("M-shr-arith-vs-logical", bundle_of([n], n["id"]),
                   "machine-cert-invalid")

    good = machine_cert("shr_arith", 8, True, "wrap", [-2], shift=1)
    n = machine_node(good, eq_prop(good))
    expect_verified("M-pos-shr-arith", bundle_of([n], n["id"]))

    c = machine_cert("rotl", 8, False, "wrap", [129], shift=1)
    c["math_result"] = "2"
    c["machine_result"] = "2"
    n = machine_node(c, eq_prop(c))
    expect_refused("M-rotate-confusion", bundle_of([n], n["id"]),
                   "machine-cert-invalid")

    c = machine_cert("convert", 8, False, "checked", [256])
    n = machine_node(c, eq_prop(c))
    expect_refused("M-convert-out-of-range", bundle_of([n], n["id"]),
                   "machine-overflow-claim")

    c = machine_cert("convert", 8, False, "checked", [255])
    n = machine_node(c, eq_prop(c))
    expect_verified("M-pos-convert-in-range", bundle_of([n], n["id"]))

    c = machine_cert("add", 8, False, "wrap", [200, 100])
    n = machine_node(c, eq_prop(c))
    tampered = canon({**c, "machine_result": "45"})
    n["evidence"]["payload_b64"] = base64.b64encode(tampered).decode()
    rehash(n)
    expect_refused("M-cert-mutation-hash", bundle_of([n], n["id"]),
                   "evidence-hash-mismatch")


# ---------------------------------------------------------- legacy
def fresh_receipt() -> dict | None:
    producer = ROOT / "tools/ln_rat_producer.py"
    proc = subprocess.run(
        [sys.executable, "-I", "-S", "-B", str(producer), "emit",
         "--expression=ln(x)", "--lower=2", "--upper=3"],
        capture_output=True, cwd=ROOT, timeout=300)
    if proc.returncode != 0:
        return None
    cert = proc.stdout
    hdr = fr._parse_cert_header(cert)
    lo, hi = hdr["output"].split(" ", 1)
    req = {"command": "range-bound-cert", "expression": "ln(x)",
           "input_lo": "2", "input_hi": "3"}
    return fr.build_variant_formal_receipt(
        variant="ln_rat", release_epoch="v1.5.0", request=req,
        enclosure=(lo, hi), cert_bytes=cert,
        producer_sha256=sha_file(producer),
        checker_sha256=ARCHIVAL_RANGE_CHECKER_SHA,
        canonical_lo="2", canonical_hi="3",
        request_commitment_b64=fr.request_commitment_b64(
            req["command"], req["expression"], "2", "3"),
        coverage_inventory_sha256=ARCHIVAL_RANGE_INVENTORY_SHA,
        proof_identity=fr.load_proof_identity_binding(
            ARCHIVAL_RANGE_PROOF_ID),
        plugin_sha256=None)


def receipt_node(receipt: dict, *, prop_override=None) -> dict:
    raw = json.dumps(receipt, indent=2, sort_keys=True).encode()
    req = receipt["request"]
    prop = prop_override or {
        "t": "in",
        "arg": {"t": "app", "fn": "formal.range",
                "args": [{"t": "str", "v": req["expression"]},
                         interval(req["canonical_lo"],
                                  req["canonical_hi"])]},
        "set": interval(receipt["result"]["enclosure_lo"],
                        receipt["result"]["enclosure_hi"]),
    }
    node = base_node(
        proposition=prop,
        evidence={"kind": "formal-receipt",
                  "payload_b64": base64.b64encode(raw).decode(),
                  "sha256": sha_hex(raw)},
        rule={"id": "evidence_admit",
              "params": {
                  "evidence_kind": "formal-receipt",
                  "expected_request": {
                      "command": req["command"],
                      "expression": req["expression"],
                      "input_lo": req["input_lo"],
                      "input_hi": req["input_hi"],
                  },
                  "expected_release_epoch": receipt["release_epoch"],
                  "expected_identities": {
                      "evaluator_sha256":
                          receipt["identities"]["evaluator_sha256"],
                      "checker_sha256":
                          receipt["identities"]["checker_sha256"],
                  },
              }},
        producer={"name": "ln_rat_producer.py",
                  "sha256": receipt["identities"]["evaluator_sha256"]},
        checker={"name": "jackal_cert_check_v170",
                 "sha256": ARCHIVAL_RANGE_CHECKER_SHA},
        assumptions=[f"receipt:{a}" for a in receipt["assumptions"]],
    )
    node["assurance"] = {
        "input_provenance": "supplied",
        "model_validity": "assumed",
        "mathematical": "formal-bounded",
        "implementation": "checker-derived",
        "artifact": dict(ARTIFACT_CA),
    }
    return rehash(node)


def exact_cert_fixture() -> dict | None:
    p = subprocess.run([ENGINE, "mod-pow", "3", "100", "7"],
                       capture_output=True, timeout=300)
    if p.returncode != 0:
        return None
    for line in p.stdout.decode().splitlines():
        if line.startswith("exact-cert="):
            return json.loads(line[len("exact-cert="):])
    return None


def exact_node(cert: dict, *, prop_override=None) -> dict:
    raw = canon(cert)
    claim = cert["claim"]
    prop = prop_override or {
        "t": "in",
        "arg": {"t": "app", "fn": "mod_pow",
                "args": [rat(claim["base"]), rat(claim["exp"]),
                         rat(claim["mod"])]},
        "set": interval(claim["r"], claim["r"]),
    }
    node = base_node(
        proposition=prop,
        evidence={"kind": "exact-cert",
                  "payload_b64": base64.b64encode(raw).decode(),
                  "sha256": sha_hex(raw)},
        rule={"id": "evidence_admit",
              "params": {"evidence_kind": "exact-cert"}},
    )
    node["assurance"] = {
        "input_provenance": "supplied",
        "model_validity": "not-applicable",
        "mathematical": "exact",
        "implementation": "independently-recomputed",
        "artifact": dict(ARTIFACT_CA),
    }
    return rehash(node)


def family_legacy() -> None:
    receipt = fresh_receipt()
    if receipt is None:
        record("LEG-setup", False, "fresh v1.5 receipt", "producer/checker failed")
        return
    n = receipt_node(receipt)
    expect_verified("LEG-pos-receipt", bundle_of([n], n["id"]),
                    with_legacy=True,
                    contains=["mathematical=formal-bounded"])

    rthr = threshold_node(n, "lt", "2")
    d_model = decision_node(rthr, n, cclass="safety-critical")
    expect_refused("D-safety-critical-assumed-model",
                   bundle_of([n, rthr, d_model], d_model["id"]),
                   "consequence-floor", with_legacy=True)

    tampered = copy.deepcopy(receipt)
    tampered["result"]["enclosure_lo"] = "0"
    tn = receipt_node(tampered)
    expect_refused("LEG-receipt-tampered",
                   bundle_of([tn], tn["id"]), "evidence-verify-failed",
                   with_legacy=True)

    wide = copy.deepcopy(receipt)
    n2 = receipt_node(wide, prop_override={
        "t": "in",
        "arg": {"t": "app", "fn": "formal.range",
                "args": [{"t": "str", "v": "ln(x)"},
                         interval("2", "3")]},
        "set": interval("0", "2"),
    })
    expect_refused("LEG-receipt-prop-mismatch",
                   bundle_of([n2], n2["id"]), "evidence-prop-mismatch",
                   with_legacy=True)

    cert = exact_cert_fixture()
    if cert is None:
        record("LEG-exact-setup", False, "exact cert", "engine failed")
        return
    en = exact_node(cert)
    expect_verified("LEG-pos-exact", bundle_of([en], en["id"]),
                    with_legacy=True, contains=["mathematical=exact"])

    forged = copy.deepcopy(cert)
    forged["claim"]["r"] = str((int(cert["claim"]["r"]) + 1) % 7)
    fn2 = exact_node(forged)
    expect_refused("LEG-exact-forged",
                   bundle_of([fn2], fn2["id"]), "evidence-verify-failed",
                   with_legacy=True)

    thr = threshold_node(en, "lt", "7")
    expect_verified("LEG-pos-exact-threshold",
                    bundle_of([en, thr], thr["id"]), with_legacy=True)

    d_db = decision_node(thr, en, cclass="decision-boundary")
    expect_verified("D-pos-exact-decision-boundary",
                    bundle_of([en, thr, d_db], d_db["id"]),
                    with_legacy=True)

    d_sc = decision_node(thr, en, cclass="safety-critical")
    expect_verified("D-pos-exact-safety-critical",
                    bundle_of([en, thr, d_sc], d_sc["id"]),
                    with_legacy=True)


def family_render() -> None:
    n = input_node("x", "1", "2")
    b = bundle_of([n], n["id"],
                  rendering={"token": "forged-token",
                             "permitted_text": "VERIFIED"})
    expect_refused("R-forged-rendering", b, "render-mismatch")

    b = simple_bundle()
    verdict, _r, out = run_verify(b)
    ok = (verdict == "verified" and "rendering.token=" in out
          and "VERIFIED\n" not in out
          and "input provenance supplied" in out.lower())
    record("R-pos-conditions-present", ok,
           "rendering with conditions", out[:160].replace("\n", " "))


def main() -> int:
    family_serialization()
    family_graph()
    family_laundering()
    family_units()
    family_decisions()
    family_freshness()
    family_machine()
    family_legacy()
    family_render()
    failures = [r for r in ROWS if not r["ok"]]
    doc = {
        "schema": "jackal-claim-hostile-matrix-v1",
        "release_epoch": EPOCH,
        "verifier": sha_file(VERIFIER),
        "rows": ROWS,
        "verdict": "PASS" if not failures else "FAIL",
    }
    EVIDENCE_OUT.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
    print(f"evidence={EVIDENCE_OUT}")
    print(f"CLAIM_HOSTILE_{'PASS' if not failures else 'FAIL'} "
          f"rows={len(ROWS)} failures={len(failures)}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
