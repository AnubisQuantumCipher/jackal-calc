# JACKAL Claim Bundle v1 — canonical data model (v1.6.0 evidence-kernel epoch)

Schema registry (final names, all explicitly versioned):

| Schema id | Artifact | Owner |
|---|---|---|
| `jackal-claim-node-v1` | one claim-graph node | `tools/claim_kernel.py` (producer) / `tools/claim_bundle_verify.py` (independent) |
| `jackal-claim-bundle-v1` | bundle envelope: nodes + root + policy + registries + rendering | same |
| `jackal-claim-policy-v1` | deterministic acceptance policy | same |
| `jackal-inference-registry-v1` | `release/claim/inference_registry_v1.json` | pinned by file-bytes SHA-256 |
| `jackal-unit-registry-v1` | `release/claim/unit_registry_v1.json` | pinned by file-bytes SHA-256 |
| `jackal-machine-int-cert-v1` | machine-arithmetic certificate | produced by kernel, independently recomputed by verifier |

The existing v1.5.0 schemas (`jackal-formal-receipt-v1`, `jackal-exact-cert-v1`,
`jackal-eval-cert v2`, `jackal-coverage-inventory-v1`, `jackal-claim-v1`,
proof-identity and seal-audit schemas) are UNCHANGED and remain first-class.
Legacy evidence enters claim graphs only through explicit adapters that
dispatch to the existing independent verifiers (`tools/receipt_verify.py`,
`tools/exact_verify.py`) — never through reimplementation.

## 1. Canonical JSON (claim documents only)

Function: `canonical_bytes(obj)` = UTF-8 of
`json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`.
This matches the existing `formal_receipt.canonical_json_bytes` and is an
RFC 8785 (JCS) subset because claim documents restrict the value space:

- **No JSON floats anywhere.**  Any float (including `1.0`, `1e3`, `NaN`,
  `Infinity`) is refused at parse (`float-forbidden`).  Exact numerics ride
  as canonical rational string tokens.
- **Bounded ints.**  JSON integers are admitted only where a field schema
  names them (dimension exponents, machine widths, counts) and are bounded
  well inside 2^53, where JCS integer serialization is exact.
- **Keys.**  Object keys must match `^[A-Za-z0-9_.:/-]{1,64}$` (ASCII), so
  Python code-point key sorting equals JCS UTF-16 sorting.
- **Strings.**  Must be valid Unicode, NFC-normalized, free of U+2028 /
  U+2029 and of C0/C1 controls; refused otherwise (`unicode-forbidden`).
  Python's `ensure_ascii=False` escaping (only `"`, `\`, and < U+0020)
  equals JCS string serialization on this admitted set.
- **Duplicate keys** refused at parse (`duplicate-key`).
- **Unknown fields** in any current-version object refused (`unknown-field`).

Canonical rational token: `str(Fraction(tok))` — `"n"` or `"n/d"`, `d >= 2`,
`gcd(n,d)=1`, no leading zeros, no `+`, `-0` refused.  Same grammar the
v1.5 exact verifier enforces.

## 2. Proposition IR (typed, bounded)

JSON objects with tag `t`.  Budgets: <= 512 nodes, depth <= 64,
strings <= 4096 bytes, int tokens <= 4096 digits.

Leaves:
- `{"t":"bool","v":true|false}`
- `{"t":"rat","v":"<canonical rat token>"}` — integers and rationals
- `{"t":"str","v":"<expr string>"}` — semantic strings (certified expression
  text bound by legacy evidence); NOT display prose
- `{"t":"interval","lo":"<rat>","hi":"<rat>"}` — requires `lo <= hi`
- Quantities: enclosure/point propositions carry an optional `"unit"`
  field (`{"t":"in","arg":T,"set":I,"unit":"m"}`) — the unit must be a
  canonical registry id (aliases refused in bundles); the dimension
  vector is derived from the registry, never stored redundantly.  The
  term stays value-denoting; add/sub require identical units, mul/div
  admit dimensionless scaling and drop dimensioned products to the
  SI-coherent unitless representation.
- `{"t":"bitvec","width":8|16|32|64,"signed":bool,"v":"<int token in range>"}`
- `{"t":"var","name":"<[a-z][a-z0-9_]{0,15}>"}` — must be declared in `env`

Terms:
- `{"t":"app","fn":"<fn id>","args":[...]}` — `fn` from the bounded
  function registry in `inference_registry_v1.json` (`gcd`, `mod_inv`,
  `mod_pow`, `crt_solve`, `formal.range`, `formal.gaussian_integral`,
  `formal.integral`,
  `m.<op>.w<w>.<s|u>.<wrap|checked>`)
- `{"t":"add"|"sub"|"mul"|"div","lhs":X,"rhs":Y}`, `{"t":"neg","arg":X}`

Propositions:
- `{"t":"eq","lhs":X,"rhs":Y}`
- `{"t":"lt"|"le"|"gt"|"ge","lhs":X,"rhs":Y}`
- `{"t":"in","arg":<term>,"set":{"t":"interval",...}}` — set-enclosure:
  every value the term denotes lies in the interval
- `{"t":"and","args":[P1,...,Pn]}` — explicitly ordered, 2..16 conjuncts
- `{"t":"pred","name":"<pred id>","args":[...]}` — bounded predicate ids:
  `denominator_nonzero`, `threshold_robust`, `prime`, `composite`,
  `exact:<kind>` (opaque poly/ratfunc/roots facts),
  `formal.range_enclosure`, `m.overflow.<op>.w<w>.<s|u>.checked`

Natural language NEVER defines semantics.  `display.text` is untrusted
commentary; it is bundle-bound (hash-covered, mutation-detected) but the
renderer and verifier never read it as semantics.

### Set-enclosure soundness note

`in(term, I)` asserts the value set of `term` is a subset of `I`.  For
`formal.range(expr, domain)` this is exactly the certified receipt claim
(∀x ∈ domain: expr(x) ∈ I).  Interval composition on set-enclosures is
outward-sound: values of `f + g` over any variable coupling lie in the
Minkowski sum, which the exact rational hull contains.

## 3. Node schema `jackal-claim-node-v1`

Top-level keys, exactly (verifier refuses missing or unknown):

`schema, id, proposition, env, assumptions, evidence, producer, checker,
release_epoch, parents, rule, assurance, freshness, residual_non_claims,
decision, display`

- `id` — SHA-256 hex of `canonical_bytes(node-without-id)`.  Recomputed by
  the verifier; mismatch refuses (`node-id-mismatch`).
- `env` — `{"vars": {name: {"t":"interval",...}}}`; every `var` in the
  proposition must be declared; unused declarations refused.
- `assumptions` — ordered list of bounded strings (bundle-bound).
- `evidence` — `{"kind":"none"}` for derived/input nodes, or
  `{"kind":"formal-receipt"|"exact-cert"|"machine-int-cert",
    "payload_b64":"<base64 of exact evidence bytes>",
    "sha256":"<hex of those bytes>"}`.
- `producer` / `checker` — `{"name":..., "sha256":...}` or `null`.
- `parents` — ordered list of node ids; order is semantically bound
  (`and_intro` conjunct order, operand order).  Never silently reordered.
- `rule` — `{"id":"<registry rule id>", "params":{...}}`.
  Parentless nodes must use `input_declare` or `evidence_admit`.
- `assurance` — see §4.
- `freshness` — `{"source_version","emitted_at_unix","max_age_seconds",
  "expires_at_unix","nonce","environment_epoch"}` (nullable fields
  explicit `null`).  `environment_epoch` = pinned evaluator SHA-256.
  Chronology is bounded on BOTH sides against the caller-supplied
  verification time `t`: the verifier refuses `emitted_at_unix < 0` or
  `t < 0` (`freshness-schema`), `expires_at_unix < 0` or
  `expires_at_unix < emitted_at_unix` (`freshness-schema`),
  `t < emitted_at_unix` (`freshness-premature`), `t > expires_at_unix`
  when set (`freshness-expired`), and `t - emitted_at_unix >
  max_age_seconds` when set (`freshness-stale`).  These bind
  SELF-DECLARED timestamps for lifecycle consistency only — see §10.
- `decision` — `null` or `{"decision_id","action","comparison","threshold",
  "margin","consequence_class"}` (only `robust_decision` nodes).
- `display` — `{"text": "<untrusted commentary>"}` (may be empty string).

## 4. Assurance vector (never flattened)

Axis values and their registry order (meet = minimum rank; ties broken by
first-listed):

1. `input_provenance`: `unknown < supplied < integrity-bound < observed <
   authenticated-source < measured`.  v1 producers may emit only
   `unknown`, `supplied`, `integrity-bound` (others require adapters that
   do not exist yet — emitting them refuses).
2. `model_validity`: `unknown < assumed < calibrated <
   empirically-validated`; `not-applicable` is the meet identity.
3. `mathematical`: rank map `refused=0, indeterminate=1, estimated=2,
   model-based=2, checked=3, bounded=4, formal-bounded=5, exact=6`.
   Existing v1.5 classes preserved verbatim.
4. `implementation`: `unknown < directly-trusted < campaign-tested <
   independently-recomputed < checker-derived < source-native-refined`.
   `source-native-refined` is NEVER granted in v1 (research residual).
5. `artifact`: flags object `{content_addressed, reproducible_built,
   authenticated, transparency_logged}` — booleans; child = AND of
   parents unless `artifact_attestation_attach` adds records.
6. Freshness/replay: carried in `freshness`, enforced by verifier against
   caller-supplied verification time / nonce / epochs.
7. Composition validity: the `rule` field + independent verifier re-run.
8. Decision binding: the `decision` field.

### Axis algebra (small, compositional, non-bypassable)

The entire propagation semantics is four lines; anything richer refuses:

1. **Ordered axes** (`input_provenance`, `model_validity`, `mathematical`,
   `implementation`): child value = pointwise MEET (minimum rank) of the
   parents, then lowered by the rule's cap when the rule table names one.
2. **Artifact flags**: child = AND of parents; only
   `artifact_attestation_attach` may raise a flag, and only with a
   matching attestation record.
3. **Residual non-claims**: child = fixed v1 residual set ∪ union of
   parents' residuals (first-seen order).  Residuals never disappear.
4. **Exactness**: a node's DECLARED vector must equal the recomputed
   vector exactly — stronger AND weaker divergence both refuse.  Axes are
   load-bearing, never decoration.

Laundering is refused mechanically with per-axis classes
(`assurance-launder`, `provenance-upgrade`, `model-upgrade`,
`implementation-upgrade`, `artifact-upgrade`).  A signature/hash can only
affect `artifact`.  Exact math over an assumed model keeps
`model_validity=assumed`.  Formal math over supplied input keeps
`input_provenance=supplied` — perfect mathematics over false or stale
inputs stays visibly conditional; the provenance axis is enforced with
the same machinery as the mathematical axis and appears in every
rendering and every consequence floor.

### Consequence classes (closed enum, deterministic floors)

`decision.consequence_class` is one of exactly four structured values —
never free-form natural language.  Each maps to kernel-mandated MINIMUM
axis strengths that the independent verifier enforces on the decision
node itself (refusal class `consequence-floor`).  Policy may tighten
these floors; nothing may loosen them.

| class | mathematical ≥ | implementation ≥ | input_provenance ≥ | model_validity ∈ | margin |
|---|---|---|---|---|---|
| `informational` | estimated | directly-trusted | unknown | any | any |
| `advisory` | checked | directly-trusted | supplied | any | any |
| `decision-boundary` | bounded | independently-recomputed | supplied | not-applicable, assumed, calibrated, empirically-validated | > 0 |
| `safety-critical` | formal-bounded | independently-recomputed | supplied | not-applicable, calibrated, empirically-validated | > 0 |

Implementation floors note: input declarations are not computations, so
declared-input chains legitimately bottom out at `directly-trusted`;
`decision-boundary` and above demand at least one independently
recomputed derivation chain.

`safety-critical` under a merely `assumed` physical model refuses: v1
cannot validate models, so it cannot certify safety over one.  The floor
table is versioned in `inference_registry_v1.json` and cross-checked
against verifier-embedded constants.

## 5. Inference rules (v1, closed set)

See `inference_registry_v1.json` for the machine-readable registry
(arities, param keys, caps).  Semantics (verifier re-evaluates all):

| rule | parents | conclusion check | math class | implementation |
|---|---|---|---|---|
| `input_declare` | 0 | proposition is `in(var, I)`, `eq(var, rat)`, or `in(var-qty, I)` with declared env | as declared, <= `checked` | <= `directly-trusted` |
| `evidence_admit` | 0 | proposition == deterministic derivation from independently verified evidence payload (§6) | from adapter | from adapter |
| `and_intro` | 2..16 | conclusion == `and` of parent propositions in parent order | meet(parents) | min(meet, independently-recomputed) |
| `equality_substitute` | 2 (eq, target) | conclusion == target with every occurrence of `eq.lhs` subtree replaced by `eq.rhs`; typed; unit-compatible | meet | min(meet, independently-recomputed) |
| `interval_add/sub/mul` | 2 | parents `in(t1,I1)`, `in(t2,I2)`; conclusion `in({add|sub|mul}(t1,t2), hull)` with exact rational hull equality | min(meet, bounded) | min(meet, independently-recomputed) |
| `interval_div` | 2 | as above; verifier independently re-proves `0 not in I2` from parent 2's canonical proposition, else `interval-div-zero` | min(meet, bounded) | min(meet, independently-recomputed) |
| `unit_convert_linear` | 1 | qty enclosure/eq rescaled by exact rational factor; same dimension; both units linear | meet | min(meet, independently-recomputed) |
| `unit_convert_affine` | 1 | point qty only (`eq` or degenerate interval); affine map applied exactly; add/sub/mul/div over affine-represented quantities refused | meet | min(meet, independently-recomputed) |
| `threshold_from_enclosure` | 1 | parent `in(t,[lo,hi])`; params `{op, threshold}`; conclusion `{op}(t, threshold)` valid iff `hi < t` (lt), `hi <= t` (le), `lo > t` (gt), `lo >= t` (ge) | meet | min(meet, independently-recomputed) |
| `robust_decision` | 1 | parent is threshold conclusion over enclosure; `decision` binds id/action/threshold/margin; margin = exact distance from the relevant endpoint to threshold; must be > 0 for strict ops, >= 0 for non-strict; policy may require a floor | meet | min(meet, independently-recomputed) |
| `model_condition` | 1 | conclusion == parent proposition; assumptions strictly extended; `model_validity` <= parent (never upgraded) | meet | preserve |
| `provenance_passthrough` | 1 | conclusion == parent proposition; `input_provenance` <= parent | meet | preserve |
| `artifact_attestation_attach` | 1 | conclusion == parent proposition; only `artifact` flags may change, each new `true` requires a declared attestation record in params; mathematical/model/input/implementation axes must be EXACTLY parent's | meet (identical) | preserve |

Anything else — nonlinear composition, probabilistic propagation,
quantifier reasoning, unregistered rules — refuses (`rule-unknown` /
`rule-invalid`).  This is not a theorem prover.

## 6. Evidence adapters (deterministic proposition derivation)

- `formal-receipt` (payload = `jackal-formal-receipt-v1` bytes):
  verifier dispatches payload to `tools/receipt_verify.py` under
  `python3 -I -S -B` with caller-pinned checker binary/identities and the
  request fields carried in `rule.params.expected_request`; on ACCEPT the
  node proposition must equal
  `in(app("formal.range",[str expr, interval domain]), enclosure)` for
  range/variant receipts, or
  `in(app("formal.gaussian_integral",[str expr, interval domain, rat tol]), enclosure)`,
  or `in(app("formal.integral",[str expr, interval domain, rat tol]), enclosure)`.
  Lane boundary (v1.7.2): independent bundle replay selects from a closed
  four-context registry: current v1.7.2 range/rational, archival v1.5.0
  range/rational, Gaussian v1.5.0, and current request-bound composed
  integral v1.7.2. Every tuple supplies its own exact checker and proof
  identity pins. The request-unbound v1.7.0 composed-integral checker is
  revoked and has no admitted context.
  Axes: `mathematical=formal-bounded`, `implementation=checker-derived`,
  `input_provenance=supplied`, `model_validity` = per receipt assumptions
  (`assumed` for the f64/model TCB), artifact `content_addressed=true`.
- `exact-cert` (payload = `jackal-exact-cert-v1` bytes): dispatch to
  `tools/exact_verify.py`; on ACCEPT proposition must equal the per-kind
  derivation: `xgcd -> in(app(gcd,[a,b]),[g,g])` (+ Bezout recorded in
  assumptions? no — Bezout is internal to the cert), `mod-inv ->
  in(app(mod_inv,[a,m]),[inv,inv])`, `mod-pow ->
  in(app(mod_pow,[b,e,m]),[r,r])`, `crt ->
  in(app(crt_solve,[r1,m1,...]),[x,x])`, `prime -> pred(prime,[n])`,
  `composite -> pred(composite,[n])`, poly/ratfunc/roots ->
  `pred("exact:<kind>", [str expr, ...claim fields])`.
  Axes: `mathematical=exact`, `implementation=independently-recomputed`,
  `input_provenance=supplied`, `model_validity=not-applicable`.
- `machine-int-cert` (payload = `jackal-machine-int-cert-v1` bytes):
  verifier recomputes the full two's-complement semantics itself (§7);
  proposition = `eq(app(m.<op>...),bitvec result)` or
  `pred(m.overflow...)`.  Axes: `mathematical=exact`,
  `implementation=independently-recomputed`,
  `input_provenance=supplied`, `model_validity=not-applicable`.

Evidence bytes are bundle-bound (`payload_b64` + `sha256`); the verifier
re-hashes decoded bytes and refuses drift (`evidence-hash-mismatch`).

## 7. Machine-int certificates `jackal-machine-int-cert-v1`

Fields: `schema, width (8|16|32|64 int), signed (bool),
op (add|sub|mul|and|or|xor|not|shl|shr_logical|shr_arith|rotl|rotr|neg|convert|eq|lt|le|gt|ge),
mode (wrap|checked), operands ([1..2 int tokens, in machine range for
width/signedness]), shift (int token 0..width-1; only shift/rotate ops),
math_result (unbounded int token), machine_result (in-range token),
overflow (bool), semantics ("two-complement-v1")`.

Semantics: `math_result` is the exact integer result over Z (shifts:
floor/logical per op; bitwise ops: on two's-complement bit patterns,
reinterpreted per signedness).  `machine_result` = `math_result` reduced
into the machine range by two's-complement wrap.  `overflow` =
(`math_result != machine_result` as integers).  In `checked` mode an
`overflow=true` certificate is admissible only as the explicit overflow
FACT (`pred(m.overflow...)`); claiming a value result under checked
overflow refuses.  In `wrap` mode the proposition binds the wrapped value
and the flag remains informational.  Shift/rotate by amounts outside
`0..width-1` and `convert` out of range refuse.  Comparisons emit
`machine_result` in {0,1}, `overflow=false`.

The Anubis engine's exact `band/bor/bxor/shl/shr` commands are used by the
seal battery as independent drift alarms; soundness rests on the verifier's
own recomputation (same architecture as the exact CAS lane).

## 8. Bundle schema `jackal-claim-bundle-v1`

Top-level keys exactly: `schema, release_epoch, engine_identity
({evaluator_sha256, source_anb_sha256}), registries
({inference_registry_sha256, unit_registry_sha256}), policy, nodes, root,
rendering ({token, permitted_text}), bundle_digest_sha256`.

- `nodes` — topologically ordered (parents before children), each with
  `id`; verifier revalidates order, uniqueness, closure, acyclicity,
  budgets (<=128 nodes, depth <=32, <=16 parents).
- `root` — id of the root claim node; must be reachable-closure equal to
  the node set (no orphans).
- `bundle_digest_sha256` — SHA-256 of `canonical_bytes(bundle-without-digest)`.
- `rendering` — recomputed by the verifier from the verified root +
  policy verdict; any divergence refuses (`render-mismatch`).

## 9. Policy schema `jackal-claim-policy-v1`

Keys exactly: `schema, policy_id, accept ({input_provenance[],
model_validity[], mathematical[], implementation[],
artifact_required_flags{}}), require ({max_nodes, max_depth,
require_nonce, max_age_seconds, decision_margin_min,
max_enclosure_width, forbid_rules[]}), allow_fallback (bool)`.

Deterministic evaluation against the ROOT node's axis vector, graph
statistics, and decision binding.  No silent fallback: if the router
cannot satisfy `accept.mathematical` with `allow_fallback=false`, it
refuses (`policy-fallback-forbidden`); it never downgrades silently.

## 10. Independent verifier contract

`tools/claim_bundle_verify.py` (dependency-free, `python3 -I -S -B`):

Required caller pins: `--bundle`, `--expected-release-epoch`,
`--expected-policy-sha256` (or `--expected-policy` file),
`--expected-root-proposition` (file or inline JSON),
`--expected-inference-registry` (path) with `--expected-inference-registry-sha256`,
`--expected-unit-registry` + `--expected-unit-registry-sha256`,
`--expected-environment-epoch`, `--verification-time-unix`.
Optional (unbind the legacy dispatcher when a bundle carries no
formal-receipt or exact-cert evidence): `--expected-nonce`,
`--receipt-verifier`, `--exact-verifier`, `--max-bundle-bytes`.

When a bundle embeds a `formal-receipt` node, the verifier owns a closed
four-context registry — every context pins its own checker, proof
identity, and (for the archival lane) inventory bytes, and the CLI
refuses to invent tuples the code does not admit:

| Context | CLI arguments |
|---|---|
| current range/rational v1.7.2 | `--checker`, `--expected-checker`, `--expected-evaluator`, `--inventory`, `--expected-inventory`, `--proof-identity`, `--expected-proof-identity-file`, `--expected-proof-identity-digest` |
| Gaussian v1.5.0 | `--gaussian-checker`, `--expected-gaussian-checker`, `--gaussian-proof-identity`, `--expected-gaussian-proof-identity-file`, `--expected-gaussian-proof-identity-digest` (evaluator and coverage inventory arguments are reused from the current tuple) |
| current request-bound int-cert v1.7.2 | `--int-cert-checker`, `--expected-int-cert-checker`, `--int-cert-proof-identity`, `--expected-int-cert-proof-identity-file`, `--expected-int-cert-proof-identity-digest` (evaluator and coverage inventory arguments are reused from the current tuple) |
| archival range/rational v1.5.0 | `--archival-range-checker`, `--expected-archival-range-checker`, `--archival-range-proof-identity`, `--expected-archival-range-proof-identity-file`, `--expected-archival-range-proof-identity-digest`, `--archival-range-inventory`, `--expected-archival-range-inventory` |

There is no admitted context for the revoked request-unbound v1.7.0
composed-integral checker.  Cross-mixing any of these tuples — for
example, pairing the current inventory with the archival checker, or
the archival proof identity with the current v1.7.2 range checker —
refuses with a stable reason class (`receipt-context-unsupported` for
pre-dispatch selector failures; `evidence-verify-failed`,
`digest-mismatch`, or `evidence-producer-untrusted` for the downstream
identity checks).  `--trusted-producer` may be repeated to admit
additional evaluator digests beyond the default `--expected-evaluator`.

Verdicts: `claim-verify=verified|refused|indeterminate` with
`reason=<stable class>`; never a bare badge — the success output
enumerates the axis vector, assumptions, residual non-claims, freshness
result, and the recomputed rendering token + permitted text.
`indeterminate` is reserved for infrastructure absence (e.g. legacy
verifier binary unavailable), never for semantic failure.

Replay honesty: the verifier proves nonce/epoch binding and caller-time
freshness only.  Freshness bounds emission, verification, and expiry
against the caller-supplied time (see §3), but those timestamps are
SELF-DECLARED by the producer: the verifier enforces internal lifecycle
consistency, NOT timestamp authenticity or temporal provenance (there is
no trusted time source).  One-time replay PREVENTION requires a durable
external nonce store and is an explicit residual non-claim in v1.

## 11. Renderer

`render(root_node, policy_verdict) -> {token, permitted_text}`.
Deterministic templates keyed by the mathematical class + conditions;
always includes: epistemic wording, checker/implementation status, input
provenance, model conditions, residual non-claims, decision margin when
present, freshness qualifiers, and explicit forbidden-upgrade notes.
Never emits bare `VERIFIED`.

## 12. Residual non-claims (v1, verbatim in bundles)

- no source-to-native refinement (`source-native-refined` never granted);
- claim-bundle `formal-receipt` replay is limited to the four explicitly
  pinned contexts above; arbitrary epochs, caller-selected checkers, and the
  revoked request-unbound v1.7.0 composed-integral context refuse;
- no one-time replay prevention without an external nonce store;
- no probability distributions, confidence levels, independence, or
  calibration inferred from intervals;
- no real-world truth of supplied inputs;
- no universal soundness; bounded fragments only;
- transparency metadata is provenance, never mathematical evidence.
