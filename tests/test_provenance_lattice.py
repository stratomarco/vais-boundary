"""P1-3: prove the provenance implementation matches its stated lattice.

`taint.py` already states the intended design in its docstrings: integrity is
trusted only if every input is trusted, any dependency on an untrusted value
becomes DERIVED_UNTRUSTED, and confidentiality is monotonic, so a derived value
inherits the most restrictive input confidentiality. This module does not
redesign that. It asserts the implementation agrees with the statement under
adversarial composition, which is where the gap between a correct stated design
and a correct implementation usually lives.

Two deliberate choices.

The expected labels are computed by `_expected_*` below, written from the
docstring rather than from `taint.py`. A test that recomputes the labels the way
the implementation does would pass no matter what the implementation said.

The generator is seeded rather than property-based. This project keeps frozen
inputs and recorded seeds everywhere else, and a failing case from a fixed seed
reproduces exactly, which matters more here than shrinking. No new dependency is
introduced for the sake of one module.
"""

from __future__ import annotations

import json
import random

import pytest

from vais import (
    ConfidentialityLevel as C,
    Provenance,
    TrustLevel,
    TrustedValue,
    Value,
    derive_model_output,
    derive_value,
)
from vais.mcp import label_mcp_input

LEVELS = [C.PUBLIC, C.INTERNAL, C.CONFIDENTIAL, C.SECRET]
SEEDS = [1, 2, 3, 5, 8, 13, 21, 34]
DAG_NODES = 40
MIN_SPINE_DEPTH = 12


# --- the lattice, written from the docstring rather than from taint.py --------

def _expected_trust(inputs: list[Value]) -> TrustLevel:
    """Trusted only if there is at least one input and every input is trusted."""
    if inputs and all(v.provenance.trust is TrustLevel.TRUSTED for v in inputs):
        return TrustLevel.TRUSTED
    return TrustLevel.DERIVED_UNTRUSTED


def _expected_confidentiality(inputs: list[Value]) -> C:
    """The join, meaning the most restrictive input label, or PUBLIC if none."""
    if not inputs:
        return C.PUBLIC
    return max((v.confidentiality for v in inputs), key=lambda level: level.rank)


# --- generator ----------------------------------------------------------------

def _root(rng: random.Random, index: int) -> Value:
    trust = rng.choice([TrustLevel.TRUSTED, TrustLevel.UNTRUSTED])
    level = rng.choice(LEVELS)
    if trust is TrustLevel.TRUSTED:
        return TrustedValue(f"root-{index}", source=f"source-{index}", confidentiality=level)
    return Value(
        f"root-{index}",
        Provenance(source=f"source-{index}", trust=TrustLevel.UNTRUSTED, confidentiality=level),
    )


def _build_dag(seed: int):
    """Return (nodes, edges) where edges[i] lists the input indices of node i.

    A spine of at least MIN_SPINE_DEPTH chained derivations is forced, so depth
    is never left to chance, and the remaining nodes fan in from anywhere
    earlier to produce genuine mixing.
    """
    rng = random.Random(seed)
    nodes: list[Value] = []
    edges: list[list[int]] = []

    for i in range(4):
        nodes.append(_root(rng, i))
        edges.append([])

    while len(nodes) < DAG_NODES:
        i = len(nodes)
        if i <= MIN_SPINE_DEPTH + 4:
            parents = [i - 1]  # the forced spine
            if rng.random() < 0.4:
                parents.append(rng.randrange(0, i))
        else:
            parents = rng.sample(range(i), k=rng.randint(1, min(3, i)))
        inputs = [nodes[p] for p in parents]
        if rng.random() < 0.25:
            nodes.append(derive_model_output(f"node-{i}", *inputs))
        else:
            nodes.append(derive_value(f"node-{i}", *inputs, source=f"derived-{i}"))
        edges.append(parents)

    return nodes, edges


def _depth(edges: list[list[int]]) -> int:
    depths = [0] * len(edges)
    for i, parents in enumerate(edges):
        depths[i] = 1 + max((depths[p] for p in parents), default=-1)
    return max(depths)


# --- the properties -----------------------------------------------------------

@pytest.mark.parametrize("seed", SEEDS)
def test_generated_dag_reaches_the_required_depth(seed):
    _, edges = _build_dag(seed)
    assert _depth(edges) >= MIN_SPINE_DEPTH


@pytest.mark.parametrize("seed", SEEDS)
def test_integrity_matches_the_stated_rule_at_every_node(seed):
    nodes, edges = _build_dag(seed)
    for i, parents in enumerate(edges):
        if not parents:
            continue
        inputs = [nodes[p] for p in parents]
        if nodes[i].provenance.source == "model_output":
            continue  # covered separately; model output is never trusted
        assert nodes[i].provenance.trust is _expected_trust(inputs), f"node {i}, seed {seed}"


@pytest.mark.parametrize("seed", SEEDS)
def test_confidentiality_is_the_join_at_every_node(seed):
    nodes, edges = _build_dag(seed)
    for i, parents in enumerate(edges):
        if not parents:
            continue
        inputs = [nodes[p] for p in parents]
        assert nodes[i].confidentiality is _expected_confidentiality(inputs), f"node {i}, seed {seed}"


@pytest.mark.parametrize("seed", SEEDS)
def test_trust_never_recovers_along_any_path(seed):
    """Once a node is not trusted, nothing downstream of it is trusted."""
    nodes, edges = _build_dag(seed)
    tainted = set()
    for i, parents in enumerate(edges):
        if nodes[i].provenance.trust is not TrustLevel.TRUSTED:
            tainted.add(i)
        elif any(p in tainted for p in parents):
            raise AssertionError(f"node {i} is trusted but descends from tainted input, seed {seed}")


@pytest.mark.parametrize("seed", SEEDS)
def test_confidentiality_never_decreases_along_any_edge(seed):
    nodes, edges = _build_dag(seed)
    for i, parents in enumerate(edges):
        for p in parents:
            assert nodes[i].confidentiality.rank >= nodes[p].confidentiality.rank, (
                f"edge {p}->{i} lowered confidentiality, seed {seed}"
            )


def test_one_untrusted_input_taints_regardless_of_arity_or_position():
    trusted = [TrustedValue(f"t{i}", source=f"t{i}") for i in range(6)]
    dirty = Value("x", Provenance(source="doc", trust=TrustLevel.UNTRUSTED))
    for position in range(len(trusted) + 1):
        inputs = trusted[:position] + [dirty] + trusted[position:]
        result = derive_value("out", *inputs)
        assert result.provenance.trust is TrustLevel.DERIVED_UNTRUSTED
    assert derive_value("out", *trusted).provenance.trust is TrustLevel.TRUSTED


def test_label_is_independent_of_input_order():
    values = [
        TrustedValue("a", source="a", confidentiality=C.INTERNAL),
        Value("b", Provenance(source="b", trust=TrustLevel.UNTRUSTED, confidentiality=C.SECRET)),
        TrustedValue("c", source="c", confidentiality=C.PUBLIC),
    ]
    rng = random.Random(99)
    reference = derive_value("out", *values)
    for _ in range(20):
        shuffled = values[:]
        rng.shuffle(shuffled)
        candidate = derive_value("out", *shuffled)
        assert candidate.provenance.trust is reference.provenance.trust
        assert candidate.confidentiality is reference.confidentiality


def test_derivation_with_no_inputs_fails_closed():
    orphan = derive_value("out")
    assert orphan.provenance.trust is TrustLevel.DERIVED_UNTRUSTED
    assert orphan.confidentiality is C.PUBLIC


def test_model_output_is_never_trusted_even_from_wholly_trusted_inputs():
    trusted = [TrustedValue(f"t{i}", source=f"t{i}") for i in range(4)]
    assert derive_model_output("summary", *trusted).provenance.trust is TrustLevel.DERIVED_UNTRUSTED
    assert derive_model_output("summary").provenance.trust is TrustLevel.DERIVED_UNTRUSTED


def test_model_output_inherits_the_highest_visible_confidentiality():
    visible = [
        TrustedValue("public", source="p", confidentiality=C.PUBLIC),
        TrustedValue("secret", source="s", confidentiality=C.SECRET),
        TrustedValue("internal", source="i", confidentiality=C.INTERNAL),
    ]
    assert derive_model_output("summary", *visible).confidentiality is C.SECRET


@pytest.mark.parametrize("level", LEVELS)
def test_a_secret_cannot_be_summarised_down_to_public(level):
    secret = Value(
        "payload",
        Provenance(source="vault", trust=TrustLevel.UNTRUSTED, confidentiality=C.SECRET),
    )
    other = TrustedValue("context", source="ctx", confidentiality=level)
    assert derive_model_output("summary", secret, other).confidentiality is C.SECRET
    assert derive_value("transform", secret, other).confidentiality is C.SECRET


# --- the boundary of what the lattice can enforce -----------------------------

def test_labels_do_not_survive_serialisation_round_trip():
    """The classic laundering path, asserted so the obligation stays visible.

    Labels live on the Value, not on the data. Anything that leaves the process
    and returns, through a file, a database or a tool result, arrives unlabelled.
    Re-labelling on the way back in is an application obligation, and nothing in
    the library can perform it on the application's behalf.
    """
    secret = Value(
        {"ssn": "000-00-0000"},
        Provenance(source="hr", trust=TrustLevel.UNTRUSTED, confidentiality=C.SECRET),
    )
    round_tripped = json.loads(json.dumps(dict(secret.data)))
    assert round_tripped == {"ssn": "000-00-0000"}
    assert not hasattr(round_tripped, "provenance")

    # Re-entering through the MCP boundary is labelled untrusted and public by
    # default, so a secret that round-trips is downgraded unless the caller says
    # otherwise. The default is safe for integrity and lossy for confidentiality.
    relabelled = label_mcp_input(
        round_tripped, server_id="srv", primitive="tool", name="read_record"
    )
    assert relabelled.provenance.trust is TrustLevel.UNTRUSTED
    assert relabelled.confidentiality is C.PUBLIC

    preserved = label_mcp_input(
        round_tripped,
        server_id="srv",
        primitive="tool",
        name="read_record",
        confidentiality=C.SECRET,
    )
    assert preserved.confidentiality is C.SECRET


def test_direct_construction_bypasses_the_lattice_entirely():
    """Provenance is propagated, not enforced.

    Any call site may mint a TRUSTED value from nothing. That is by design, since
    declassification is an application concern, but it means every site that
    constructs a Value directly is inside the trusted computing base. The lattice
    holds through derivation only.
    """
    laundered = Value(
        "anything at all",
        Provenance(source="application", trust=TrustLevel.TRUSTED, confidentiality=C.PUBLIC),
    )
    assert laundered.is_trusted
    downstream = derive_value("out", laundered)
    assert downstream.provenance.trust is TrustLevel.TRUSTED


def test_integrity_and_confidentiality_defaults_are_asymmetric():
    """FIND-044: the two halves of the lattice do not fail in the same direction.

    Integrity defaults to the cautious end. Data crossing the MCP boundary is
    UNTRUSTED unless something trusted vouches for it, and a derivation with no
    inputs is DERIVED_UNTRUSTED.

    Confidentiality defaults to PUBLIC, which is the *bottom* of the lattice and
    therefore an assertion the library is in no position to make about remote
    data. PUBLIC is the identity element for the join, so the default is chosen
    so that unlabelled inputs do not raise the ceiling of everything they touch.
    That is a reasonable trade and it is not a conservative one.

    The consequence is recorded in LIM-036 and shown in the test below: a missing
    label fails closed at the invariant, and a wrongly PUBLIC one does not.
    """
    remote = label_mcp_input(
        {"salary": 120000}, server_id="hr", primitive="tool", name="read_employee"
    )
    assert remote.provenance.trust is TrustLevel.UNTRUSTED  # cautious
    assert remote.confidentiality is C.PUBLIC  # not cautious

    assert derive_value("out").provenance.trust is TrustLevel.DERIVED_UNTRUSTED  # cautious
    assert derive_value("out").confidentiality is C.PUBLIC  # not cautious


def test_a_wrong_public_label_is_not_caught_but_a_missing_one_is():
    """LIM-036, asserted so the boundary of the confidentiality guarantee is visible.

    The ceiling invariant fails closed when provenance is absent. It cannot fail
    closed when provenance is present and wrong, because a label is all it has.
    Confidentiality enforcement is therefore only as good as the application's
    labelling at the point data enters the system. Integrity does not share this
    property: nothing the application omits can make untrusted data trusted.
    """
    from pathlib import Path

    from vais import Effect, TaskContract, load_invariants

    engine = load_invariants(Path(__file__).resolve().parents[1] / "invariants" / "default.yaml")
    ceiling = next(i for i in engine.invariants if i.type == "confidentiality_ceiling")
    contract = TaskContract(allowed_tools={"send_email"})

    def reasons(effect):
        return [v.reason for v in engine.evaluate([effect], contract) if v.invariant_id == ceiling.id]

    secret_but_labelled_public = Effect(
        ceiling.effect,
        {ceiling.field: "payload"},
        provenance={ceiling.field: Provenance("mcp", TrustLevel.UNTRUSTED, confidentiality=C.PUBLIC)},
    )
    unlabelled = Effect(ceiling.effect, {ceiling.field: "payload"})
    labelled_truthfully = Effect(
        ceiling.effect,
        {ceiling.field: "payload"},
        provenance={ceiling.field: Provenance("mcp", TrustLevel.UNTRUSTED, confidentiality=C.SECRET)},
    )

    assert reasons(secret_but_labelled_public) == []
    assert reasons(unlabelled) == [f"missing_effect_provenance:{ceiling.field}"]
    assert reasons(labelled_truthfully) == [
        f"confidentiality_exceeds_limit:{ceiling.field}:secret>public"
    ]


def test_parent_lineage_is_recorded_by_source_name_and_is_lossy():
    """Two distinct inputs sharing a source name collapse to one parent entry.

    Labels stay correct because they are computed from the values. Lineage does
    not: an auditor reconstructing ancestry from `parents` cannot tell how many
    values contributed, only which source names did.
    """
    a = Value("a", Provenance(source="shared", trust=TrustLevel.UNTRUSTED))
    b = Value("b", Provenance(source="shared", trust=TrustLevel.UNTRUSTED, confidentiality=C.SECRET))
    derived = derive_value("out", a, b)
    assert derived.provenance.parents == ("shared",)
    assert derived.confidentiality is C.SECRET
