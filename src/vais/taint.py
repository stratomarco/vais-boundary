from __future__ import annotations

from typing import Any, Iterable

from .models import ConfidentialityLevel, Provenance, TrustLevel, Value


def _max_confidentiality(values: Iterable[Value]) -> ConfidentialityLevel:
    labels = [value.confidentiality for value in values]
    if not labels:
        return ConfidentialityLevel.PUBLIC
    return max(labels, key=lambda item: item.rank)


def derive_value(data: Any, *inputs: Value, source: str = "derived") -> Value:
    """Create a value while conservatively propagating security labels.

    Integrity is trusted only if *every* input is trusted. Any dependency on an
    untrusted value becomes DERIVED_UNTRUSTED. Confidentiality is monotonic: a
    derived value inherits the most restrictive input confidentiality.
    """

    trust = (
        TrustLevel.TRUSTED
        if inputs and all(value.is_trusted for value in inputs)
        else TrustLevel.DERIVED_UNTRUSTED
    )
    confidentiality = _max_confidentiality(inputs)
    parents = tuple(dict.fromkeys(value.provenance.source for value in inputs))
    return Value(
        data,
        Provenance(
            source=source,
            trust=trust,
            confidentiality=confidentiality,
            parents=parents,
        ),
    )


def derive_model_output(data: Any, *visible_inputs: Value) -> Value:
    """Label model output as untrusted and conservatively input-dependent.

    A model can transform, summarize, encode or partially copy anything in its
    prompt. Content-similarity checks therefore cannot prove that an output is
    independent of a sensitive input. Every non-authority-bound model value
    inherits the maximum confidentiality of the values visible to that
    generation. Explicit trusted application transforms remain the only
    declassification mechanism.
    """

    model_origin = Value(
        None,
        Provenance(
            source="model_output",
            trust=TrustLevel.DERIVED_UNTRUSTED,
            confidentiality=ConfidentialityLevel.PUBLIC,
        ),
    )
    return derive_value(data, model_origin, *visible_inputs, source="model_output")


def action_origin(*visible_inputs: Value) -> Provenance:
    """The provenance of an action as a whole: the join of what was visible when it was planned.

    An argument's label says where that value came from. It cannot say that the model
    chose to act at all because of something it read, so an argument without a trust
    requirement can carry hostile intent to a trusted destination (LIM-048). The origin
    answers that question conservatively, from labels alone: an action is trusted only
    if everything visible to its planner was trusted, and it is as confidential as the
    most confidential thing visible. With nothing visible it is untrusted, as with
    ``derive_value``; pass the trusted task among the inputs.
    """
    return derive_value(None, *visible_inputs, source="planning_context").provenance
