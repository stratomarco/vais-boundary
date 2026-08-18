from vais import (
    ConfidentialityLevel,
    Provenance,
    TrustLevel,
    TrustedValue,
    Value,
    derive_model_output,
    derive_value,
)


def test_derived_from_only_trusted_inputs_stays_trusted():
    result = derive_value("AB", TrustedValue("A"), TrustedValue("B"), source="join")
    assert result.is_trusted
    assert result.provenance.parents == ("trusted",)


def test_any_untrusted_dependency_taints_derived_value():
    untrusted = Value("document", Provenance("web", TrustLevel.UNTRUSTED))
    result = derive_value("summary", TrustedValue("instruction"), untrusted, source="summarizer")
    assert result.provenance.trust == TrustLevel.DERIVED_UNTRUSTED
    assert result.provenance.parents == ("trusted", "web")


def test_confidentiality_propagates_monotonically():
    secret = TrustedValue(
        "token",
        source="vault",
        confidentiality=ConfidentialityLevel.SECRET,
    )
    public = TrustedValue("prefix")
    result = derive_value("prefix token", public, secret)
    assert result.confidentiality == ConfidentialityLevel.SECRET


def test_model_output_is_untrusted_and_inherits_all_visible_confidentiality():
    secret = TrustedValue(
        "complete secret-bearing source",
        source="vault",
        confidentiality=ConfidentialityLevel.SECRET,
    )

    result = derive_model_output("partial or transformed output", secret)

    assert result.provenance.trust == TrustLevel.DERIVED_UNTRUSTED
    assert result.confidentiality == ConfidentialityLevel.SECRET
    assert result.provenance.parents == ("model_output", "vault")
