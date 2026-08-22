from vais._version import __version__
from vais.adaptive_reference import REFERENCE_BASELINE_VERSION
from vais.reference_agent import attack_workflows, clean_workflows, control_workflows


def test_v09_version_and_reference_suite_shape():
    assert __version__ == "0.12.0rc7"
    assert REFERENCE_BASELINE_VERSION == "0.9.3"
    assert len(clean_workflows()) == 5
    assert len(attack_workflows()) == 20
    assert len(control_workflows()) == 20
