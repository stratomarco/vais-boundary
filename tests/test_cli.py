from pathlib import Path

from vais.cli import main

ROOT = Path(__file__).resolve().parents[1]


def test_validate_policy_command(capsys):
    assert main(["validate-policy", str(ROOT / "policies" / "default.yaml")]) == 0
    assert "valid policy" in capsys.readouterr().out


def test_validate_invariants_command(capsys):
    assert main(["validate-invariants", str(ROOT / "invariants" / "default.yaml")]) == 0
    assert "valid invariants" in capsys.readouterr().out


def test_validate_mcp_profile_cli(capsys):
    from pathlib import Path
    from vais.cli import main

    path = Path(__file__).parents[1] / "mcp" / "example-profile.yaml"
    assert main(["validate-mcp-profile", str(path)]) == 0
    assert "valid MCP profile" in capsys.readouterr().out


def test_mcp_demo_cli(capsys):
    from vais.cli import main

    assert main(["mcp-demo"]) == 0
    output = capsys.readouterr().out
    assert "Not AI-powered" in output
    assert "UNPROTECTED" in output
    assert "VAIS PROTECTED" in output
    assert "invariant violations: 1" in output
    assert "decision: deny" in output


def test_version_flags(capsys):
    from pytest import raises

    with raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "vais 0.12.0rc8" in capsys.readouterr().out


def test_version_subcommand_remains_compatible(capsys):
    assert main(["version"]) == 0
    assert capsys.readouterr().out.strip() == "0.12.0rc8"
