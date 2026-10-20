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

    assert main(["lab", "mcp-demo"]) == 0
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
    assert "vais 0.12.0rc15" in capsys.readouterr().out


def test_version_subcommand_remains_compatible(capsys):
    assert main(["version"]) == 0
    assert capsys.readouterr().out.strip() == "0.12.0rc15"


def test_the_top_level_is_the_boundary_and_lab_holds_the_tooling(capsys):
    """Step 2 of the 1.0 track: the command line mirrors the public interface."""
    import argparse
    from vais.cli import CORE_COMMANDS, _lab_commands, _parser

    top = next(a for a in _parser()._actions if isinstance(a, argparse._SubParsersAction))
    assert set(top.choices) == CORE_COMMANDS | {"lab"}
    assert _lab_commands() and not (_lab_commands() & CORE_COMMANDS)


def test_the_old_tooling_form_still_runs_but_warns(capsys):
    assert main(["mcp-demo"]) == 0
    captured = capsys.readouterr()
    assert "VAIS PROTECTED" in captured.out
    assert "`vais lab mcp-demo`" in captured.err and "removed in 1.0" in captured.err


def test_boundary_commands_do_not_warn(capsys):
    assert main(["validate-policy", str(ROOT / "policies" / "default.yaml")]) == 0
    assert capsys.readouterr().err == ""
