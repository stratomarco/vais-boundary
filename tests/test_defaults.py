from vais import load_default_invariants, load_default_policy


def test_packaged_default_policy_loads():
    policy = load_default_policy()
    assert policy.version == 4
    assert policy.tools["send_email"].required_scope == "email:send"


def test_packaged_default_invariants_load():
    engine = load_default_invariants()
    assert {item.id for item in engine.invariants} >= {
        "email_destination_integrity",
        "no_secret_email_egress",
    }


def test_packaged_example_mcp_profile_loads():
    from vais import load_example_mcp_profile

    profile = load_example_mcp_profile()
    assert profile.by_endpoint("ops", "send_email").canonical_tool == "send_email"
