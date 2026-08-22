from vais.reasoning import reasoning_mode_mismatch, reasoning_mode_status


def test_explicit_reasoning_modes_are_checked_bidirectionally():
    assert reasoning_mode_mismatch("off", observed=True) is True
    assert reasoning_mode_mismatch("off", observed=False) is False
    assert reasoning_mode_mismatch("on", observed=False) is True
    assert reasoning_mode_mismatch("on", observed=True) is False


def test_auto_and_undeclared_modes_are_not_enforced():
    assert reasoning_mode_mismatch("auto", observed=True) is False
    assert reasoning_mode_mismatch(None, observed=False) is False
    assert reasoning_mode_status("auto", observed=True) == "not-enforced"
    assert reasoning_mode_mismatch([], observed=True) is False
    assert reasoning_mode_status({}, observed=False) == "not-enforced"
