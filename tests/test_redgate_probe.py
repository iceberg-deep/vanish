"""TEMPORARY probe: a deliberately failing test to verify the CI gate blocks a
red PR. Lives only on the ci-gate-redtest branch and is never merged to main."""


def test_intentional_failure_to_prove_gate_blocks():
    assert False, "intentional failure — proving the ci-success gate blocks merge"
