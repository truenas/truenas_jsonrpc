"""Shared pytest configuration for the truenas_pyjsonrpc suite.

Optional-dependency guards (``pytest.importorskip`` / ``skipif``) let the suite
run in a partial environment, but they also mean a runner that is *missing* a
dependency silently reports the affected tests as skipped instead of exercising
them - which is exactly how the filterable (truenas_pyfilter) tests went
untested in the full-stack VM run.

When ``TRUENAS_FORBID_TEST_SKIPS`` is set we turn every skip into a hard
failure, so that a full-stack run (the QEMU job, where every optional dependency
*is* installed) can never quietly drop coverage. It is deliberately gated on a
dedicated variable rather than the generic ``CI``: the lightweight
``build-test.yml`` job runs on a partial stack and is *expected* to skip
``test_pam`` (no loaded PAM module) and similar, so the gate must not fire there.
Without the variable (local dev, partial CI) skips behave normally.

``xfail`` outcomes are left untouched - they are an intended result, not a gap.
"""
import os

import pytest

_FORBID_SKIPS = bool(os.environ.get("TRUENAS_FORBID_TEST_SKIPS"))


def _forbidden_skip_longrepr(longrepr: object) -> str:
    """Render a skipped report's reason as a failure message. A skip's longrepr
    is the ``(path, lineno, "Skipped: <reason>")`` triple; fall back to ``str``."""
    reason = longrepr
    if isinstance(longrepr, tuple) and len(longrepr) == 3:
        reason = longrepr[2]
    return (f"Skipped tests are forbidden in this run (TRUENAS_FORBID_TEST_SKIPS "
            f"is set): {reason}. Install the missing dependency or fix the "
            f"condition instead of skipping.")


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    """Convert a skipped test (``skipif`` marker, ``pytest.skip()``, or a
    function-level ``importorskip``) into a failure. ``xfail`` is preserved."""
    outcome = yield
    report = outcome.get_result()
    if _FORBID_SKIPS and report.skipped and not hasattr(report, "wasxfail"):
        report.outcome = "failed"
        report.longrepr = _forbidden_skip_longrepr(report.longrepr)


@pytest.hookimpl(hookwrapper=True)
def pytest_collectreport(report):
    """Convert a module-level skip (a top-level ``pytest.importorskip`` raised
    during collection) into a collection error."""
    if _FORBID_SKIPS and report.skipped:
        report.outcome = "failed"
        report.longrepr = _forbidden_skip_longrepr(report.longrepr)
    yield
