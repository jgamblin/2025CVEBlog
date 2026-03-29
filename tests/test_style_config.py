"""Tests for style_config module."""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))


def test_colors_dict_has_required_keys():
    """Verify the COLORS dict contains all expected palette keys."""
    from style_config import COLORS

    required_keys = [
        "primary",
        "secondary",
        "accent",
        "alert",
        "neutral",
        "light",
        "text",
        "grid",
    ]
    for key in required_keys:
        assert key in COLORS, f"Missing color key: {key}"


def test_severity_colors_has_all_levels():
    """Severity palette should cover CRITICAL through NONE."""
    from style_config import SEVERITY_COLORS

    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]:
        assert level in SEVERITY_COLORS, f"Missing severity: {level}"


def test_colors_are_valid_hex():
    """All colour values should be valid 7-char hex strings."""
    from style_config import COLORS, SEVERITY_COLORS

    for name, val in {**COLORS, **SEVERITY_COLORS}.items():
        assert val.startswith("#") and len(val) == 7, (
            f"Invalid hex color for {name}: {val}"
        )


def test_format_thousands():
    """format_thousands should abbreviate large numbers with K suffix."""
    from style_config import format_thousands

    assert format_thousands(500, None) == "500"
    assert format_thousands(1000, None) == "1K"
    assert format_thousands(25000, None) == "25K"


def test_figure_sizes():
    """Figure size tuples should have exactly two positive values."""
    from style_config import FIG_SIZE, FIG_SIZE_TALL, FIG_SIZE_DOUBLE

    for size in [FIG_SIZE, FIG_SIZE_TALL, FIG_SIZE_DOUBLE]:
        assert len(size) == 2
        assert all(v > 0 for v in size)


def test_cwe_names_mapping():
    """CWE_NAMES should map string keys to non-empty string values."""
    from style_config import CWE_NAMES

    assert len(CWE_NAMES) > 0
    for key, val in CWE_NAMES.items():
        assert isinstance(key, str)
        assert isinstance(val, str) and len(val) > 0


def test_apply_style_runs_without_error():
    """apply_style() should not raise."""
    import matplotlib

    matplotlib.use("Agg")  # Non-interactive backend for CI
    from style_config import apply_style

    apply_style()  # Should not raise


def test_save_dpi_reasonable():
    """DPI should be a reasonable value for publication output."""
    from style_config import SAVE_DPI

    assert 72 <= SAVE_DPI <= 600
