"""The CLI is a contract with test.sh. These tests pin that contract."""
import pytest

pytest.importorskip("unicorn")

from tracer.cli import build_parser  # noqa: E402


def test_parses_the_exact_vector_test_sh_uses():
    """test.sh:161-163 invokes the tracer with precisely this shape."""
    args = build_parser().parse_args(
        ["tests/test08.exe", "-o", "traces/x.dtrace", "--start-func", "main"]
    )
    assert args.binary == "tests/test08.exe"
    assert args.output == "traces/x.dtrace"
    assert args.start_func == "main"


def test_stop_on_empty_stack_still_parses():
    """Forwarded by test.sh's --stop-on-empty-stack option."""
    args = build_parser().parse_args(["b.exe", "--stop-on-empty-stack"])
    assert args.stop_on_empty_stack is True


def test_post_double_dash_passthrough_args():
    """test.sh forwards anything after `--` straight to the tracer."""
    args = build_parser().parse_args(["b.exe", "--max-insns", "500000", "-v"])
    assert args.max_insns == 500000
    assert args.verbose is True


def test_defaults_match_pre_refactor_behavior():
    args = build_parser().parse_args(["b.exe"])
    assert args.output == "trace.dtrace"
    assert args.start_func == "main"
    assert args.max_insns == 200_000
    assert args.timeout == 10
    assert args.layouts == 1
    assert args.skip_unknown_calls is True
    assert args.tier == 0


@pytest.mark.parametrize("tier", [0, 1, 2, 3, 7])
def test_tier_accepts_valid_values(tier):
    args = build_parser().parse_args(["b.exe", "--tier", str(tier)])
    assert args.tier == tier


def test_tier_rejects_out_of_range():
    with pytest.raises(SystemExit):
        build_parser().parse_args(["b.exe", "--tier", "10"])


def test_the_highest_tier_is_accepted():
    """Bumped with each new tier, deliberately: the range is the contract."""
    assert build_parser().parse_args(["b.exe", "--tier", "9"]).tier == 9


def test_percent_signs_in_help_are_escaped():
    """argparse %-formats help strings, so a literal `80%` is a format spec.

    `80% of what Kvasir reports` was read as `%o` and made --help crash with
    "TypeError: %o format: an integer is required" - a runtime error in the
    one code path a user hits before anything else.
    """
    build_parser().format_help()


def test_layer_is_rejected_not_prefix_matched():
    """--layers (stack relocation) and a hypothetical --layer (heuristics) are
    unrelated knobs with confusable names. The heuristic flag is --tier, and
    --layer must be a hard error rather than an argparse prefix match onto
    --layouts."""
    with pytest.raises(SystemExit):
        build_parser().parse_args(["b.exe", "--layer", "3"])


def test_layouts_still_means_stack_relocation():
    args = build_parser().parse_args(["b.exe", "--layouts", "5"])
    assert args.layouts == 5


def test_help_renders_the_usage_epilog(capsys):
    with pytest.raises(SystemExit) as exc:
        build_parser().parse_args(["--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "--layouts 5" in out, "usage epilog (module docstring) missing from --help"
