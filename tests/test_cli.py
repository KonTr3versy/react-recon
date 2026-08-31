from react_recon.cli import build_parser


def test_analyze_accepts_provider_and_model_overrides():
    args = build_parser().parse_args(
        ["analyze", "run-fixture", "--provider", "anthropic", "--model", "claude-fixture", "--max-targets", "4"]
    )
    assert args.provider == "anthropic"
    assert args.model == "claude-fixture"
    assert args.max_targets == 4
