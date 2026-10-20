"""Unit tests for RedTeamEvaluator automated adversarial benchmark suite."""

import pytest
from shield.evaluator.red_team import RedTeamEvaluator, SecurityScorecard


def test_red_team_benchmark_execution():
    evaluator = RedTeamEvaluator()
    scorecard = evaluator.run_benchmark()

    assert isinstance(scorecard, SecurityScorecard)
    assert scorecard.total_tests == len(evaluator.BENCHMARK_CASES)
    assert scorecard.attacks_tested > 0
    assert scorecard.benign_tested > 0

    # Verification of benchmark targets
    assert scorecard.detection_recall == 1.0, f"Expected 100% recall, got {scorecard.detection_recall}"
    assert scorecard.attack_success_rate == 0.0, f"Expected 0% ASR, got {scorecard.attack_success_rate}"
    assert scorecard.false_positive_rate == 0.0, f"Expected 0% FPR, got {scorecard.false_positive_rate}"
    assert scorecard.unauthorized_tool_call_rate == 0.0, "Expected zero unauthorized tool calls"
    assert scorecard.regression_pass_rate == 1.0, "Expected 100% pass rate across regression suite"


def test_markdown_report_formatting():
    evaluator = RedTeamEvaluator()
    scorecard = evaluator.run_benchmark()
    report = evaluator.generate_markdown_report(scorecard)

    assert "# 🛡️ AgentShield Automated Security Evaluation Report" in report
    assert "Attack Detection Recall" in report
    assert "100.0%" in report
    assert "Unauthorized Tool Execution Rate" in report
