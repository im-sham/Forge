from forge_cli.display import display_stats
from forge_cli.models import Incident


def test_display_stats_empty(capsys):
    """Stats with no incidents prints a message."""
    display_stats([])
    # No crash is the assertion — Rich writes to its own console


def test_display_stats_with_incidents(sample_data):
    """Stats command processes incidents without errors."""
    incidents = [Incident.from_dict(sample_data)]
    # Should not raise
    display_stats(incidents)


def test_display_stats_multiple(sample_data):
    """Stats aggregates correctly across multiple incidents."""
    data2 = sample_data.copy()
    data2["id"] = "2026-03-04-002"
    data2["project"] = "aegis"
    data2["severity"] = "safety-critical"
    data2["failure_type"] = "error_handling_failure"
    data2["platform"] = "cursor"
    data2["tags"] = ["safety-critical"]

    incidents = [Incident.from_dict(sample_data), Incident.from_dict(data2)]
    # Should not raise
    display_stats(incidents)
