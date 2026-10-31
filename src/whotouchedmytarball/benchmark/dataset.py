"""Default benchmark dataset using bundled example fixtures."""

from __future__ import annotations

from pathlib import Path

from .models import Scenario

DATASET_VERSION = '0.1.0'

_ROOT = Path(__file__).resolve().parents[3]  # repo root


def default_scenarios():
    from .generator import scenarios
    return scenarios()
