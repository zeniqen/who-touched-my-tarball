"""Red-team mode: tamper copies of real releases with modelled attacks and measure detection."""

from .attacks import ATTACKS, Attack, NotApplicable
from .campaign import CampaignResult, Row, run_campaign
from .tamper import TamperResult, applicable_attacks, detect_format, tamper

__all__ = ["ATTACKS", "Attack", "CampaignResult", "NotApplicable", "Row", "TamperResult", "applicable_attacks",
           "detect_format", "run_campaign", "tamper"]
