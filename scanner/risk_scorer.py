"""
Risk Scorer Module

Calculates CVSS-like numeric risk scores for IAM findings.
Applies severity base + contextual modifiers.
Provides helper to map score back to severity bucket.
"""

from typing import Dict, Any


class RiskScorer:
    """
    Calculates risk scores and maps them to severity levels.
    """

    # Base scores per severity tier
    BASE_SCORES = {
        "CRITICAL": 9.0,
        "HIGH": 7.5,
        "MEDIUM": 5.5,
        "LOW": 3.0,
        "INFO": 1.0
    }

    # Valid severity levels in descending order of severity
    SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

    def calculate_score(self, severity: str, modifiers: Dict[str, bool] = None) -> float:
        """
        Calculate numeric risk score (0.0 - 10.0).

        Args:
            severity: One of CRITICAL, HIGH, MEDIUM, LOW, INFO
            modifiers: Optional dict of boolean flags:
                - no_mfa: +0.5
                - admin_access: +0.5
                - externally_accessible: +0.5
                - has_condition: -0.5
                - is_service_role: -0.5
                - has_compensating_control: -1.0

        Returns:
            float rounded to 1 decimal place, capped at 10.0
        """
        if modifiers is None:
            modifiers = {}

        base = self.BASE_SCORES.get(severity.upper(), 1.0)
        score = base

        # Apply modifiers
        if modifiers.get("no_mfa"):
            score += 0.5
        if modifiers.get("admin_access"):
            score += 0.5
        if modifiers.get("externally_accessible"):
            score += 0.5
        if modifiers.get("has_condition"):
            score -= 0.5
        if modifiers.get("is_service_role"):
            score -= 0.5
        if modifiers.get("has_compensating_control"):
            score -= 1.0

        # Cap at 10.0 and floor at 0.0
        score = max(0.0, min(10.0, score))

        # Round to 1 decimal place
        return round(score, 1)

    def get_severity_from_score(self, score: float) -> str:
        """
        Map a numeric score back to a severity string.

        Ranges:
            9.0 - 10.0  -> CRITICAL
            7.0 - 8.9   -> HIGH
            4.0 - 6.9   -> MEDIUM
            1.0 - 3.9   -> LOW
            0.0 - 0.9   -> INFO
        """
        if score >= 9.0:
            return "CRITICAL"
        elif score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        elif score >= 1.0:
            return "LOW"
        else:
            return "INFO"

    def get_severity_rank(self, severity: str) -> int:
        """Return numeric rank for sorting (higher = more severe)."""
        try:
            return self.SEVERITY_ORDER.index(severity.upper())
        except ValueError:
            return len(self.SEVERITY_ORDER)  # unknown at end
