"""
Policy Parser Module

Analyzes IAM policy documents for dangerous patterns, wildcards,
privilege escalation vectors, and missing conditions.
Handles all documented edge cases:
- Action / Resource can be str or list
- Statement can be dict or list
- Policy may include Version at top level
"""

import logging

logger = logging.getLogger(__name__)

# Dangerous actions that indicate high privilege or escalation potential.
# Any of these (or wildcard that covers them) should be flagged.
DANGEROUS_ACTIONS = [
    "iam:*",
    "iam:CreateUser",
    "iam:AttachUserPolicy",
    "iam:PutUserPolicy",
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",
    "iam:PassRole",
    "iam:CreateAccessKey",
    "iam:UpdateAssumeRolePolicy",
    "s3:*",
    "ec2:*",
    "sts:AssumeRole",
    "lambda:InvokeFunction",
    "organizations:*",
    "cloudtrail:DeleteTrail",
    "cloudtrail:StopLogging",
    "logs:DeleteLogGroup"
]


class PolicyParser:
    """
    Parses IAM policy JSON documents and extracts security-relevant signals.
    """

    def __init__(self):
        self.dangerous_actions = DANGEROUS_ACTIONS

    def _normalize_to_list(self, value):
        """Normalize a value that may be string or list into list."""
        if value is None:
            return []
        if isinstance(value, list):
            return value
        return [value]

    def _statement_to_list(self, policy_document):
        """
        Return list of statements regardless of whether policy has single statement or list.
        """
        if not policy_document or not isinstance(policy_document, dict):
            return []

        statements = policy_document.get('Statement', [])
        return self._normalize_to_list(statements)

    def _action_matches_dangerous(self, action):
        """
        Check if a given action string (or wildcard) matches any dangerous action.
        Supports exact match and simple prefix for wildcards (e.g. iam:*).
        """
        if not action or not isinstance(action, str):
            return False

        action_lower = action.lower().strip()

        for dangerous in self.dangerous_actions:
            d_lower = dangerous.lower()
            if action_lower == d_lower:
                return True
            # Handle wildcards: iam:* matches iam:CreateUser etc, and * matches everything
            if d_lower.endswith('*'):
                prefix = d_lower[:-1]
                if action_lower.startswith(prefix):
                    return True
            if action_lower == '*':
                return True
            # Also, if action is "iam:*" it should match "iam:CreateUser" etc but we check from both sides
            if action_lower.endswith('*'):
                a_prefix = action_lower[:-1]
                if d_lower.startswith(a_prefix):
                    return True

        return False

    def _has_wildcard_in_list(self, items):
        """Return True if '*' appears in the (normalized) list of strings."""
        for item in self._normalize_to_list(items):
            if isinstance(item, str) and item.strip() == '*':
                return True
        return False

    def _contains_dangerous_action(self, actions):
        """
        Check list of actions for any dangerous match (including "*").
        """
        actions_list = self._normalize_to_list(actions)
        for action in actions_list:
            if isinstance(action, str):
                if self._action_matches_dangerous(action):
                    return True
        return False

    def analyze_policy(self, policy_document):
        """
        Analyze a single policy document.

        Returns dict with:
            has_wildcard_action, has_wildcard_resource, is_full_admin,
            dangerous_actions, has_condition, has_notaction, has_notresource,
            allow_statements, deny_statements
        """
        result = {
            "has_wildcard_action": False,
            "has_wildcard_resource": False,
            "is_full_admin": False,
            "dangerous_actions": [],
            "has_condition": False,
            "has_notaction": False,
            "has_notresource": False,
            "allow_statements": [],
            "deny_statements": []
        }

        if not policy_document or not isinstance(policy_document, dict):
            return result

        statements = self._statement_to_list(policy_document)

        found_full_admin = False
        dangerous_found = set()

        for stmt in statements:
            if not isinstance(stmt, dict):
                continue

            effect = str(stmt.get('Effect', '')).lower()
            actions = stmt.get('Action')
            not_actions = stmt.get('NotAction')
            resources = stmt.get('Resource')
            not_resources = stmt.get('NotResource')
            condition = stmt.get('Condition')
            principal = stmt.get('Principal')

            # Track allow vs deny
            if effect == 'allow':
                result['allow_statements'].append(stmt)
            elif effect == 'deny':
                result['deny_statements'].append(stmt)

            # has_condition
            if condition and isinstance(condition, dict) and len(condition) > 0:
                result['has_condition'] = True

            # has_notaction
            if not_actions:
                result['has_notaction'] = True

            # has_notresource
            if not_resources:
                result['has_notresource'] = True

            # Wildcard action
            if self._has_wildcard_in_list(actions):
                result['has_wildcard_action'] = True

            # Wildcard resource
            if self._has_wildcard_in_list(resources):
                result['has_wildcard_resource'] = True

            # Check dangerous actions (including when Action == "*")
            actions_list = self._normalize_to_list(actions)
            for action in actions_list:
                if isinstance(action, str):
                    if self._action_matches_dangerous(action):
                        dangerous_found.add(action)
                    # Special case: plain "*" is dangerous
                    if action.strip() == '*':
                        dangerous_found.add('*')

            # Full admin: Effect Allow + Action:* + Resource:*
            if effect == 'allow':
                if self._has_wildcard_in_list(actions) and self._has_wildcard_in_list(resources):
                    found_full_admin = True

        result['is_full_admin'] = found_full_admin
        result['dangerous_actions'] = sorted(list(dangerous_found))

        return result

    def is_wildcard_policy(self, policy_document):
        """Convenience: returns True if policy has both wildcard action and resource."""
        analysis = self.analyze_policy(policy_document)
        return analysis['has_wildcard_action'] and analysis['has_wildcard_resource']

    def get_dangerous_actions(self, policy_document):
        """Return list of dangerous actions found in the policy."""
        analysis = self.analyze_policy(policy_document)
        return analysis['dangerous_actions']
