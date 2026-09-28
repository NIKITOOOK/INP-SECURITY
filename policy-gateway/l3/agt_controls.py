"""Small Python adapter for selected AGT policy semantics.

Derived from the MIT-licensed AGT stock policy helpers ``budgets.rego``,
``approval.rego``, ``egress.rego`` and ``ifc.rego``.  This module does not
claim Rego/OPA compatibility; it preserves only the explicitly tested
decision semantics needed by the laboratory gateway.
"""
from __future__ import annotations

import math
from urllib.parse import urlsplit


BUDGET_COUNTERS = (
    'tool_call_count', 'token_count', 'elapsed_seconds', 'cost_usd',
)


def _number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def budget_verdict(counters, thresholds):
    """Return an AGT-shaped deny verdict, or ``None`` while under budget."""
    if not isinstance(counters, dict) or not isinstance(thresholds, dict):
        return {'decision': 'deny', 'reason': 'budget_state_invalid'}
    for name in BUDGET_COUNTERS:
        if name in counters and (not _number(counters[name]) or counters[name] < 0):
            return {'decision': 'deny', 'reason': 'budget_counter_invalid', 'counter': name}
        if name in thresholds and (not _number(thresholds[name]) or thresholds[name] <= 0):
            return {'decision': 'deny', 'reason': 'budget_threshold_invalid', 'counter': name}
    reasons = {
        'tool_call_count': 'budget_tool_calls_exceeded',
        'token_count': 'budget_tokens_exceeded',
        'elapsed_seconds': 'budget_timeout_exceeded',
        'cost_usd': 'budget_cost_exceeded',
    }
    for name in BUDGET_COUNTERS:
        if name in thresholds and counters.get(name, 0) >= thresholds[name]:
            return {
                'decision': 'deny', 'reason': reasons[name], 'counter': name,
                'value': counters.get(name, 0), 'limit': thresholds[name],
            }
    return None


def approval_verdict(required, approvers):
    """Map AGT ``escalate`` to this gateway's ``require_review`` decision."""
    if required is not True:
        return None
    if not isinstance(approvers, list) or not approvers or any(
        not isinstance(value, str) or not value for value in approvers
    ):
        return {'decision': 'deny', 'reason': 'approval_resolver_invalid'}
    return {
        'decision': 'require_review', 'reason': 'approval_required',
        'approvers': list(approvers),
    }


def host_of(destination):
    """Extract a normalized hostname without accepting embedded credentials."""
    if not isinstance(destination, str) or not destination or '\x00' in destination:
        return None
    candidate = destination if '://' in destination else f'//{destination}'
    parsed = urlsplit(candidate)
    if parsed.username is not None or parsed.password is not None:
        return None
    try:
        host = parsed.hostname
        return host.encode('idna').decode('ascii').lower().rstrip('.') if host else None
    except (UnicodeError, ValueError):
        return None


def _host_allowed(host, pattern):
    pattern = pattern.lower().rstrip('.')
    if pattern.startswith('*.'):
        suffix = pattern[1:]
        return host.endswith(suffix) and host != suffix[1:]
    return host == pattern


def egress_verdict(arguments, allowlist):
    """Deny an absent, malformed or off-allowlist network destination."""
    if not isinstance(arguments, dict) or not isinstance(allowlist, list):
        return {'decision': 'deny', 'reason': 'egress_policy_invalid'}
    destination = next((arguments.get(key) for key in ('url', 'endpoint', 'host', 'domain')
                        if isinstance(arguments.get(key), str)), None)
    host = host_of(destination)
    if host is None:
        return {'decision': 'deny', 'reason': 'egress_destination_missing_or_invalid'}
    if not any(isinstance(pattern, str) and _host_allowed(host, pattern) for pattern in allowlist):
        return {'decision': 'deny', 'reason': 'egress_destination_not_allowed', 'host': host}
    return None


def ifc_verdict(sink_clearance, data_labels, lattice, default_source_label):
    """Apply AGT's no-write-down lattice rule to ``class:<label>`` labels."""
    if not isinstance(lattice, dict) or sink_clearance not in lattice:
        return {'decision': 'deny', 'reason': 'ifc_policy_invalid'}
    explicit = [label[6:] for label in data_labels
                if isinstance(label, str) and label.startswith('class:')]
    source_labels = explicit or [default_source_label]
    if any(label not in lattice for label in source_labels):
        return {'decision': 'deny', 'reason': 'ifc_label_unknown'}
    dominated = lattice[sink_clearance]
    if not isinstance(dominated, list) or any(label not in dominated for label in source_labels):
        return {
            'decision': 'deny', 'reason': 'ifc_clearance_violation',
            'sink_clearance': sink_clearance, 'source_labels': source_labels,
        }
    return None

