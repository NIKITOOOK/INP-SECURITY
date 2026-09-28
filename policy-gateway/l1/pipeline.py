"""Trusted L1 provenance binding before an L3 tool decision."""
from __future__ import annotations

import copy
from typing import Any, Callable

from engine import Engine, PolicyError, digest
from .nemo_jailbreak import DetectorUnavailable


class L1Pipeline:
    """Stores L1 results and binds them to one later tool request.

    The host supplies tool identity and user/task identity.  Model-controlled
    arguments cannot supply ``data_labels`` or ``source_event_ids``.
    """

    def __init__(self, engine: Engine, detector: Callable[[str], bool] | None = None):
        self.engine = engine
        self.detector = detector
        self._inputs: dict[str, dict[str, Any]] = {}

    def inspect(self, event: dict[str, Any]) -> dict[str, Any]:
        result = self.engine.check_input(copy.deepcopy(event))
        labels = list(result.get('labels', []))
        if result['decision'] == 'deny':
            return result
        if self.detector is not None:
            try:
                if self.detector(event['text']):
                    labels.append('prompt_injection_suspected')
            except (DetectorUnavailable, TypeError, ValueError, RuntimeError):
                labels.extend(['detector_unavailable', 'untrusted'])
        labels = sorted(set(labels))
        record = {
            'event_id': event['event_id'],
            'origin': event['origin'],
            'labels': labels,
            'content_digest': digest({'origin': event['origin'], 'text': event['text']}),
        }
        self._inputs[event['event_id']] = record
        return {**result, 'labels': labels, 'content_digest': record['content_digest']}

    def bind_tool_request(
        self,
        event: dict[str, Any],
        *,
        source_event_ids: list[str],
    ) -> dict[str, Any]:
        if not isinstance(event, dict) or set(event) & {'data_labels', 'source_event_ids'}:
            raise PolicyError('Tool request cannot self-assign provenance')
        if not isinstance(source_event_ids, list) or any(
            not isinstance(value, str) or not value for value in source_event_ids
        ) or len(set(source_event_ids)) != len(source_event_ids):
            raise PolicyError('Invalid source_event_ids')
        labels: set[str] = set()
        for event_id in source_event_ids:
            record = self._inputs.get(event_id)
            if record is None:
                labels.update({'unknown', 'untrusted'})
            else:
                labels.update(record['labels'])
        if not source_event_ids:
            labels.update({'unknown', 'untrusted'})
        return {
            **copy.deepcopy(event),
            'source_event_ids': list(source_event_ids),
            'data_labels': sorted(labels),
        }

    def decide_tool(
        self,
        event: dict[str, Any],
        *,
        source_event_ids: list[str],
        approval_token: str | None = None,
        approval_available: bool = True,
    ) -> dict[str, Any]:
        try:
            bound = self.bind_tool_request(event, source_event_ids=source_event_ids)
        except (PolicyError, TypeError, ValueError, RecursionError):
            return self.engine._result('deny', 'INVALID_PROVENANCE_BINDING')
        return self.engine.decide(bound, approval_token, approval_available)
