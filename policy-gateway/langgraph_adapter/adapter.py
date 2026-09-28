"""Fail-closed adapter from LangGraph tool-call dictionaries to Policy Engine events.

This module does not import or run LangGraph. It is the contract layer used by the
safe portability spike; the real ToolNode/interrupt binding is added only after the
runtime environment is approved.
"""
from __future__ import annotations

import copy
from typing import TYPE_CHECKING, Any, Callable

from engine import Engine

if TYPE_CHECKING:
    from l1 import L1Pipeline


class SessionEnrollmentError(ValueError):
    pass


TOOL_MAP = {
    'read': ('file.read', 'read'),
    'write': ('file.write', 'write'),
    'edit': ('file.write', 'write'),
    'delete': ('file.delete', 'delete'),
    'http_request': ('network.http', 'network.send'),
    # This deliberately maps to an operation that L3 must always deny. The
    # callable, if a host registers one, is never an administrative bypass.
    'modify_policy': ('file.write', 'policy.modify'),
}


class LangGraphPolicyAdapter:
    """Trusted host enrolls threads; model-controlled state cannot assign rights."""

    def __init__(self, engine: Engine, *, l1_pipeline: 'L1Pipeline | None' = None):
        self.engine = engine
        self.l1_pipeline = l1_pipeline
        self._sessions: dict[str, tuple[str, str]] = {}

    def _deny(self, rule_id: str) -> dict[str, Any]:
        return {
            'decision': 'deny',
            'rule_id': rule_id,
            'policy_version': self.engine.config['policy_version'],
            'policy_digest': self.engine.policy_digest,
        }

    def enroll(self, thread_id: str, *, actor_id: str, task_id: str) -> None:
        if not all(isinstance(value, str) and value for value in (thread_id, actor_id, task_id)):
            raise SessionEnrollmentError('Thread, actor and task identifiers must be nonempty strings')
        identity = (actor_id, task_id)
        previous = self._sessions.get(thread_id)
        if previous is not None and previous != identity:
            raise SessionEnrollmentError('An enrolled thread cannot change actor or task')
        self._sessions[thread_id] = identity

    def _event(
        self,
        thread_id: str,
        tool_call: dict[str, Any],
        *,
        source_event_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        if thread_id not in self._sessions:
            raise SessionEnrollmentError('Thread is not enrolled')
        if not isinstance(tool_call, dict) or not {'id', 'name', 'args'} <= set(tool_call):
            raise ValueError('Invalid LangGraph tool call')
        if set(tool_call) - {'id', 'name', 'args', 'type'}:
            raise ValueError('Unknown tool-call fields')
        if 'type' in tool_call and tool_call['type'] != 'tool_call':
            raise ValueError('Unsupported tool-call type')
        call_id, name, args = tool_call['id'], tool_call['name'], tool_call['args']
        if not isinstance(call_id, str) or not call_id or not isinstance(name, str) or not name:
            raise ValueError('Tool call id and name must be nonempty strings')
        if not isinstance(args, dict):
            raise ValueError('Tool arguments must be a mapping')
        actor_id, task_id = self._sessions[thread_id]
        mapping = TOOL_MAP.get(name)
        if mapping is None:
            tool_name, operation = f'unmapped:{name}', 'invoke'
            arguments = {'original_arguments': copy.deepcopy(args)}
        elif mapping[1] == 'network.send':
            tool_name, operation = mapping
            arguments = {
                'url': args.get('url'),
                'original_arguments': copy.deepcopy(args),
            }
        else:
            tool_name, operation = mapping
            arguments = {
                'path': args.get('file_path'),
                'original_arguments': copy.deepcopy(args),
            }
        event = {
            'kind': 'tool.requested',
            'call_id': call_id,
            'session_id': thread_id,
            'task_id': task_id,
            'actor_id': actor_id,
            'tool_name': tool_name,
            'operation': operation,
            'arguments': arguments,
        }
        if self.l1_pipeline is None:
            # Contract-only use has no trusted input hook. Preserve uncertainty.
            return {
                **event,
                'source_event_ids': [],
                'data_labels': ['unknown', 'untrusted'],
            }
        return self.l1_pipeline.bind_tool_request(
            event,
            source_event_ids=list(source_event_ids or []),
        )

    def evaluate(
        self,
        thread_id: str,
        tool_call: dict[str, Any],
        *,
        source_event_ids: list[str] | None = None,
        approval_token: str | None = None,
        approval_available: bool = True,
    ) -> dict[str, Any]:
        try:
            event = self._event(
                thread_id,
                tool_call,
                source_event_ids=source_event_ids,
            )
        except (ValueError, TypeError, RecursionError):
            return self._deny('INVALID_LANGGRAPH_TOOL_CALL')
        try:
            return self.engine.decide(
                event,
                approval_token=approval_token,
                approval_available=approval_available,
            )
        except Exception:
            # A crashed policy hook must not expose ToolNode. Operational detail
            # belongs in a host-side log, not in the model-visible decision.
            return self._deny('POLICY_EVALUATION_FAILED')

    def operator_approve(self, pending_id: str) -> str:
        """Trusted control-plane operation. Never expose this as an agent tool."""
        return self.engine.approve(pending_id)

    def guarded_execute(
        self,
        thread_id: str,
        tool_call: dict[str, Any],
        body: Callable[[dict[str, Any]], Any],
        *,
        source_event_ids: list[str] | None = None,
        approval_token: str | None = None,
        approval_available: bool = True,
    ) -> tuple[dict[str, Any], Any | None]:
        decision = self.evaluate(
            thread_id,
            tool_call,
            source_event_ids=source_event_ids,
            approval_token=approval_token,
            approval_available=approval_available,
        )
        if decision['decision'] != 'allow':
            return decision, None
        return decision, body(copy.deepcopy(tool_call['args']))
