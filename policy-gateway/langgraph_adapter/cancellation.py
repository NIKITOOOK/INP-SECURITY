"""Cooperative active-tool cancellation for the LangGraph laboratory adapter."""
from __future__ import annotations

from contextvars import ContextVar
import json
from threading import Event, RLock
from typing import Any, Callable

from langchain_core.messages import ToolMessage

from engine import Engine


class ToolCancelled(RuntimeError):
    """Raised by a cooperative tool at a trusted cancellation point."""


_active_signal: ContextVar[Event | None] = ContextVar('active_tool_cancel_signal', default=None)


def cancellation_point() -> None:
    """Allow a cooperative tool to stop after the control plane requests it."""
    signal = _active_signal.get()
    if signal is not None and signal.is_set():
        raise ToolCancelled('Tool execution cancelled by the trusted control plane')


class LangGraphCancellationController:
    """Connect ``Engine.stop_session`` to a LangGraph ``ToolNode`` wrapper.

    This is cooperative cancellation, not an OS process kill. A tool that never
    calls :func:`cancellation_point` may already have performed an effect and may
    keep running. The returned ToolMessage therefore reports effect uncertainty.
    """

    def __init__(self, engine: Engine):
        self.engine = engine
        self._signals: dict[str, Event] = {}
        self._lock = RLock()

    def _signal(self, session_id: str) -> Event:
        with self._lock:
            return self._signals.setdefault(session_id, Event())

    def stop_session(self, session_id: str) -> dict[str, Any]:
        result = self.engine.stop_session(session_id)
        self._signal(session_id).set()
        return result

    @staticmethod
    def _session_id(request: Any) -> str:
        config = getattr(getattr(request, 'runtime', None), 'config', {})
        value = config.get('configurable', {}).get('thread_id') if isinstance(config, dict) else None
        return value if isinstance(value, str) else ''

    @staticmethod
    def _cancelled_message(request: Any, effect: str) -> ToolMessage:
        call = request.tool_call
        return ToolMessage(
            content=json.dumps({
                'status': 'cancelled',
                'effect': effect,
            }),
            name=call['name'],
            tool_call_id=call['id'],
            status='error',
        )

    def wrap_tool_call(
        self,
        request: Any,
        execute: Callable[[Any], ToolMessage],
    ) -> ToolMessage:
        session_id = self._session_id(request)
        signal = self._signal(session_id)
        if not session_id or signal.is_set() or session_id in self.engine.stopped_sessions:
            return self._cancelled_message(request, 'not_started')
        token = _active_signal.set(signal)
        try:
            return execute(request)
        except ToolCancelled:
            return self._cancelled_message(request, 'may_have_occurred')
        finally:
            _active_signal.reset(token)
