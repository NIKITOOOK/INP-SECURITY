"""Real LangGraph binding for the fail-closed policy adapter.

The graph accepts one model-produced tool call at a time.  A trusted host must
enrol the LangGraph ``thread_id`` in ``LangGraphPolicyAdapter`` before invoking
the graph.  ToolNode is reachable only after an explicit policy ``allow``.
"""
from __future__ import annotations

import copy
from typing import Annotated, Any, Callable

from langchain_core.messages import AIMessage, AnyMessage, ToolMessage
from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode
from langgraph.types import interrupt
from typing_extensions import TypedDict

from engine import PolicyError
from l1 import L1Pipeline
from .adapter import LangGraphPolicyAdapter
from .cancellation import LangGraphCancellationController


class PolicyGraphState(TypedDict, total=False):
    messages: Annotated[list[AnyMessage], add_messages]
    active_tool_call: dict[str, Any]
    policy_decision: dict[str, Any]
    pending_id: str


class SecureAgentState(PolicyGraphState, total=False):
    input_event: dict[str, Any]
    input_decision: dict[str, Any]
    source_event_ids: list[str]
    result_decision: dict[str, Any]
    result_source_event_ids: list[str]
    planner_failed: bool


def _thread_id(config: RunnableConfig) -> str:
    value = config.get('configurable', {}).get('thread_id')
    return value if isinstance(value, str) else ''


def _local_deny(adapter: LangGraphPolicyAdapter, rule_id: str) -> dict[str, Any]:
    """Construct a fail-closed result without asking the policy engine to run a tool."""
    return {
        'decision': 'deny',
        'rule_id': rule_id,
        'policy_version': adapter.engine.config['policy_version'],
        'policy_digest': adapter.engine.policy_digest,
    }


def _one_tool_call(state: PolicyGraphState) -> dict[str, Any] | None:
    messages = state.get('messages', [])
    if not messages or not isinstance(messages[-1], AIMessage):
        return None
    calls = messages[-1].tool_calls
    if len(calls) != 1:
        return None
    return copy.deepcopy(calls[0])


def build_policy_graph(
    adapter: LangGraphPolicyAdapter,
    tools: list[Any],
    *,
    checkpointer: Any | None = None,
):
    """Build a single-tool-call graph with policy and human-approval gates.

    ``tools`` are passed to LangGraph's real ToolNode.  The graph uses an
    in-memory checkpointer by default so ``interrupt``/``resume`` works in the
    laboratory spike.  Production deployment needs a durable checkpointer.
    """

    def policy_gate(state: PolicyGraphState, config: RunnableConfig):
        call = _one_tool_call(state)
        if call is None:
            return {
                'policy_decision': _local_deny(adapter, 'INVALID_OR_BATCHED_TOOL_CALL'),
            }
        decision = adapter.evaluate(_thread_id(config), call)
        update: dict[str, Any] = {
            'active_tool_call': call,
            'policy_decision': decision,
        }
        if decision['decision'] == 'require_review':
            update['pending_id'] = decision['pending_id']
        return update

    def approval_gate(state: PolicyGraphState, config: RunnableConfig):
        call = state.get('active_tool_call')
        pending_id = state.get('pending_id')
        if not isinstance(call, dict) or not isinstance(pending_id, str):
            return {'policy_decision': _local_deny(adapter, 'INVALID_APPROVAL_STATE')}

        response = interrupt({
            'kind': 'policy.approval_required',
            'pending_id': pending_id,
            'tool_call': copy.deepcopy(call),
            'policy_digest': adapter.engine.policy_digest,
        })
        if (
            not isinstance(response, dict)
            or set(response) != {'approved'}
            or type(response['approved']) is not bool
        ):
            return {'policy_decision': _local_deny(adapter, 'INVALID_APPROVAL_RESPONSE')}
        if response['approved'] is not True:
            return {'policy_decision': _local_deny(adapter, 'HUMAN_REJECTED')}

        try:
            token = adapter.operator_approve(pending_id)
        except PolicyError:
            return {'policy_decision': _local_deny(adapter, 'APPROVAL_INVALID')}
        decision = adapter.evaluate(
            _thread_id(config),
            call,
            approval_token=token,
        )
        return {'policy_decision': decision}

    def route_after_policy(state: PolicyGraphState):
        decision = state.get('policy_decision', {}).get('decision')
        if decision == 'allow':
            return 'tools'
        if decision == 'require_review':
            return 'approval'
        return END

    def route_after_approval(state: PolicyGraphState):
        return 'tools' if state.get('policy_decision', {}).get('decision') == 'allow' else END

    graph = StateGraph(PolicyGraphState)
    graph.add_node('policy', policy_gate)
    graph.add_node('approval', approval_gate)
    graph.add_node('tools', ToolNode(tools))
    graph.add_edge(START, 'policy')
    graph.add_conditional_edges('policy', route_after_policy, ['tools', 'approval', END])
    graph.add_conditional_edges('approval', route_after_approval, ['tools', END])
    graph.add_edge('tools', END)
    return graph.compile(checkpointer=checkpointer or InMemorySaver(), name='policy-gated-tools')


def build_secure_agent_graph(
    adapter: LangGraphPolicyAdapter,
    l1_pipeline: L1Pipeline,
    tools: list[Any],
    planner: Callable[[dict[str, Any], dict[str, Any]], AIMessage],
    *,
    cancellation_controller: LangGraphCancellationController | None = None,
    checkpointer: Any | None = None,
):
    """Build the laboratory end-to-end path ``L1 -> planner -> L3 -> ToolNode``.

    ``planner`` is deliberately injected by the trusted host. Tests use a
    deterministic planner, so this function proves the security control flow
    without claiming that an LLM is safe. The adapter and L1 pipeline must share
    the same policy engine, and provenance is supplied only by the L1 node.
    """
    if adapter.engine is not l1_pipeline.engine:
        raise ValueError('L1 pipeline and LangGraph adapter must share one policy engine')
    if adapter.l1_pipeline is not l1_pipeline:
        raise ValueError('LangGraph adapter must be constructed with this L1 pipeline')

    def input_gate(state: SecureAgentState):
        event = state.get('input_event')
        if not isinstance(event, dict):
            return {'input_decision': _local_deny(adapter, 'INVALID_INPUT')}
        try:
            decision = l1_pipeline.inspect(copy.deepcopy(event))
        except (KeyError, PolicyError, TypeError, ValueError, RuntimeError, RecursionError):
            decision = _local_deny(adapter, 'INVALID_INPUT')
        update: dict[str, Any] = {'input_decision': decision}
        if decision.get('decision') == 'annotate':
            event_id = event.get('event_id')
            if isinstance(event_id, str) and event_id:
                update['source_event_ids'] = [event_id]
        return update

    def planner_node(state: SecureAgentState):
        event = state.get('input_event')
        decision = state.get('input_decision')
        if not isinstance(event, dict) or not isinstance(decision, dict):
            return {'policy_decision': _local_deny(adapter, 'INVALID_PLANNER_STATE')}
        try:
            message = planner(copy.deepcopy(event), copy.deepcopy(decision))
        except Exception:  # A planner failure must never fall through to ToolNode.
            return {
                'policy_decision': _local_deny(adapter, 'PLANNER_FAILURE'),
                'planner_failed': True,
            }
        if not isinstance(message, AIMessage):
            return {
                'policy_decision': _local_deny(adapter, 'INVALID_PLANNER_OUTPUT'),
                'planner_failed': True,
            }
        return {'messages': [message], 'planner_failed': False}

    def policy_gate(state: SecureAgentState, config: RunnableConfig):
        call = _one_tool_call(state)
        if call is None:
            return {'policy_decision': _local_deny(adapter, 'INVALID_OR_BATCHED_TOOL_CALL')}
        decision = adapter.evaluate(
            _thread_id(config),
            call,
            source_event_ids=state.get('source_event_ids', []),
        )
        update: dict[str, Any] = {
            'active_tool_call': call,
            'policy_decision': decision,
        }
        if decision['decision'] == 'require_review':
            update['pending_id'] = decision['pending_id']
        return update

    def approval_gate(state: SecureAgentState, config: RunnableConfig):
        call = state.get('active_tool_call')
        pending_id = state.get('pending_id')
        if not isinstance(call, dict) or not isinstance(pending_id, str):
            return {'policy_decision': _local_deny(adapter, 'INVALID_APPROVAL_STATE')}
        response = interrupt({
            'kind': 'policy.approval_required',
            'pending_id': pending_id,
            'tool_call': copy.deepcopy(call),
            'policy_digest': adapter.engine.policy_digest,
        })
        if (
            not isinstance(response, dict)
            or set(response) != {'approved'}
            or type(response['approved']) is not bool
        ):
            return {'policy_decision': _local_deny(adapter, 'INVALID_APPROVAL_RESPONSE')}
        if response['approved'] is not True:
            return {'policy_decision': _local_deny(adapter, 'HUMAN_REJECTED')}
        try:
            token = adapter.operator_approve(pending_id)
        except PolicyError:
            return {'policy_decision': _local_deny(adapter, 'APPROVAL_INVALID')}
        return {
            'policy_decision': adapter.evaluate(
                _thread_id(config),
                call,
                source_event_ids=state.get('source_event_ids', []),
                approval_token=token,
            )
        }

    def route_after_input(state: SecureAgentState):
        return 'planner' if state.get('input_decision', {}).get('decision') == 'annotate' else END

    def route_after_planner(state: SecureAgentState):
        return END if state.get('planner_failed') is True else 'policy'

    def route_after_policy(state: SecureAgentState):
        decision = state.get('policy_decision', {}).get('decision')
        if decision == 'allow':
            return 'tools'
        if decision == 'require_review':
            return 'approval'
        return END

    def route_after_approval(state: SecureAgentState):
        return 'tools' if state.get('policy_decision', {}).get('decision') == 'allow' else END

    def result_gate(state: SecureAgentState, config: RunnableConfig):
        messages = state.get('messages', [])
        if not messages or not isinstance(messages[-1], ToolMessage):
            return {'result_decision': _local_deny(adapter, 'INVALID_TOOL_RESULT')}
        message = messages[-1]
        if not isinstance(message.content, str):
            return {'result_decision': _local_deny(adapter, 'INVALID_TOOL_RESULT')}
        result_event_id = (
            f"result:{_thread_id(config)}:{message.tool_call_id}"
        )
        decision = l1_pipeline.inspect({
            'kind': 'input.received',
            'event_id': result_event_id,
            'origin': 'tool',
            'text': message.content,
        })
        update: dict[str, Any] = {
            'result_decision': decision,
            'result_source_event_ids': [result_event_id],
        }
        if decision.get('decision') == 'deny':
            update['messages'] = [ToolMessage(
                content='Tool output blocked by input policy',
                name=message.name,
                tool_call_id=message.tool_call_id,
                status='error',
                id=message.id,
            )]
        return update

    graph = StateGraph(SecureAgentState)
    graph.add_node('input', input_gate)
    graph.add_node('planner', planner_node)
    graph.add_node('policy', policy_gate)
    graph.add_node('approval', approval_gate)
    graph.add_node(
        'tools',
        ToolNode(
            tools,
            wrap_tool_call=(
                cancellation_controller.wrap_tool_call
                if cancellation_controller is not None
                else None
            ),
        ),
    )
    graph.add_node('result', result_gate)
    graph.add_edge(START, 'input')
    graph.add_conditional_edges('input', route_after_input, ['planner', END])
    graph.add_conditional_edges('planner', route_after_planner, ['policy', END])
    graph.add_conditional_edges('policy', route_after_policy, ['tools', 'approval', END])
    graph.add_conditional_edges('approval', route_after_approval, ['tools', END])
    graph.add_edge('tools', 'result')
    graph.add_edge('result', END)
    return graph.compile(checkpointer=checkpointer or InMemorySaver(), name='l1-l3-secure-agent')
