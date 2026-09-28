import copy
from pathlib import Path
import tempfile
import unittest

from langchain_core.messages import AIMessage, ToolMessage
from langchain_core.tools import StructuredTool
from langgraph.types import Command

from engine import Engine, load_policy
from langgraph_adapter import LangGraphPolicyAdapter
from langgraph_adapter.runtime import build_policy_graph


POLICY = Path(__file__).resolve().parent.parent / 'Политики_L1_L3_v0.1.yaml'


class LangGraphRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'workspace'
        self.root.mkdir()
        config = load_policy(POLICY)
        config['workspace']['root'] = str(self.root)
        self.adapter = LangGraphPolicyAdapter(Engine(config))
        self.executions = []

        def read(file_path: str) -> str:
            """Laboratory read tool; records execution without reading a file."""
            self.executions.append(('read', file_path))
            return 'read executed'

        def delete(file_path: str) -> str:
            """Laboratory delete tool; records execution without deleting a file."""
            self.executions.append(('delete', file_path))
            return 'delete executed'

        tools = [
            StructuredTool.from_function(read, name='read'),
            StructuredTool.from_function(delete, name='delete'),
        ]
        self.graph = build_policy_graph(self.adapter, tools)

    def call(self, call_id='call-1', name='read', path=None):
        return {
            'id': call_id,
            'name': name,
            'args': {'file_path': str(path or self.root / 'sample.txt')},
            'type': 'tool_call',
        }

    def config(self, thread_id):
        return {'configurable': {'thread_id': thread_id}}

    def invoke(self, thread_id, call):
        self.adapter.enroll(thread_id, actor_id='researcher', task_id='edit_workspace')
        return self.graph.invoke(
            {'messages': [AIMessage(content='', tool_calls=[copy.deepcopy(call)])]},
            self.config(thread_id),
        )

    def test_allowed_call_reaches_real_toolnode_once(self):
        thread = 'allow-thread'
        call = self.call()
        state = self.invoke(thread, call)
        self.assertEqual(state['policy_decision']['decision'], 'allow')
        self.assertIsInstance(state['messages'][-1], ToolMessage)
        self.assertEqual(self.executions, [('read', str(self.root / 'sample.txt'))])

        replay = self.graph.invoke(
            {'messages': [AIMessage(content='', tool_calls=[copy.deepcopy(call)])]},
            self.config(thread),
        )
        self.assertEqual(replay['policy_decision']['rule_id'], 'CALL_REPLAY')
        self.assertEqual(len(self.executions), 1)

    def test_denied_call_never_reaches_toolnode(self):
        outside = self.root.parent / 'outside.txt'
        state = self.invoke('deny-thread', self.call(path=outside))
        self.assertEqual(state['policy_decision']['rule_id'], 'P03_WORKSPACE_BOUNDARY')
        self.assertNotIsInstance(state['messages'][-1], ToolMessage)
        self.assertEqual(self.executions, [])

    def test_critical_call_interrupts_and_approved_resume_executes_once(self):
        thread = 'approval-thread'
        call = self.call(name='delete')
        state = self.invoke(thread, call)
        self.assertEqual(state['policy_decision']['decision'], 'require_review')
        self.assertIn('__interrupt__', state)
        self.assertEqual(self.executions, [])

        resumed = self.graph.invoke(
            Command(resume={'approved': True}),
            self.config(thread),
        )
        self.assertEqual(resumed['policy_decision']['decision'], 'allow')
        self.assertIsInstance(resumed['messages'][-1], ToolMessage)
        self.assertEqual(self.executions, [('delete', str(self.root / 'sample.txt'))])

    def test_rejected_resume_never_executes(self):
        thread = 'reject-thread'
        self.invoke(thread, self.call(name='delete'))
        state = self.graph.invoke(
            Command(resume={'approved': False}),
            self.config(thread),
        )
        self.assertEqual(state['policy_decision']['rule_id'], 'HUMAN_REJECTED')
        self.assertEqual(self.executions, [])

    def test_malformed_approval_response_fails_closed(self):
        thread = 'bad-response-thread'
        self.invoke(thread, self.call(name='delete'))
        state = self.graph.invoke(
            Command(resume={'approved': 'yes'}),
            self.config(thread),
        )
        self.assertEqual(state['policy_decision']['rule_id'], 'INVALID_APPROVAL_RESPONSE')
        self.assertEqual(self.executions, [])

    def test_multiple_tool_calls_fail_closed(self):
        thread = 'batch-thread'
        self.adapter.enroll(thread, actor_id='researcher', task_id='edit_workspace')
        state = self.graph.invoke(
            {'messages': [AIMessage(content='', tool_calls=[
                self.call(call_id='a'), self.call(call_id='b'),
            ])]},
            self.config(thread),
        )
        self.assertEqual(state['policy_decision']['rule_id'], 'INVALID_OR_BATCHED_TOOL_CALL')
        self.assertEqual(self.executions, [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
