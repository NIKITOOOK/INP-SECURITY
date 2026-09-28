import copy
from pathlib import Path
import tempfile
import unittest

from engine import Engine, load_policy
from langgraph_adapter import LangGraphPolicyAdapter, SessionEnrollmentError


POLICY = Path(__file__).resolve().parent.parent / 'Политики_L1_L3_v0.1.yaml'


class LangGraphAdapterContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'workspace'
        self.root.mkdir()
        config = load_policy(POLICY)
        config['workspace']['root'] = str(self.root)
        self.engine = Engine(config)
        self.adapter = LangGraphPolicyAdapter(self.engine)
        self.adapter.enroll('thread-1', actor_id='researcher', task_id='edit_workspace')
        self.executions = []

    def call(self, **changes):
        call = {
            'id': 'call-1',
            'name': 'read',
            'args': {'file_path': str(self.root / 'sample.txt')},
            'type': 'tool_call',
        }
        call.update(changes)
        return call

    def body(self, args):
        self.executions.append(copy.deepcopy(args))
        return 'executed'

    def test_allowed_call_reaches_body_once_and_replay_is_denied(self):
        decision, output = self.adapter.guarded_execute('thread-1', self.call(), self.body)
        self.assertEqual((decision['decision'], output), ('allow', 'executed'))
        replay, output = self.adapter.guarded_execute('thread-1', self.call(), self.body)
        self.assertEqual((replay['rule_id'], output), ('CALL_REPLAY', None))
        self.assertEqual(len(self.executions), 1)

    def test_outside_workspace_never_reaches_body(self):
        call = self.call(args={'file_path': str(self.root.parent / 'secret.txt')})
        decision, output = self.adapter.guarded_execute('thread-1', call, self.body)
        self.assertEqual((decision['rule_id'], output), ('P03_WORKSPACE_BOUNDARY', None))
        self.assertEqual(self.executions, [])

    def test_unknown_tool_is_denied_by_allowlist(self):
        decision, output = self.adapter.guarded_execute(
            'thread-1', self.call(name='send_email', args={'to': 'outside@example.invalid'}), self.body
        )
        self.assertEqual((decision['rule_id'], output), ('P02_TOOL_ALLOWLIST', None))

    def test_model_cannot_supply_task_identity(self):
        call = self.call(args={'file_path': str(self.root / 'x'), 'task_id': 'administrator'})
        decision = self.adapter.evaluate('thread-1', call)
        self.assertEqual(decision['decision'], 'allow')
        with self.assertRaises(SessionEnrollmentError):
            self.adapter.enroll('thread-1', actor_id='researcher', task_id='administrator')

    def test_unenrolled_or_malformed_call_fails_closed(self):
        self.assertEqual(self.adapter.evaluate('unknown', self.call())['decision'], 'deny')
        self.assertEqual(self.adapter.evaluate('thread-1', {'id': 'x'})['decision'], 'deny')
        self.assertEqual(self.adapter.evaluate('thread-1', self.call(extra=True))['decision'], 'deny')

    def test_interrupt_resume_approval_is_bound_and_one_time(self):
        call = self.call(name='delete', args={'file_path': str(self.root / 'old.txt')})
        interrupted, output = self.adapter.guarded_execute('thread-1', call, self.body)
        self.assertEqual((interrupted['decision'], output), ('require_review', None))
        token = self.adapter.operator_approve(interrupted['pending_id'])
        resumed, output = self.adapter.guarded_execute(
            'thread-1', call, self.body, approval_token=token
        )
        self.assertEqual((resumed['decision'], output), ('allow', 'executed'))
        replay, output = self.adapter.guarded_execute(
            'thread-1', call, self.body, approval_token=token
        )
        self.assertEqual((replay['rule_id'], output), ('CALL_REPLAY', None))
        self.assertEqual(len(self.executions), 1)

    def test_changed_arguments_invalidate_approval(self):
        call = self.call(name='delete', args={'file_path': str(self.root / 'old.txt')})
        pending = self.adapter.evaluate('thread-1', call)
        token = self.adapter.operator_approve(pending['pending_id'])
        changed = self.call(name='delete', args={'file_path': str(self.root / 'other.txt')})
        self.assertEqual(
            self.adapter.evaluate('thread-1', changed, approval_token=token)['rule_id'],
            'APPROVAL_INVALID',
        )

    def test_missing_approval_channel_denies_critical_call(self):
        call = self.call(name='delete', args={'file_path': str(self.root / 'old.txt')})
        decision = self.adapter.evaluate('thread-1', call, approval_available=False)
        self.assertEqual(decision['rule_id'], 'APPROVAL_UNAVAILABLE')


if __name__ == '__main__':
    unittest.main(verbosity=2)
