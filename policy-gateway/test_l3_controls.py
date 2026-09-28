import unittest

from l3.agt_controls import (
    approval_verdict, budget_verdict, egress_verdict, host_of, ifc_verdict,
)


class AGTControlAdapterTests(unittest.TestCase):
    def test_budget_under_and_at_limit(self):
        thresholds = {'tool_call_count': 5, 'elapsed_seconds': 60}
        self.assertIsNone(budget_verdict({'tool_call_count': 4}, thresholds))
        result = budget_verdict({'tool_call_count': 5}, thresholds)
        self.assertEqual(result['reason'], 'budget_tool_calls_exceeded')

    def test_budget_malformed_counter_fails_closed(self):
        result = budget_verdict({'token_count': '999'}, {'token_count': 1000})
        self.assertEqual(result['reason'], 'budget_counter_invalid')

    def test_approval_maps_escalation_and_rejects_missing_resolver(self):
        self.assertEqual(
            approval_verdict(True, ['administrator'])['decision'], 'require_review'
        )
        self.assertEqual(approval_verdict(True, [])['decision'], 'deny')

    def test_host_parser_rejects_credentials(self):
        self.assertEqual(host_of('https://API.Example.Test:443/v1'), 'api.example.test')
        self.assertIsNone(host_of('https://user:secret@api.example.test/v1'))

    def test_egress_exact_wildcard_and_denial(self):
        allowed = ['api.example.test', '*.trusted.example.test']
        self.assertIsNone(egress_verdict({'url': 'https://api.example.test/v1'}, allowed))
        self.assertIsNone(egress_verdict({'host': 'a.trusted.example.test'}, allowed))
        self.assertEqual(
            egress_verdict({'url': 'https://attacker.example/'}, allowed)['reason'],
            'egress_destination_not_allowed',
        )
        self.assertEqual(egress_verdict({}, allowed)['decision'], 'deny')

    def test_ifc_no_write_down_and_unknown_label(self):
        lattice = {'public': ['public'], 'protected': ['public', 'protected']}
        self.assertIsNone(ifc_verdict('protected', ['class:public'], lattice, 'protected'))
        self.assertEqual(
            ifc_verdict('public', ['class:protected'], lattice, 'protected')['reason'],
            'ifc_clearance_violation',
        )
        self.assertEqual(
            ifc_verdict('protected', ['class:secret'], lattice, 'protected')['reason'],
            'ifc_label_unknown',
        )


if __name__ == '__main__':
    unittest.main(verbosity=2)

