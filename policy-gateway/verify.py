"""Produce a repeatable local test report and synthetic decision trace."""
import contextlib
from datetime import datetime, timezone
import io
from importlib.metadata import PackageNotFoundError, version
import json
from pathlib import Path
import platform
import re
import subprocess
import sys
import unittest

import yaml
from demo import run


def main():
    here = Path(__file__).resolve().parent
    policy_suite = unittest.defaultTestLoader.discover(str(here), pattern='test_engine.py')
    l3_suite = unittest.defaultTestLoader.discover(str(here), pattern='test_l3_controls.py')
    l3_count = l3_suite.countTestCases()
    l1_suite = unittest.defaultTestLoader.discover(str(here), pattern='test_l1_pipeline.py')
    l1_count = l1_suite.countTestCases()
    langgraph_suite = unittest.defaultTestLoader.discover(str(here), pattern='test_langgraph_adapter.py')
    langgraph_count = langgraph_suite.countTestCases()
    try:
        langgraph_version = version('langgraph')
        runtime_suite = unittest.defaultTestLoader.discover(
            str(here), pattern='test_langgraph_runtime.py'
        )
        runtime_count = runtime_suite.countTestCases()
        end_to_end_suite = unittest.defaultTestLoader.discover(
            str(here), pattern='test_langgraph_end_to_end.py'
        )
        end_to_end_count = end_to_end_suite.countTestCases()
        runtime_available = True
    except PackageNotFoundError:
        langgraph_version = None
        runtime_suite = unittest.TestSuite()
        runtime_count = 0
        end_to_end_suite = unittest.TestSuite()
        end_to_end_count = 0
        runtime_available = False
    suite = unittest.TestSuite([
        policy_suite,
        l3_suite,
        l1_suite,
        langgraph_suite,
        runtime_suite,
        end_to_end_suite,
    ])
    output = io.StringIO()
    result = unittest.TextTestRunner(stream=output, verbosity=2).run(suite)
    demo_output = io.StringIO()
    with contextlib.redirect_stdout(demo_output):
        run(here.parent / 'Политики_L1_L3_v0.1.yaml')
    import os
    environment = dict(os.environ, LAB_PYTHON=sys.executable)
    adapter = subprocess.run(
        ['node', '--test', str(here / 'dsh-adapter' / 'adapter.test.mjs')],
        capture_output=True, text=True, encoding='utf-8', env=environment,
        timeout=60,
    )
    adapter_output = adapter.stdout + adapter.stderr
    adapter_count = re.search(r'^# tests (\d+)$', adapter.stdout, re.MULTILINE)
    adapter_tests = int(adapter_count.group(1)) if adapter_count else 0
    success = result.wasSuccessful() and adapter.returncode == 0 and adapter_tests > 0
    report = {
        'generated_at_utc': datetime.now(timezone.utc).isoformat(),
        'python': platform.python_version(), 'pyyaml': yaml.__version__,
        'platform': platform.platform(), 'tests_run': result.testsRun,
        'failures': len(result.failures), 'errors': len(result.errors),
        'skipped': [(str(test), reason) for test, reason in result.skipped],
        'passed': success,
        'l1_pipeline': {
            'tests_run': l1_count,
            'scope': ('NeMo-compatible detector contract, RU/EN input labels and '
                      'trusted provenance binding from L1 to L3'),
        },
        'l3_controls': {
            'tests_run': l3_count,
            'scope': ('MIT AGT-derived approval/budget semantics, data-flow lattice, '
                      'egress destination allowlist and fail-closed parsing'),
        },
        'langgraph_adapter': {
            'tests_run': langgraph_count,
            'scope': 'LangGraph-shaped tool-call contract',
        },
        'langgraph_runtime': {
            'available': runtime_available,
            'version': langgraph_version,
            'tests_run': runtime_count,
            'scope': ('Real StateGraph, ToolNode, interrupt/resume and InMemorySaver; '
                      'laboratory tools have no file or network side effects'),
        },
        'langgraph_end_to_end': {
            'tests_run': end_to_end_count,
            'scope': ('Real StateGraph path L1 -> deterministic planner -> L3 -> ToolNode, '
                      'including trusted provenance and HITL resume'),
        },
        'adapter': {'tests_run': adapter_tests, 'exit_code': adapter.returncode,
                    'scope': 'Real Python worker, DSH runtime contract double; not a running DSH instance'},
        'scope': ('Synthetic policy decisions, NeMo-compatible detector adapter, DSH adapter '
                  'contract and real LangGraph L1/L3 control-flow tests; deterministic planner '
                  'only, no detector model, LLM, real DSH runtime or OS sandbox test'),
        'demo': json.loads(demo_output.getvalue()),
    }
    (here / 'test-results.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    (here / 'test-results.txt').write_text(output.getvalue(), encoding='utf-8')
    (here / 'adapter-test-results.tap').write_text(adapter_output, encoding='utf-8')
    print(f"Python L1/L3 + LangGraph tests: {result.testsRun}; failures: {len(result.failures)}; errors: {len(result.errors)}; skipped: {len(result.skipped)}")
    print(f"LangGraph runtime: {langgraph_version or 'not installed'}; runtime tests: {runtime_count}")
    print(f"Adapter contract tests: {adapter_tests}; exit code: {adapter.returncode}")
    return 0 if success else 1


if __name__ == '__main__':
    raise SystemExit(main())
