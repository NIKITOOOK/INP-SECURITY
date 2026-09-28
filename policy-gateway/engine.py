"""Research policy simulator. Does not execute tools or provide OS isolation."""
from __future__ import annotations

import copy
import hashlib
import json
import math
from pathlib import Path
import re
import secrets
import time
from collections import deque
from typing import Any

import yaml

from l3.agt_controls import approval_verdict, budget_verdict, egress_verdict, ifc_verdict


class PolicyError(ValueError):
    pass


class UniqueLoader(yaml.SafeLoader):
    pass


def unique_mapping(loader, node, deep=False):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str) or key in result:
            raise PolicyError('YAML keys must be unique strings')
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping)


def fields(value, required):
    if not isinstance(value, dict) or set(value) != set(required):
        raise PolicyError(f'Expected exactly these fields: {", ".join(required)}')


def strings(value, nonempty=True):
    if not isinstance(value, list) or (nonempty and not value):
        raise PolicyError('Expected a nonempty list')
    if any(not isinstance(x, str) or not x for x in value) or len(set(value)) != len(value):
        raise PolicyError('Expected unique nonempty strings')


def positive_integer(value):
    if type(value) is not int or value <= 0:
        raise PolicyError('Expected a positive integer')


RULES = {
    'P01_INPUT_PROVENANCE': ('input', 'input.received', ['origin_any']),
    'P02_TOOL_ALLOWLIST': ('system', 'tool.requested', ['permission_match']),
    'P03_WORKSPACE_BOUNDARY': ('system', 'tool.requested', ['operation_any', 'canonical_target_inside_workspace']),
    'P04_RATE_LIMIT': ('system', 'tool.requested', ['rate_limit_exceeded']),
    'P05_CRITICAL_APPROVAL': ('system', 'tool.requested', ['operation_in_critical_operations']),
    'N03_DATA_FLOW': ('system', 'tool.requested',
                      ['sink_clearance_dominates_source', 'destination_in_allowlist']),
    'N04_STOP': ('system', 'tool.requested', ['session_is_stopped']),
    'N05_POLICY_INTEGRITY': ('system', 'tool.requested', ['operation_is_policy_modify']),
}


def validate(config):
    fields(config, ['schema_version', 'profile', 'policy_version', 'layers', 'controls',
                    'defaults', 'input_limits', 'tool_permissions', 'workspace',
                    'memory', 'rate_limits', 'budgets', 'approval', 'data_flow', 'egress',
                    'critical_operations', 'rules'])
    if str(config['schema_version']) != '0.4':
        raise PolicyError('Unsupported schema_version')
    for key in ('profile', 'policy_version'):
        if not isinstance(config[key], str) or not config[key].strip():
            raise PolicyError(f'{key} must be a nonempty string')
    fields(config['layers'], ['input', 'model', 'system'])
    fields(config['controls'], ['tool_allowlist', 'workspace_boundary', 'rate_limit',
                                'budget_guard', 'data_flow', 'egress_allowlist',
                                'human_approval', 'memory_boundary', 'session_stop',
                                'sandbox_mode'])
    for values in (config['layers'], config['controls']):
        for key, value in values.items():
            choices = ('read-only', 'workspace-write') if key == 'sandbox_mode' else ('enabled', 'disabled')
            if value not in choices:
                raise PolicyError(f'Invalid switch: {key}')
    if config['layers']['model'] != 'disabled':
        raise PolicyError('L2 is not implemented')
    expected_defaults = dict(tool_decision='deny', on_policy_error='deny',
                             on_approval_unavailable='deny', source_trust='untrusted')
    if config['defaults'] != expected_defaults:
        raise PolicyError('Unsupported or permissive defaults')
    fields(config['input_limits'], ['max_chars'])
    positive_integer(config['input_limits']['max_chars'])
    fields(config['workspace'], ['root', 'resolve_symlinks'])
    root = config['workspace']['root']
    if not isinstance(root, str) or not Path(root).is_absolute():
        raise PolicyError('workspace.root must be an absolute path for this OS')
    if config['workspace']['resolve_symlinks'] is not True:
        raise PolicyError('resolve_symlinks must be true')
    if not isinstance(config['tool_permissions'], list) or not config['tool_permissions']:
        raise PolicyError('tool_permissions must be nonempty')
    identities = set()
    for entry in config['tool_permissions']:
        fields(entry, ['task', 'tool', 'operations'])
        if any(not isinstance(entry[k], str) or not entry[k] for k in ('task', 'tool')):
            raise PolicyError('Invalid permission identity')
        strings(entry['operations'])
        identity = (entry['task'], entry['tool'])
        if identity in identities:
            raise PolicyError('Duplicate permission entry')
        identities.add(identity)
    fields(config['memory'], ['operations', 'permissions'])
    strings(config['memory']['operations'])
    if set(config['memory']['operations']) != {'memory.read', 'memory.write'}:
        raise PolicyError('Memory operations must cover read and write')
    if not isinstance(config['memory']['permissions'], list) or not config['memory']['permissions']:
        raise PolicyError('Memory permissions must be nonempty')
    memory_identities = set()
    for entry in config['memory']['permissions']:
        fields(entry, ['task', 'tool', 'operation', 'key_prefixes'])
        identity = (entry['task'], entry['tool'], entry['operation'])
        if any(not isinstance(value, str) or not value for value in identity):
            raise PolicyError('Invalid memory permission identity')
        if identity in memory_identities or entry['operation'] not in config['memory']['operations']:
            raise PolicyError('Invalid or duplicate memory permission')
        memory_identities.add(identity)
        strings(entry['key_prefixes'])
        if any(
            not prefix.endswith('/') or prefix.startswith('/') or '\\' in prefix or '\x00' in prefix
            or any(part in {'', '.', '..'} for part in prefix[:-1].split('/'))
            for prefix in entry['key_prefixes']
        ):
            raise PolicyError('Invalid memory key prefix')
    permitted_memory = {
        (entry['task'], entry['tool'], operation)
        for entry in config['tool_permissions']
        for operation in entry['operations']
        if operation in config['memory']['operations']
    }
    if memory_identities != permitted_memory:
        raise PolicyError('Every memory permission requires exactly one namespace rule')
    if not isinstance(config['rate_limits'], list):
        raise PolicyError('rate_limits must be a list')
    limited = set()
    for limit in config['rate_limits']:
        fields(limit, ['tool', 'scope', 'window_seconds', 'max_calls'])
        if not isinstance(limit['tool'], str) or not limit['tool'] or limit['tool'] in limited:
            raise PolicyError('Invalid or duplicate rate limit')
        limited.add(limit['tool'])
        strings(limit['scope'])
        if not set(limit['scope']) <= {'actor_id', 'task_id', 'session_id'}:
            raise PolicyError('Unsupported rate scope')
        positive_integer(limit['window_seconds'])
        positive_integer(limit['max_calls'])
    fields(config['budgets'], ['scope', 'tool_call_count', 'elapsed_seconds'])
    strings(config['budgets']['scope'])
    if not set(config['budgets']['scope']) <= {'actor_id', 'task_id', 'session_id'}:
        raise PolicyError('Unsupported budget scope')
    positive_integer(config['budgets']['tool_call_count'])
    if not isinstance(config['budgets']['elapsed_seconds'], (int, float)) or isinstance(
        config['budgets']['elapsed_seconds'], bool
    ) or not math.isfinite(config['budgets']['elapsed_seconds']) or config['budgets']['elapsed_seconds'] <= 0:
        raise PolicyError('Invalid elapsed budget')
    fields(config['approval'], ['timeout_seconds', 'max_outstanding_per_session', 'approvers'])
    positive_integer(config['approval']['timeout_seconds'])
    positive_integer(config['approval']['max_outstanding_per_session'])
    strings(config['approval']['approvers'])
    fields(config['data_flow'], ['default_source_label', 'lattice', 'sink_clearance'])
    lattice = config['data_flow']['lattice']
    if not isinstance(lattice, dict) or not lattice:
        raise PolicyError('Invalid data-flow lattice')
    for label, dominated in lattice.items():
        if not isinstance(label, str) or not label:
            raise PolicyError('Invalid data-flow label')
        strings(dominated)
        if label not in dominated or not set(dominated) <= set(lattice):
            raise PolicyError('Invalid data-flow dominance relation')
    if config['data_flow']['default_source_label'] not in lattice:
        raise PolicyError('Unknown default source label')
    sinks = config['data_flow']['sink_clearance']
    if not isinstance(sinks, dict) or any(
        not isinstance(tool, str) or not tool or clearance not in lattice
        for tool, clearance in sinks.items()
    ):
        raise PolicyError('Invalid sink clearances')
    permission_tools = {entry['tool'] for entry in config['tool_permissions']}
    if set(sinks) != permission_tools:
        raise PolicyError('Every permitted tool requires exactly one sink clearance')
    fields(config['egress'], ['operations', 'tool_allowlists'])
    strings(config['egress']['operations'])
    if not isinstance(config['egress']['tool_allowlists'], list):
        raise PolicyError('tool_allowlists must be a list')
    egress_tools = set()
    for entry in config['egress']['tool_allowlists']:
        fields(entry, ['tool', 'destinations'])
        if not isinstance(entry['tool'], str) or not entry['tool'] or entry['tool'] in egress_tools:
            raise PolicyError('Invalid or duplicate egress tool')
        egress_tools.add(entry['tool'])
        strings(entry['destinations'])
    tools_with_egress = {
        entry['tool'] for entry in config['tool_permissions']
        if set(entry['operations']) & set(config['egress']['operations'])
    }
    if egress_tools != tools_with_egress:
        raise PolicyError('Every egress tool requires exactly one destination allowlist')
    strings(config['critical_operations'])
    if not {'delete', 'network.send', 'policy.modify'} <= set(config['critical_operations']):
        raise PolicyError('Mandatory critical operations are missing')
    if not isinstance(config['rules'], list) or len(config['rules']) != len(RULES):
        raise PolicyError('Every supported rule is required exactly once')
    seen = set()
    for rule in config['rules']:
        if not isinstance(rule, dict):
            raise PolicyError('Rule must be a mapping')
        identifier = rule.get('id')
        if identifier not in RULES or identifier in seen:
            raise PolicyError('Unknown or duplicate rule')
        seen.add(identifier)
        layer, event, conditions = RULES[identifier]
        is_input = layer == 'input'
        fields(rule, ['id', 'layer', 'event', 'when', 'effect' if is_input else 'decision'])
        if (rule['layer'], rule['event']) != (layer, event):
            raise PolicyError('Unsupported rule routing')
        fields(rule['when'], conditions)
        if is_input:
            strings(rule['when']['origin_any'])
            if not set(rule['when']['origin_any']) <= {'web', 'file', 'tool', 'memory'}:
                raise PolicyError('Unsupported input origin')
            fields(rule['effect'], ['add_labels', 'detect_prompt_injection'])
            if rule['effect']['add_labels'] != ['untrusted'] or type(rule['effect']['detect_prompt_injection']) is not bool:
                raise PolicyError('Unsupported input effect')
        else:
            expected = 'require_review' if identifier == 'P05_CRITICAL_APPROVAL' else 'deny'
            if rule['decision'] != expected:
                raise PolicyError('Unsupported decision for rule')
            for key, value in rule['when'].items():
                if key == 'operation_any':
                    strings(value)
                    if not {'read', 'write', 'delete'} <= set(value):
                        raise PolicyError('Workspace must cover read/write/delete')
                elif value is not {
                    'permission_match': False,
                    'canonical_target_inside_workspace': False,
                    'rate_limit_exceeded': True,
                    'operation_in_critical_operations': True,
                    'sink_clearance_dominates_source': False,
                    'destination_in_allowlist': False,
                    'session_is_stopped': True,
                    'operation_is_policy_modify': True,
                }[key]:
                    raise PolicyError('Unsupported condition value')
    return config


def load_policy(path):
    try:
        with Path(path).open(encoding='utf-8') as stream:
            return validate(yaml.load(stream, Loader=UniqueLoader))
    except (OSError, yaml.YAMLError, TypeError, ValueError, RecursionError) as exc:
        raise PolicyError(str(exc)) from exc


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
                                     allow_nan=False, separators=(',', ':')).encode()).hexdigest()


class Engine:
    """Trusted caller supplies identity/action classification; events are not an API boundary."""
    def __init__(self, config, clock=time.monotonic):
        self.config = copy.deepcopy(validate(config))
        self.rules = {r['id']: r for r in self.config['rules']}
        self.policy_digest = digest(self.config)
        self.clock = clock
        self.previous_time = -math.inf
        self.counters = {}
        self.budget_state = {}
        self.pending = {}
        self.pending_by_call = {}
        self.grants = {}
        self.completed = set()
        self.stopped_sessions = set()

    def _time(self):
        now = self.clock()
        if not isinstance(now, (int, float)) or not math.isfinite(now) or now < self.previous_time:
            raise PolicyError('Clock must be finite and monotonic')
        self.previous_time = now
        return now

    def _result(self, decision, rule, **extra):
        return dict(decision=decision, rule_id=rule, policy_version=self.config['policy_version'],
                    policy_digest=self.policy_digest, **extra)

    def check_input(self, event):
        try:
            fields(event, ['event_id', 'kind', 'origin', 'text'])
            if event['kind'] != 'input.received' or event['origin'] not in {'user', 'model', 'system', 'web', 'file', 'tool', 'memory'}:
                raise PolicyError('Invalid input event')
            if not isinstance(event['text'], str) or not isinstance(event['event_id'], str):
                raise PolicyError('Invalid input data')
            if len(event['text']) > self.config['input_limits']['max_chars']:
                return self._result('deny', 'N01_INPUT_VALIDATION', labels=['untrusted'])
            if self.config['layers']['input'] == 'disabled':
                return self._result('unchecked', 'L1_DISABLED', labels=['untrusted'])
            rule = self.rules['P01_INPUT_PROVENANCE']
            labels = list(rule['effect']['add_labels']) if event['origin'] in rule['when']['origin_any'] else []
            # Demonstration heuristic, NOT a reliable injection classifier.
            if rule['effect']['detect_prompt_injection'] and re.search(
                r'ignore\s+(all\s+)?(previous\s+)?instructions|игнорируй\s+(все\s+)?(предыдущие\s+)?инструкции',
                event['text'], re.IGNORECASE):
                labels.append('prompt_injection_suspected')
            return self._result('annotate', rule['id'], labels=labels)
        except (ValueError, TypeError):
            return self._result('deny', 'INVALID_INPUT')

    def approve(self, pending_id):
        """Administrator simulation only. Must never be exposed to the agent."""
        now = self._time()
        self._prune_approvals(now)
        record = self._drop_pending(pending_id)
        if record is None:
            raise PolicyError('Unknown, consumed or expired pending request')
        token = secrets.token_urlsafe(24)
        self.grants[token] = record
        return token

    def _drop_pending(self, pending_id):
        record = self.pending.pop(pending_id, None)
        if record is not None and self.pending_by_call.get(record[3]) == pending_id:
            del self.pending_by_call[record[3]]
        return record

    def _prune_approvals(self, now):
        for pending_id, record in list(self.pending.items()):
            if record[1] <= now:
                self._drop_pending(pending_id)
        for token, record in list(self.grants.items()):
            if record[1] <= now:
                del self.grants[token]

    def stop_session(self, session_id):
        """Trusted control-plane simulation; never expose this method as a model tool."""
        if not isinstance(session_id, str) or not session_id:
            raise PolicyError('Invalid session_id')
        self.stopped_sessions.add(session_id)
        pending = [key for key, record in self.pending.items() if record[2] == session_id]
        grants = [key for key, record in self.grants.items() if record[2] == session_id]
        for key in pending:
            self._drop_pending(key)
        for key in grants:
            del self.grants[key]
        return {'session_id': session_id, 'pending_cancelled': len(pending),
                'grants_cancelled': len(grants)}

    def decide(self, event, approval_token=None, approval_available=True):
        try:
            return self._decide(event, approval_token, approval_available)
        except (ValueError, TypeError, OSError, RuntimeError, RecursionError):
            return self._result('deny', 'INVALID_EVENT_OR_STATE')

    def _decide(self, event, token, approval_available):
        fields(event, ['kind', 'call_id', 'session_id', 'task_id', 'actor_id',
                       'tool_name', 'operation', 'arguments', 'source_event_ids',
                       'data_labels'])
        if event['kind'] != 'tool.requested' or not isinstance(event['arguments'], dict):
            raise PolicyError('Invalid event')
        if any(not isinstance(event[k], str) or not event[k] for k in (
                'kind', 'call_id', 'session_id', 'task_id', 'actor_id', 'tool_name', 'operation')):
            raise PolicyError('Invalid event identity')
        strings(event['source_event_ids'], nonempty=False)
        strings(event['data_labels'], nonempty=False)
        if not event['source_event_ids'] and not {'unknown', 'untrusted'} <= set(event['data_labels']):
            raise PolicyError('Unlinked tool requests must remain unknown and untrusted')
        now = self._time()
        fingerprint = digest({'event': event, 'policy': self.policy_digest})
        call = (event['session_id'], event['call_id'])
        if call in self.completed:
            return self._result('deny', 'CALL_REPLAY')
        c = self.config
        if c['layers']['system'] == 'disabled':
            return self._result('deny', 'L3_DISABLED')
        if c['controls']['session_stop'] != 'enabled':
            return self._result('deny', 'SESSION_STOP_GATE_DISABLED')
        if event['session_id'] in self.stopped_sessions:
            return self._result('deny', 'N04_STOP')
        self._prune_approvals(now)
        if c['controls']['tool_allowlist'] != 'enabled':
            return self._result('deny', 'PERMISSION_GATE_DISABLED')
        permitted = any(p['task'] == event['task_id'] and p['tool'] == event['tool_name']
                        and event['operation'] in p['operations'] for p in c['tool_permissions'])
        if not permitted:
            return self._result('deny', 'P02_TOOL_ALLOWLIST')
        op = event['operation']
        if op == 'policy.modify':
            return self._result('deny', 'N05_POLICY_INTEGRITY')
        if op in c['memory']['operations']:
            if c['controls']['memory_boundary'] != 'enabled':
                return self._result('deny', 'MEMORY_GATE_DISABLED')
            key = event['arguments'].get('key')
            if (
                not isinstance(key, str) or not key or key.startswith('/')
                or '\\' in key or '\x00' in key
                or any(part in {'', '.', '..'} for part in key.split('/'))
            ):
                return self._result('deny', 'P02_TOOL_ALLOWLIST',
                                    reason='memory_key_invalid')
            permission = next(
                entry for entry in c['memory']['permissions']
                if (entry['task'], entry['tool'], entry['operation'])
                == (event['task_id'], event['tool_name'], op)
            )
            if not any(key.startswith(prefix) for prefix in permission['key_prefixes']):
                return self._result('deny', 'P02_TOOL_ALLOWLIST',
                                    reason='memory_namespace_not_allowed')
        if op in self.rules['P03_WORKSPACE_BOUNDARY']['when']['operation_any']:
            if c['controls']['workspace_boundary'] != 'enabled':
                return self._result('deny', 'WORKSPACE_GATE_DISABLED')
            path = event['arguments'].get('path')
            if not isinstance(path, str) or not path or '\x00' in path:
                return self._result('deny', 'P03_WORKSPACE_BOUNDARY')
            target = Path(path)
            if not target.is_absolute():
                return self._result('deny', 'P03_WORKSPACE_BOUNDARY')
            # Reject Windows alternate data streams / extended device paths.
            if ':' in str(target)[2:] or str(target).startswith(('\\\\?\\', '\\\\.\\')):
                return self._result('deny', 'P03_WORKSPACE_BOUNDARY')
            root = Path(c['workspace']['root']).resolve()
            resolved = target.resolve()
            if not resolved.is_relative_to(root) or (op == 'delete' and resolved == root):
                return self._result('deny', 'P03_WORKSPACE_BOUNDARY')
        if c['controls']['sandbox_mode'] == 'read-only' and op in {'write', 'delete'}:
            return self._result('deny', 'SANDBOX_READ_ONLY')
        rate = next((r for r in c['rate_limits'] if r['tool'] == event['tool_name']), None)
        queue = None
        if rate and c['controls']['rate_limit'] == 'enabled':
            key = (event['tool_name'], *(event[k] for k in rate['scope']))
            queue = self.counters.setdefault(key, deque())
            while queue and queue[0] <= now - rate['window_seconds']:
                queue.popleft()
            if len(queue) >= rate['max_calls']:
                return self._result('deny', 'P04_RATE_LIMIT', retry_after=queue[0] + rate['window_seconds'] - now)
        budget_key = tuple(event[key] for key in c['budgets']['scope'])
        budget = self.budget_state.setdefault(
            budget_key, {'tool_call_count': 0, 'started_at': now}
        )
        if c['controls']['budget_guard'] == 'enabled':
            budget_result = budget_verdict(
                {
                    'tool_call_count': budget['tool_call_count'],
                    'elapsed_seconds': now - budget['started_at'],
                },
                {
                    'tool_call_count': c['budgets']['tool_call_count'],
                    'elapsed_seconds': c['budgets']['elapsed_seconds'],
                },
            )
            if budget_result is not None:
                return self._result('deny', 'P04_RATE_LIMIT',
                                    control='budget', reason=budget_result['reason'])
        if c['controls']['data_flow'] != 'enabled':
            return self._result('deny', 'DATA_FLOW_GATE_DISABLED')
        flow_result = ifc_verdict(
            c['data_flow']['sink_clearance'][event['tool_name']],
            event['data_labels'], c['data_flow']['lattice'],
            c['data_flow']['default_source_label'],
        )
        if flow_result is not None:
            return self._result('deny', 'N03_DATA_FLOW', reason=flow_result['reason'])
        if op in c['egress']['operations']:
            if c['controls']['egress_allowlist'] != 'enabled':
                return self._result('deny', 'EGRESS_GATE_DISABLED')
            allowlist = next(
                entry['destinations'] for entry in c['egress']['tool_allowlists']
                if entry['tool'] == event['tool_name']
            )
            egress_result = egress_verdict(event['arguments'], allowlist)
            if egress_result is not None:
                return self._result('deny', 'N03_DATA_FLOW', reason=egress_result['reason'])
        if op in c['critical_operations']:
            if c['controls']['human_approval'] != 'enabled' or not approval_available:
                return self._result('deny', 'APPROVAL_UNAVAILABLE')
            if token is None:
                escalation = approval_verdict(True, c['approval']['approvers'])
                if escalation is None or escalation['decision'] != 'require_review':
                    return self._result('deny', 'APPROVAL_UNAVAILABLE')
                previous_id = self.pending_by_call.get(call)
                if previous_id is not None:
                    previous = self.pending.get(previous_id)
                    if previous is not None and previous[0] == fingerprint:
                        return self._result(
                            'require_review', 'P05_CRITICAL_APPROVAL',
                            pending_id=previous_id, approvers=escalation['approvers'],
                        )
                    self._drop_pending(previous_id)
                outstanding = sum(
                    record[2] == event['session_id']
                    for record in (*self.pending.values(), *self.grants.values())
                )
                if outstanding >= c['approval']['max_outstanding_per_session']:
                    return self._result('deny', 'APPROVAL_QUEUE_LIMIT')
                pending = secrets.token_urlsafe(24)
                self.pending[pending] = (
                    fingerprint, now + c['approval']['timeout_seconds'],
                    event['session_id'], call,
                )
                self.pending_by_call[call] = pending
                return self._result('require_review', 'P05_CRITICAL_APPROVAL',
                                    pending_id=pending, approvers=escalation['approvers'])
            grant = self.grants.pop(token, None)
            if grant is None or grant[0] != fingerprint or grant[1] <= now:
                return self._result('deny', 'APPROVAL_INVALID')
        elif token is not None:
            return self._result('deny', 'UNEXPECTED_APPROVAL')
        if queue is not None:
            queue.append(now)
        budget['tool_call_count'] += 1
        self.completed.add(call)
        return self._result('allow', 'EXPLICIT_PERMISSION')


def audit_record(event, result):
    """Only identifiers and decisions: no input text, paths, arguments or approval tokens."""
    return {**{k: event.get(k) for k in ('call_id', 'session_id', 'task_id')},
            **{k: result[k] for k in ('decision', 'rule_id', 'policy_version', 'policy_digest')}}
