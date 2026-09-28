import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { PolicyBridge } from './bridge.mjs';
import { bindPolicyGate } from './adapter.mjs';

const directory = path.dirname(fileURLToPath(import.meta.url));
const python = process.env.LAB_PYTHON ?? 'python';
const worker = path.resolve(directory, '../worker.py');
const profile = path.resolve(directory, '../../Политики_L1_L3_v0.1.yaml');
const base = JSON.parse(execFileSync(python, ['-c',
  'import json,sys,yaml; print(json.dumps(yaml.safe_load(open(sys.argv[1],encoding="utf-8"))))', profile],
{ encoding: 'utf8', windowsHide: true }));

/** Deliberately a contract double, NOT the DSH ToolRuntime. */
function runtime(approval) {
  const listeners = [];
  const guards = [];
  let bodyCalls = 0;
  const ctx = {
    on(event, handler) {
      assert.equal(event, 'tools/pre-execute');
      listeners.push(handler);
      return () => { const i = listeners.indexOf(handler); if (i >= 0) listeners.splice(i, 1); };
    },
    tools: { guard(handler) {
      guards.push(handler);
      return () => { const i = guards.indexOf(handler); if (i >= 0) guards.splice(i, 1); };
    } },
    get(name) { return name === 'approval' ? approval : undefined; },
  };
  return {
    ctx, listeners,
    get bodyCalls() { return bodyCalls; },
    async run(exec, beforeGuard = () => {}) {
      const dispatch = i => listeners[i]
        ? listeners[i](exec, () => dispatch(i + 1)) : Promise.resolve({ kind: 'allow' });
      let decision = await dispatch(0);
      if (decision.kind === 'ask') {
        decision = (await approval?.request({ agent: exec.agent, callId: exec.callId })) === 'allowed-once'
          ? { kind: 'allow' } : { kind: 'deny', reason: 'OTHER_APPROVAL_DENIED' };
      }
      if (decision.kind !== 'allow') return decision;
      beforeGuard(exec);
      for (const guard of guards) {
        const reason = guard(exec);
        if (reason !== undefined) return { kind: 'deny', reason };
      }
      bodyCalls++;
      return { kind: 'allow' };
    },
  };
}

async function setup(t, { approval, change = () => {}, enroll = true, approvalTimeoutMs = 2000 } = {}) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'agent-policy-contract-'));
  const config = structuredClone(base);
  config.workspace.root = root;
  change(config);
  const configFile = path.join(root, 'policy.json');
  await writeFile(configFile, JSON.stringify(config));
  const bridge = new PolicyBridge({ python, worker, policy: configFile });
  const host = runtime(approval);
  const gate = bindPolicyGate(host.ctx, bridge, { approvalTimeoutMs });
  const agent = { session: { id: 'session-1', header: { cwd: root } } };
  if (enroll) gate.enroll(agent.session, { actorId: 'operator', taskId: 'edit_workspace' });
  t.after(async () => {
    gate.close();
    await bridge.close();
    gate.disposeAfterRuntimeStopped();
    await rm(root, { recursive: true, force: true });
  });
  let sequence = 0;
  const exec = (name = 'read', args = {}) => ({
    callId: `call-${++sequence}`, name, agent, signal: new AbortController().signal,
    arguments: { file_path: path.join(root, 'sample.txt'), ...args },
  });
  return { root, bridge, host, gate, agent, exec };
}

test('allowed request reaches the test body exactly once', async t => {
  const s = await setup(t);
  assert.equal((await s.host.run(s.exec())).kind, 'allow');
  assert.equal(s.host.bodyCalls, 1);
});

test('unknown tools and path escapes never reach the body', async t => {
  const s = await setup(t);
  assert.equal((await s.host.run(s.exec('bash'))).kind, 'deny');
  assert.equal((await s.host.run(s.exec('write', { file_path: path.join(s.root, '..', 'outside') }))).kind, 'deny');
  assert.equal(s.host.bodyCalls, 0);
});

test('guard denies when an earlier listener bypasses our pre-execute handler', async t => {
  const s = await setup(t);
  s.host.listeners.unshift(async () => ({ kind: 'allow' }));
  assert.equal((await s.host.run(s.exec())).reason, 'POLICY_ADMISSION_MISSING');
  assert.equal(s.host.bodyCalls, 0);
});

test('argument mutation after the gate fails the final guard', async t => {
  const s = await setup(t);
  assert.equal((await s.host.run(s.exec(), exec => { exec.arguments.file_path = path.join(s.root, 'other'); })).kind, 'deny');
  assert.equal(s.host.bodyCalls, 0);
});

test('agent supplied actor/task fields cannot enroll a session', async t => {
  const s = await setup(t, { enroll: false });
  const event = s.exec('read', { actor_id: 'operator', task_id: 'edit_workspace', approved: true });
  assert.equal((await s.host.run(event)).kind, 'deny');
  assert.equal(s.host.bodyCalls, 0);
});

test('parallel requests share a single persistent rate counter', async t => {
  const s = await setup(t);
  const results = await Promise.all(Array.from({ length: 6 }, () => s.host.run(s.exec())));
  assert.equal(results.filter(r => r.kind === 'allow').length, 5);
  assert.equal(results.filter(r => r.reason === 'P04_RATE_LIMIT').length, 1);
  assert.equal(s.host.bodyCalls, 5);
});

test('critical write uses allowed-once and a one-use policy token', async t => {
  let questions = 0;
  const s = await setup(t, {
    approval: { async request(req) { questions++; assert.equal(req.toolName, 'write'); return 'allowed-once'; } },
    change: c => c.critical_operations.push('write'),
  });
  const event = s.exec('write', { content: 'sample' });
  assert.equal((await s.host.run(event)).kind, 'allow');
  assert.equal((await s.host.run(event)).kind, 'deny');
  assert.equal(questions, 1);
  assert.equal(s.host.bodyCalls, 1);
});

test('rejected, unavailable and unexpected approvals do not execute', async t => {
  for (const outcome of ['rejected', 'unavailable', 'cancelled', 'allow']) {
    const s = await setup(t, {
      approval: { async request() { return outcome; } },
      change: c => c.critical_operations.push('write'),
    });
    assert.equal((await s.host.run(s.exec('write'))).kind, 'deny');
    assert.equal(s.host.bodyCalls, 0);
  }
});

test('approval with changed content is rejected before grant', async t => {
  let event;
  const s = await setup(t, {
    approval: { async request() { event.arguments.content = 'changed'; return 'allowed-once'; } },
    change: c => c.critical_operations.push('write'),
  });
  event = s.exec('write', { content: 'original' });
  assert.equal((await s.host.run(event)).reason, 'CALL_CHANGED');
  assert.equal(s.host.bodyCalls, 0);
});

test('absence and timeout of approval channel fail closed', async t => {
  for (const approval of [undefined, { request: () => new Promise(() => {}) }]) {
    const s = await setup(t, { approval, change: c => c.critical_operations.push('write'), approvalTimeoutMs: 30 });
    assert.equal((await s.host.run(s.exec('write'))).kind, 'deny');
    assert.equal(s.host.bodyCalls, 0);
  }
});

test('stopped worker denies instead of resetting policy state', async t => {
  const s = await setup(t);
  await s.bridge.close();
  assert.equal((await s.host.run(s.exec())).kind, 'deny');
  assert.equal(s.host.bodyCalls, 0);
});

test('invalid configuration never permits a call', async t => {
  const s = await setup(t, { change: c => { c.controls.sandbox_mode = 'danger-full-access'; } });
  assert.equal((await s.host.run(s.exec())).kind, 'deny');
  assert.equal(s.host.bodyCalls, 0);
});

test('abort after gate cannot reach the body', async t => {
  const s = await setup(t);
  const controller = new AbortController();
  const event = s.exec();
  event.signal = controller.signal;
  assert.equal((await s.host.run(event, () => controller.abort())).kind, 'deny');
  assert.equal(s.host.bodyCalls, 0);
});

test('closing adapter leaves a denial guard until runtime shutdown', async t => {
  const s = await setup(t);
  s.gate.close();
  assert.equal((await s.host.run(s.exec())).kind, 'deny');
  assert.equal(s.host.bodyCalls, 0);
});

test('another policy denial is preserved', async t => {
  const s = await setup(t);
  s.host.listeners.push(async () => ({ kind: 'deny', reason: 'OTHER_POLICY' }));
  assert.equal((await s.host.run(s.exec())).reason, 'OTHER_POLICY');
  assert.equal(s.host.bodyCalls, 0);
});

test('session context cannot be re-enrolled or changed silently', async t => {
  const s = await setup(t);
  assert.throws(() => s.gate.enroll(s.agent.session, { actorId: 'other', taskId: 'other' }));
  s.agent.session.header.cwd = path.dirname(s.root);
  assert.equal((await s.host.run(s.exec())).kind, 'deny');
  assert.equal(s.host.bodyCalls, 0);
});
