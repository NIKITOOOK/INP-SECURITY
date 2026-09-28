import path from 'node:path';
import { createHash } from 'node:crypto';

const deny = reason => ({ kind: 'deny', reason });
const cancelled = () => ({ kind: 'cancel' });

// Names and file_path are confirmed in DSH packages/fs/tool-fs/src/*.ts.
const FILE_TOOLS = new Map([
  ['read', { tool: 'file.read', operation: 'read' }],
  ['write', { tool: 'file.write', operation: 'write' }],
  ['edit', { tool: 'file.write', operation: 'write' }],
]);

function fingerprint(value) {
  return createHash('sha256').update(JSON.stringify(value)).digest('hex');
}

/** Host-side adapter; not yet packaged as an installable Cordis plugin. */
export function bindPolicyGate(ctx, bridge, { approvalTimeoutMs = 60000 } = {}) {
  const sessions = new WeakMap();
  const authorized = new WeakMap();
  let live = true;

  // This registration is for trusted host code, never an LLM tool.
  function enroll(session, { actorId, taskId }) {
    if (sessions.has(session)) throw new Error('SESSION_ALREADY_PINNED');
    if (!session?.id || !path.isAbsolute(session?.header?.cwd ?? '') || !actorId || !taskId) {
      throw new Error('INVALID_SESSION_CONTEXT');
    }
    sessions.set(session, Object.freeze({
      session_id: String(session.id), actor_id: actorId, task_id: taskId,
      cwd: session.header.cwd,
    }));
  }

  function convert(exec) {
    const session = exec.agent?.session;
    const owner = session && sessions.get(session);
    if (!owner || String(session.id) !== owner.session_id || session.header.cwd !== owner.cwd) {
      throw new Error('UNENROLLED_OR_CHANGED_SESSION');
    }
    const mapping = FILE_TOOLS.get(exec.name);
    if (!mapping) throw new Error('UNMAPPED_TOOL');
    const args = exec.arguments;
    if (!args || typeof args !== 'object' || Array.isArray(args) || typeof args.file_path !== 'string' || !args.file_path.trim()) {
      throw new Error('INVALID_FILE_ARGUMENTS');
    }
    // First integration supports absolute local paths only; remote fs is out of scope.
    if (!path.isAbsolute(args.file_path)) throw new Error('ABSOLUTE_PATH_REQUIRED');
    if (args.sandbox_permissions === 'require_escalated') throw new Error('ESCALATION_NOT_SUPPORTED');
    if (typeof exec.callId !== 'string' || !exec.callId) throw new Error('INVALID_CALL_ID');
    return {
      kind: 'tool.requested', call_id: exec.callId, session_id: owner.session_id,
      task_id: owner.task_id, actor_id: owner.actor_id,
      tool_name: mapping.tool, operation: mapping.operation,
      // Keep all original arguments for the approval fingerprint; derive path ourselves.
      arguments: { path: args.file_path, original_arguments: structuredClone(args) },
      // DSH input provenance is not wired yet; fail conservatively instead of
      // accepting model-provided labels.
      source_event_ids: [], data_labels: ['unknown', 'untrusted'],
    };
  }

  async function ask(exec) {
    const service = ctx.get('approval');
    if (!service) return 'unavailable';
    const controller = new AbortController();
    const signal = AbortSignal.any([exec.signal, controller.signal]);
    let timer;
    let onAbort;
    const expired = new Promise(resolve => {
      onAbort = () => resolve('cancelled');
      exec.signal.addEventListener('abort', onAbort, { once: true });
      if (exec.signal.aborted) resolve('cancelled');
      timer = setTimeout(() => { controller.abort(); resolve('unavailable'); }, approvalTimeoutMs);
    });
    try {
      return await Promise.race([
        Promise.resolve().then(() => service.request({
          agent: exec.agent, toolName: exec.name, callId: exec.callId,
          reason: 'Policy P05 requires confirmation for this exact call.', signal,
        })).catch(() => 'unavailable'),
        expired,
      ]);
    } finally {
      clearTimeout(timer);
      exec.signal.removeEventListener('abort', onAbort);
    }
  }

  async function before(exec, next) {
    authorized.delete(exec);
    try {
      if (!live) return deny('POLICY_GATE_CLOSED');
      if (exec.signal.aborted) return cancelled();
      const event = convert(exec);
      const initial = fingerprint(event);
      const downstream = await next();
      if (!downstream || !['allow', 'deny', 'cancel', 'ask'].includes(downstream.kind)) {
        return deny('INVALID_DOWNSTREAM_DECISION');
      }
      if (downstream.kind === 'deny' || downstream.kind === 'cancel') return downstream;
      if (fingerprint(convert(exec)) !== initial) return deny('CALL_CHANGED');
      let result = await bridge.request('decide', { event, approval_token: null });
      if (result.decision === 'require_review') {
        const outcome = await ask(exec);
        if (exec.signal.aborted) return cancelled();
        if (outcome !== 'allowed-once') return deny('APPROVAL_NOT_GRANTED');
        if (fingerprint(convert(exec)) !== initial) return deny('CALL_CHANGED');
        const { token } = await bridge.request('approve', { pending_id: result.pending_id });
        result = await bridge.request('decide', { event, approval_token: token });
      }
      if (exec.signal.aborted) return cancelled();
      if (result.decision !== 'allow') return deny(result.rule_id ?? 'INVALID_POLICY_DECISION');
      if (fingerprint(convert(exec)) !== initial) return deny('CALL_CHANGED');
      authorized.set(exec, { fingerprint: initial, agent: exec.agent });
      return downstream; // Preserve an independent downstream ask as well.
    } catch {
      return deny('POLICY_GATE_ERROR');
    }
  }

  function guard(exec) {
    const mark = authorized.get(exec);
    authorized.delete(exec); // Single-use gate admission.
    try {
      if (!live || exec.signal.aborted || !mark || mark.agent !== exec.agent
          || mark.fingerprint !== fingerprint(convert(exec))) return 'POLICY_ADMISSION_MISSING';
      return undefined;
    } catch { return 'POLICY_ADMISSION_MISSING'; }
  }

  const removeGuard = ctx.tools.guard(guard);
  const removeBefore = ctx.on('tools/pre-execute', before);
  return {
    enroll,
    // Keep guard installed after close to deny calls until host teardown.
    close() { live = false; removeBefore(); },
    disposeAfterRuntimeStopped() { live = false; removeBefore(); removeGuard(); },
  };
}
