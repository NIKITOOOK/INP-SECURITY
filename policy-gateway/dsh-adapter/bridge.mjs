import { spawn } from 'node:child_process';

/** One persistent worker; a broken transport is never silently restarted. */
export class PolicyBridge {
  constructor({ python, worker, policy, timeoutMs = 5000 }) {
    this.pending = new Map();
    this.sequence = 0;
    this.buffer = '';
    this.failed = false;
    this.timeoutMs = timeoutMs;
    this.child = spawn(python, ['-u', worker, policy], {
      shell: false, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'],
    });
    this.closed = new Promise(resolve => this.child.once('close', resolve));
    this.child.once('error', () => this.fail());
    this.child.once('close', () => this.fail());
    this.child.stdin.on('error', () => this.fail());
    // Do not leak policy paths / exception details into model-facing errors.
    this.child.stderr.resume();
    this.child.stdout.setEncoding('utf8');
    this.child.stdout.on('data', text => {
      this.buffer += text;
      if (Buffer.byteLength(this.buffer) > 1024 * 1024) return this.fail();
      while (this.buffer.includes('\n')) {
        const at = this.buffer.indexOf('\n');
        const line = this.buffer.slice(0, at);
        this.buffer = this.buffer.slice(at + 1);
        try {
          const message = JSON.parse(line);
          const pending = this.pending.get(message.id);
          if (!pending || !message.result || message.error) return this.fail();
          this.pending.delete(message.id);
          clearTimeout(pending.timer);
          pending.resolve(message.result);
        } catch { this.fail(); return; }
      }
    });
  }

  fail() {
    if (this.failed) return;
    this.failed = true;
    for (const { reject, timer } of this.pending.values()) {
      clearTimeout(timer);
      reject(new Error('POLICY_WORKER_UNAVAILABLE'));
    }
    this.pending.clear();
    this.child.kill();
  }

  request(method, params) {
    if (this.failed) return Promise.reject(new Error('POLICY_WORKER_UNAVAILABLE'));
    let line;
    const id = ++this.sequence;
    try {
      line = JSON.stringify({ id, method, params }) + '\n';
      if (Buffer.byteLength(line) > 1024 * 1024) throw new Error();
    } catch { return Promise.reject(new Error('INVALID_POLICY_MESSAGE')); }
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => this.fail(), this.timeoutMs);
      this.pending.set(id, { resolve, reject, timer });
      this.child.stdin.write(line);
    });
  }

  async close() {
    this.fail();
    await this.closed;
  }
}
