import { spawn } from 'node:child_process';

/**
 * Run a command and collect stdout/stderr. Never throws on a non-zero exit —
 * callers decide what a failure means, since most probes here are best-effort.
 */
export function run(cmd, args = [], { timeout = 0, input, onStdout } = {}) {
  return new Promise((resolve) => {
    let child;
    try {
      child = spawn(cmd, args, { stdio: ['pipe', 'pipe', 'pipe'] });
    } catch (err) {
      resolve({ ok: false, code: null, stdout: '', stderr: String(err), error: err });
      return;
    }

    let stdout = '';
    let stderr = '';
    let timer = null;
    let timedOut = false;

    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (d) => {
      stdout += d;
      if (onStdout) onStdout(d);
    });
    child.stderr.on('data', (d) => { stderr += d; });

    if (timeout > 0) {
      timer = setTimeout(() => {
        timedOut = true;
        child.kill('SIGKILL');
      }, timeout);
    }

    child.on('error', (err) => {
      if (timer) clearTimeout(timer);
      resolve({ ok: false, code: null, stdout, stderr: stderr || String(err), error: err });
    });

    child.on('close', (code) => {
      if (timer) clearTimeout(timer);
      resolve({ ok: code === 0 && !timedOut, code, stdout, stderr, timedOut });
    });

    if (input !== undefined) child.stdin.end(input);
    else child.stdin.end();
  });
}

/** True if the binary resolves on PATH. */
export async function has(cmd) {
  const res = await run('/bin/sh', ['-c', `command -v ${cmd}`], { timeout: 4000 });
  return res.ok && res.stdout.trim().length > 0;
}
