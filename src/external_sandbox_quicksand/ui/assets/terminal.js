/* The browser owns presentation only. Every command uses the existing sandbox API. */
export const STDIN_CHUNK_BYTES = 32 * 1024;
export const STDIN_PENDING_BYTES = 128 * 1024;
export const SCROLLBACK_BYTES = 500 * 1024;
export const SCROLLBACK_NODES = 2000;
const encoder = new TextEncoder();

export function encodeBase64(bytes) {
  let binary = '';
  for (let offset = 0; offset < bytes.length; offset += 8192) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 8192));
  }
  return btoa(binary);
}

export function decodeBase64(value) {
  if (typeof value !== 'string' || value.length > 1024 * 1024 ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new Error('Invalid output encoding.');
  }
  return Uint8Array.from(atob(value), character => character.charCodeAt(0));
}

export class OutputDecoder {
  constructor(append) {
    this.append = append;
    this.decoders = {stdout: new TextDecoder(), stderr: new TextDecoder()};
  }
  push(kind, value) {
    const decoder = this.decoders[kind];
    if (!decoder) throw new Error('Invalid output stream.');
    const text = decoder.decode(decodeBase64(value), {stream: true});
    if (text) this.append(kind, text);
  }
  finish() {
    for (const [kind, decoder] of Object.entries(this.decoders)) {
      const text = decoder.decode();
      if (text) this.append(kind, text);
    }
  }
}

export class InputQueue {
  constructor(send, changed = () => {}) {
    this.send = send;
    this.changed = changed;
    this.queue = [];
    this.pendingBytes = 0;
    this.inflight = null;
    this.nextId = 0;
    this.eofRequested = false;
    this.eofSent = false;
    this.closed = false;
  }
  enqueue(text) {
    if (this.closed || this.eofRequested) throw new Error('Standard input is closed.');
    const bytes = encoder.encode(text);
    if (this.pendingBytes + bytes.length > STDIN_PENDING_BYTES) {
      throw new RangeError('Input is waiting for the command to read it. Keep pending input under 128 KiB.');
    }
    for (let offset = 0; offset < bytes.length; offset += STDIN_CHUNK_BYTES) {
      this.queue.push(bytes.slice(offset, offset + STDIN_CHUNK_BYTES));
    }
    this.pendingBytes += bytes.length;
    this.pump();
  }
  pump() {
    if (!this.closed && !this.inflight) {
      const bytes = this.queue.shift();
      if (bytes) {
        const id = this.nextId++;
        this.inflight = {id, length: bytes.length};
        this.send({type: 'stdin', id, data: encodeBase64(bytes)});
      } else if (this.eofRequested && !this.eofSent) {
        this.eofSent = true;
        this.send({type: 'stdin_eof'});
      }
    }
    this.changed();
  }
  acknowledge(id) {
    // A pipe may close before the final ACK arrives; queued input is then discarded.
    if (this.closed) return;
    if (!Number.isSafeInteger(id) || !this.inflight || id !== this.inflight.id) {
      throw new Error('Invalid standard-input acknowledgement.');
    }
    this.pendingBytes -= this.inflight.length;
    this.inflight = null;
    this.pump();
  }
  eof() {
    if (this.closed || this.eofRequested) return;
    this.eofRequested = true;
    this.pump();
  }
  close() {
    this.closed = true;
    this.queue.length = 0;
    this.inflight = null;
    this.pendingBytes = 0;
    this.changed();
  }
}

function tailWithinBytes(text, maximum) {
  const bytes = encoder.encode(text);
  if (bytes.length <= maximum) return {text, size: bytes.length};
  let offset = bytes.length - maximum;
  while (offset < bytes.length && (bytes[offset] & 0xc0) === 0x80) offset++;
  const tail = bytes.subarray(offset);
  return {text: new TextDecoder().decode(tail), size: tail.length};
}

export class Transcript {
  constructor(element, document, maximumBytes = SCROLLBACK_BYTES, maximumNodes = SCROLLBACK_NODES) {
    this.element = element;
    this.document = document;
    this.maximumBytes = maximumBytes;
    this.maximumNodes = maximumNodes;
    this.entries = [];
    this.bytes = 0;
  }
  append(kind, value) {
    const clipped = tailWithinBytes(String(value), this.maximumBytes);
    if (!clipped.text) return;
    const nearBottom = this.element.scrollHeight - this.element.scrollTop - this.element.clientHeight < 64;
    const last = this.entries.at(-1);
    if (last && last.kind === kind && (kind === 'stdout' || kind === 'stderr') &&
        last.size + clipped.size <= 32 * 1024) {
      // textContent never interprets shell output as HTML, links, or script.
      last.element.textContent += clipped.text;
      last.size += clipped.size;
    } else {
      const row = this.document.createElement('div');
      row.className = `terminal-row terminal-${kind}`;
      row.dataset.kind = kind;
      row.textContent = clipped.text;
      this.element.appendChild(row);
      this.entries.push({element: row, size: clipped.size, kind});
    }
    this.bytes += clipped.size;
    while (this.bytes > this.maximumBytes || this.entries.length > this.maximumNodes) {
      const removed = this.entries.shift();
      this.bytes -= removed.size;
      removed.element.remove();
    }
    if (nearBottom) this.element.scrollTop = this.element.scrollHeight;
  }
  clear() {
    this.element.replaceChildren();
    this.entries.length = 0;
    this.bytes = 0;
  }
  toText() {
    let text = '';
    for (const entry of this.entries) {
      const block = entry.kind === 'command' || entry.kind === 'system';
      if (block && text && !text.endsWith('\n')) text += '\n';
      text += entry.element.textContent;
      if (block && !text.endsWith('\n')) text += '\n';
    }
    return text;
  }
}

async function copyText(text, document, window) {
  try {
    if (!window.navigator?.clipboard?.writeText) throw new Error('Clipboard API unavailable.');
    await window.navigator.clipboard.writeText(text);
    return;
  } catch {
    // Older embedded browsers may only support copying a selected text field.
    // Keep this fallback local and restore the user's input/selection afterward.
    const focused = document.activeElement;
    const inputSelection = typeof focused?.selectionStart === 'number'
      ? [focused.selectionStart, focused.selectionEnd, focused.selectionDirection] : null;
    const selection = window.getSelection?.();
    const ranges = [];
    for (let index = 0; index < (selection?.rangeCount || 0); index++) {
      ranges.push(selection.getRangeAt(index).cloneRange());
    }
    const field = document.createElement('textarea');
    field.value = text;
    field.readOnly = true;
    field.setAttribute('aria-label', 'Terminal session to copy');
    field.style.position = 'fixed';
    field.style.opacity = '0';
    field.style.pointerEvents = 'none';
    document.body.appendChild(field);
    try {
      field.select();
      if (!document.execCommand?.('copy')) throw new Error('Copy is unavailable.');
    } finally {
      field.remove();
      focused?.focus({preventScroll: true});
      if (inputSelection) focused.setSelectionRange(...inputSelection);
      if (ranges.length) {
        selection.removeAllRanges();
        for (const range of ranges) selection.addRange(range);
      }
    }
  }
}

export class CommandHistory {
  constructor() {
    this.entries = [];
    this.bytes = 0;
    this.index = 0;
    this.draft = '';
  }
  add(command) {
    if (this.entries.at(-1) !== command) {
      this.entries.push(command);
      this.bytes += encoder.encode(command).length;
      while (this.entries.length > 100 || this.bytes > 256 * 1024) {
        this.bytes -= encoder.encode(this.entries.shift()).length;
      }
    }
    this.index = this.entries.length;
    this.draft = '';
  }
  navigate(direction, current) {
    if (this.index === this.entries.length) this.draft = current;
    this.index = Math.max(0, Math.min(this.entries.length, this.index + direction));
    return this.index === this.entries.length ? this.draft : this.entries[this.index];
  }
}

export function exitDescription(message) {
  const parts = [];
  if (message.timedOut) parts.push('Timed out');
  if (message.outputLimitExceeded) parts.push('Output limit reached');
  if (Number.isSafeInteger(message.signal) && message.signal > 0) parts.push(`Signal ${message.signal}`);
  else if (Number.isSafeInteger(message.exitCode)) parts.push(`Exit ${message.exitCode}`);
  else parts.push('Command finished');
  if (Number.isFinite(message.durationMs) && message.durationMs >= 0) {
    parts.push(message.durationMs < 1000 ? `${Math.round(message.durationMs)} ms` : `${(message.durationMs / 1000).toFixed(2)} s`);
  }
  return parts.join(' · ');
}

export class TerminalController {
  constructor({document, window, WebSocketClass = globalThis.WebSocket,
               setTimer = (callback, delay) => globalThis.setTimeout(callback, delay),
               clearTimer = timer => globalThis.clearTimeout(timer)}) {
    this.document = document;
    this.window = window;
    this.WebSocketClass = WebSocketClass;
    this.setTimer = setTimer;
    this.clearTimer = clearTimer;
    this.elements = {};
    for (const id of ['transcript', 'composer', 'run', 'cancel', 'eof', 'clear', 'cwd', 'timeout',
                      'command-form', 'connection-status', 'prompt-label', 'input-hint']) {
      this.elements[id] = document.getElementById(id);
      if (!this.elements[id]) throw new Error(`Missing terminal element: ${id}`);
    }
    this.transcript = new Transcript(this.elements.transcript, document);
    // Progressive enhancement also works with an already-running server's HTML.
    const copy = document.createElement('button');
    copy.id = 'copy-session';
    copy.type = 'button';
    copy.textContent = 'Copy session';
    copy.title = 'Copy the retained commands, input, output, and exit statuses as plain text';
    const copyStatus = document.createElement('span');
    copyStatus.id = 'copy-status';
    copyStatus.setAttribute('role', 'status');
    copyStatus.setAttribute('aria-live', 'polite');
    this.elements.clear.after(copy, copyStatus);
    this.elements['copy-session'] = copy;
    this.elements['copy-status'] = copyStatus;
    this.history = new CommandHistory();
    this.active = null;
    this.listeners = [];
    this.token = document.querySelector('meta[name="terminal-token"]')?.content || '';
    this.listen(this.elements['command-form'], 'submit', event => {
      event.preventDefault();
      this.submit();
    });
    this.listen(this.elements.composer, 'keydown', event => this.composerKey(event));
    this.listen(this.elements.cancel, 'click', () => this.cancel());
    this.listen(this.elements.eof, 'click', () => this.eof());
    this.listen(this.elements.clear, 'click', () => this.transcript.clear());
    this.listen(copy, 'click', () => this.copySession());
    this.listen(document, 'keydown', event => this.shortcuts(event));
    this.listen(window, 'pagehide', () => {
      // A back-forward-cache restore reuses this document without rerunning the
      // module. Close the command connection, but keep the form listeners alive.
      const run = this.active;
      if (run) this.finish(run, 'Command connection closed when leaving this page.', 'idle');
    });
    for (const button of document.querySelectorAll('[data-command]')) {
      this.listen(button, 'click', () => {
        if (this.active) return;
        this.elements.composer.value = button.dataset.command;
        this.elements.composer.focus();
      });
    }
    this.status('Ready', 'idle');
    this.render();
  }
  listen(target, name, handler) {
    target.addEventListener(name, handler);
    this.listeners.push(() => target.removeEventListener(name, handler));
  }
  async copySession() {
    const button = this.elements['copy-session'];
    const status = this.elements['copy-status'];
    if (button.disabled) return;
    const text = this.transcript.toText();
    status.title = '';
    if (!text) {
      status.textContent = 'Nothing to copy';
      return;
    }
    button.disabled = true;
    status.textContent = 'Copying…';
    try {
      await copyText(text, this.document, this.window);
      status.textContent = 'Copied!';
    } catch {
      status.textContent = 'Copy unavailable';
      status.title = 'Select the terminal output and copy it using your browser.';
    } finally {
      button.disabled = false;
    }
  }
  status(text, state) {
    this.elements['connection-status'].textContent = text;
    this.elements['connection-status'].dataset.state = state;
  }
  render() {
    const run = this.active;
    const writable = run?.started && !run.canceled && !run.input.closed && !run.input.eofRequested;
    this.elements.composer.disabled = Boolean(run && !writable);
    this.elements.run.disabled = Boolean(run && !writable);
    this.elements.run.textContent = run ? 'Send input' : 'Run command';
    this.elements.cancel.disabled = !run || run.canceled;
    this.elements.eof.disabled = !writable;
    this.elements.cwd.disabled = Boolean(run);
    this.elements.timeout.disabled = Boolean(run);
    this.elements['prompt-label'].textContent = run ? 'Stdin' : 'Command';
    this.elements.composer.placeholder = run ? 'Input for the running command…' : 'Enter a shell command…';
    let hint = 'Enter runs · Shift+Enter adds a line · ↑↓ history';
    if (run) {
      if (run.canceled) hint = 'Stopping command…';
      else if (!run.started) hint = 'Waiting for the command to start…';
      else if (run.input.closed) hint = 'Standard input is closed. Waiting for the command to finish.';
      else if (run.input.eofRequested) hint = 'Finishing pending input and sending EOF…';
      else hint = 'Enter sends a line · Ctrl+D sends EOF · Ctrl+C cancels';
      if (run.input.pendingBytes) hint += ` · ${run.input.pendingBytes.toLocaleString()} bytes pending`;
    }
    this.elements['input-hint'].textContent = hint;
  }
  composerKey(event) {
    if (event.isComposing) return;
    if (event.key === 'Enter' && !event.shiftKey) {
      event.preventDefault();
      this.submit();
    } else if (!this.active && !event.ctrlKey && !event.metaKey && !event.altKey &&
               (event.key === 'ArrowUp' || event.key === 'ArrowDown')) {
      const input = this.elements.composer;
      const singleLine = !input.value.includes('\n');
      const boundary = event.key === 'ArrowUp' ? input.selectionStart === 0 : input.selectionEnd === input.value.length;
      if (singleLine || boundary) {
        event.preventDefault();
        input.value = this.history.navigate(event.key === 'ArrowUp' ? -1 : 1, input.value);
        input.setSelectionRange(input.value.length, input.value.length);
      }
    }
  }
  shortcuts(event) {
    if (!event.ctrlKey || event.altKey || event.metaKey || event.isComposing) return;
    const key = event.key.toLowerCase();
    if (key === 'l') {
      event.preventDefault();
      this.transcript.clear();
    } else if (key === 'd' && this.active?.started) {
      event.preventDefault();
      this.eof();
    } else if (key === 'c' && this.active) {
      const target = event.target;
      const inputSelection = typeof target?.selectionStart === 'number' && target.selectionStart !== target.selectionEnd;
      if (!inputSelection && !String(this.window.getSelection?.() || '')) {
        event.preventDefault();
        this.cancel();
      }
    }
  }
  submit() {
    const input = this.elements.composer;
    if (this.active) {
      const run = this.active;
      if (!run.started || run.canceled || run.input.closed || run.input.eofRequested) return;
      try {
        run.input.enqueue(input.value + '\n');
        this.transcript.append('input', input.value + '\n');
        input.value = '';
        input.focus();
      } catch (error) {
        if (error instanceof RangeError) this.transcript.append('system', `${error.message}\n`);
        else this.fail(run, 'Could not send standard input. Connection closed.');
      }
      return;
    }
    this.start(input.value);
  }
  start(command) {
    if (this.active || !command.trim()) return;
    const cwd = this.elements.cwd.value;
    if (encoder.encode(command).length > 65536 || command.includes('\0')) {
      this.transcript.append('system', 'Commands must be at most 64 KiB and contain no NUL characters.\n');
      return;
    }
    if (!cwd.startsWith('/') || cwd.includes('\0') || encoder.encode(cwd).length > 4096) {
      this.transcript.append('system', 'Use an absolute sandbox directory of at most 4096 bytes.\n');
      return;
    }
    if (!this.token) {
      this.transcript.append('system', 'Terminal authorization is unavailable. Reload this page.\n');
      return;
    }
    const chosen = Number(this.elements.timeout.value);
    const timeoutMs = [30000, 120000, 300000].includes(chosen) ? chosen : 120000;
    const run = {ws: null, started: false, finished: false, canceled: false, timer: null};
    run.output = new OutputDecoder((kind, text) => this.transcript.append(kind, text));
    run.input = new InputQueue(message => this.send(run, message), () => this.render());
    this.active = run;
    this.history.add(command);
    this.transcript.append('command', `$ ${command}\n`);
    this.elements.composer.value = '';
    this.status('Connecting…', 'connecting');
    this.render();
    try {
      const url = new URL('/exec/ws', this.window.location.origin);
      url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:';
      run.ws = new this.WebSocketClass(url.toString(), ['sandbox-terminal', `sandbox-token.${this.token}`]);
      run.timer = this.setTimer(() => this.fail(run, 'The command did not start in time. Connection closed.'), 20000);
      run.ws.addEventListener('open', () => {
        if (!this.current(run)) return;
        if (run.ws.protocol !== 'sandbox-terminal') {
          this.fail(run, 'Terminal authorization failed. Reload this page.');
          return;
        }
        try {
          this.send(run, {type: 'start', command, cwd, stdin: true, timeoutMs, maxOutputBytes: 4 * 1024 * 1024});
          this.status('Starting…', 'connecting');
        } catch {
          this.fail(run, 'Could not send the command. Connection closed.');
        }
      });
      run.ws.addEventListener('message', event => this.message(run, event.data));
      run.ws.addEventListener('error', () => this.fail(run, 'WebSocket connection failed. Reload the page or check the server.'));
      run.ws.addEventListener('close', () => this.fail(run, 'Connection closed before the command finished.'));
    } catch {
      this.fail(run, 'Could not open the terminal connection. Reload this page.');
    }
  }
  current(run) {
    return this.active === run && !run.finished;
  }
  send(run, value) {
    if (!this.current(run) || !run.ws || run.ws.readyState !== 1) throw new Error('Terminal connection is closed.');
    run.ws.send(JSON.stringify(value));
  }
  message(run, raw) {
    if (!this.current(run)) return;
    try {
      if (typeof raw !== 'string') throw new Error('Invalid message.');
      const message = JSON.parse(raw);
      if (!message || typeof message !== 'object' || Array.isArray(message)) throw new Error('Invalid message.');
      switch (message.type) {
        case 'started':
          if (run.started) throw new Error('Duplicate startup message.');
          run.started = true;
          if (!run.canceled) {
            this.clearTimer(run.timer);
            run.timer = null;
          }
          this.status(run.canceled ? 'Canceling…' : 'Running', 'running');
          this.render();
          if (!run.canceled) this.elements.composer.focus();
          break;
        case 'stdout':
        case 'stderr':
          if (!run.started) throw new Error('Output arrived before startup.');
          run.output.push(message.type, message.data);
          break;
        case 'stdin_ack':
          run.input.acknowledge(message.id);
          break;
        case 'stdin_closed':
          run.input.close();
          break;
        case 'exit': {
          const description = exitDescription(message);
          this.finish(run, description, message.exitCode === 0 && !message.timedOut && !message.outputLimitExceeded ? 'idle' : 'error');
          break;
        }
        case 'error':
          this.fail(run, typeof message.error === 'string' ? message.error : 'Command failed.');
          break;
        default:
          throw new Error('Unknown terminal message.');
      }
    } catch {
      this.fail(run, 'Invalid server response. Connection closed.');
    }
  }
  eof() {
    const run = this.active;
    if (!run?.started || run.canceled) return;
    try {
      run.input.eof();
    } catch {
      this.fail(run, 'Could not close standard input. Connection closed.');
    }
  }
  cancel() {
    const run = this.active;
    if (!run || run.canceled) return;
    run.canceled = true;
    run.input.close();
    this.status('Canceling…', 'running');
    if (run.ws?.readyState !== 1) {
      this.finish(run, 'Canceled before the command started.', 'idle');
      return;
    }
    try {
      this.send(run, {type: 'cancel'});
      this.clearTimer(run.timer);
      run.timer = this.setTimer(() => this.finish(run, 'Connection closed after cancellation.', 'idle'), 5000);
    } catch {
      this.finish(run, 'Connection closed after cancellation.', 'idle');
    }
  }
  fail(run, message) {
    if (this.current(run)) this.finish(run, message, 'error');
  }
  finish(run, message, state) {
    if (!this.current(run)) return;
    run.finished = true;
    this.active = null;
    this.clearTimer(run.timer);
    run.input.close();
    run.output.finish();
    this.transcript.append('system', `${message}\n`);
    this.status(state === 'idle' ? 'Ready' : 'Command stopped', state);
    try { run.ws?.close(); } catch { /* Already disconnected. */ }
    this.render();
    this.elements.composer.focus();
  }
  destroy() {
    for (const remove of this.listeners.splice(0)) remove();
    const run = this.active;
    if (run) this.finish(run, 'Terminal closed.', 'idle');
  }
}

if (typeof document !== 'undefined' && typeof window !== 'undefined') {
  const boot = () => {
    if (document.getElementById('command-form')) new TerminalController({document, window});
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot, {once: true});
  else boot();
}
