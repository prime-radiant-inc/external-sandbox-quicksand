import assert from 'node:assert/strict';
import {test} from 'node:test';
import {loadModule} from './load-assets.mjs';

const {
  CommandHistory, InputQueue, OutputDecoder, Transcript, TerminalController,
  STDIN_CHUNK_BYTES, STDIN_PENDING_BYTES, decodeBase64, encodeBase64, exitDescription,
} = await loadModule('terminal.js');

const encoder = new TextEncoder();

class Events {
  constructor() { this.events = new Map(); }
  addEventListener(name, handler) {
    if (!this.events.has(name)) this.events.set(name, new Set());
    this.events.get(name).add(handler);
  }
  removeEventListener(name, handler) { this.events.get(name)?.delete(handler); }
  emit(name, event = {}) {
    event.type = name;
    event.defaultPrevented = false;
    event.preventDefault ||= () => { event.defaultPrevented = true; };
    for (const handler of [...(this.events.get(name) || [])]) handler(event);
    return event;
  }
}

class Element extends Events {
  constructor(document) {
    super();
    this.document = document;
    this.children = [];
    this.dataset = {};
    this.style = {};
    this.attributes = {};
    this.value = '';
    this._text = '';
    this.disabled = false;
    this.scrollTop = 0;
    this.clientHeight = 100;
    this.selectionStart = this.selectionEnd = 0;
  }
  set textContent(value) { this._text = value; this.children = []; }
  get textContent() { return this._text + this.children.map(child => child.textContent).join(''); }
  set id(value) { this._id = value; this.document.elements[value] = this; }
  get id() { return this._id; }
  get scrollHeight() { return this.children.length * 20; }
  appendChild(child) { this.children.push(child); child.parent = this; return child; }
  after(...children) {
    const index = this.parent.children.indexOf(this);
    this.parent.children.splice(index + 1, 0, ...children);
    for (const child of children) child.parent = this.parent;
  }
  setAttribute(name, value) { this.attributes[name] = String(value); }
  replaceChildren() { for (const child of this.children) child.parent = null; this.children = []; this._text = ''; }
  remove() { if (this.parent) this.parent.children = this.parent.children.filter(child => child !== this); this.parent = null; }
  focus() { this.document.activeElement = this; }
  setSelectionRange(start, end) { this.selectionStart = start; this.selectionEnd = end; }
  select() { this.focus(); this.setSelectionRange(0, this.value.length); }
}

class Document extends Events {
  constructor(token = 'local-demo-token') {
    super();
    this.token = token;
    this.elements = Object.fromEntries(['transcript', 'composer', 'run', 'cancel', 'eof', 'clear',
      'cwd', 'timeout', 'command-form', 'connection-status', 'prompt-label', 'input-hint']
      .map(id => [id, new Element(this)]));
    this.body = new Element(this);
    for (const [id, element] of Object.entries(this.elements)) {
      element.id = id;
      this.body.appendChild(element);
    }
    this.elements.cwd.value = '/workspace';
    this.elements.timeout.value = '120000';
    this.example = new Element(this);
    this.example.dataset.command = 'printf example';
  }
  getElementById(id) { return this.elements[id]; }
  createElement() { return new Element(this); }
  querySelector() { return {content: this.token}; }
  querySelectorAll() { return [this.example]; }
}

function terminal(options = {}) {
  const document = new Document(options.token);
  const window = new Events();
  window.location = {origin: options.origin || 'http://127.0.0.1:8687'};
  window.navigator = {};
  window.selection = '';
  window.getSelection = () => window.selection;
  const sockets = [];
  class Socket extends Events {
    constructor(url, protocols) {
      super();
      this.url = url;
      this.protocols = protocols;
      this.protocol = 'sandbox-terminal';
      this.readyState = 0;
      this.sent = [];
      sockets.push(this);
    }
    open() { this.readyState = 1; this.emit('open'); }
    send(value) { assert.equal(this.readyState, 1); this.sent.push(JSON.parse(value)); }
    message(value) { this.emit('message', {data: JSON.stringify(value)}); }
    close() { this.readyState = 3; this.emit('close'); }
  }
  let timerId = 0;
  const timers = new Map();
  const controller = new TerminalController({document, window, WebSocketClass: Socket,
    setTimer: (callback, delay) => { const id = ++timerId; timers.set(id, {callback, delay}); return id; },
    clearTimer: id => timers.delete(id)});
  return {controller, document, window, sockets, timers, elements: document.elements,
    start(command = 'cat') {
      document.elements.composer.value = command;
      document.elements['command-form'].emit('submit');
      const socket = sockets.at(-1);
      socket.open();
      socket.message({type: 'started', processId: 'demo'});
      return socket;
    }};
}

test('separate streaming decoders preserve split Unicode and flush incomplete bytes', () => {
  const seen = [];
  const output = new OutputDecoder((kind, text) => seen.push([kind, text]));
  const emoji = encoder.encode('🍎');
  output.push('stdout', encodeBase64(emoji.slice(0, 2)));
  output.push('stderr', encodeBase64(encoder.encode('é').slice(0, 1)));
  output.push('stdout', encodeBase64(emoji.slice(2)));
  output.push('stderr', encodeBase64(encoder.encode('é').slice(1)));
  output.push('stdout', encodeBase64(Uint8Array.of(0xe2)));
  output.finish();
  assert.deepEqual(seen, [['stdout', '🍎'], ['stderr', 'é'], ['stdout', '�']]);
  assert.throws(() => decodeBase64('<script>'), /encoding/);
});

test('stdin sends one 32 KiB chunk at a time and EOF follows the final acknowledgement', () => {
  const sent = [];
  const input = new InputQueue(message => sent.push(message));
  const content = '🍎'.repeat(18000);
  const bytes = encoder.encode(content);
  input.enqueue(content);
  input.eof();
  assert.equal(sent.length, 1);
  assert.equal(input.pendingBytes, bytes.length);
  assert.equal(decodeBase64(sent[0].data).length, STDIN_CHUNK_BYTES);
  assert.throws(() => input.acknowledge(55), /acknowledgement/);
  input.acknowledge(0);
  assert.equal(sent.length, 2);
  input.acknowledge(1);
  assert.equal(sent.length, 3);
  input.acknowledge(2);
  assert.equal(input.pendingBytes, 0);
  assert.deepEqual(sent.at(-1), {type: 'stdin_eof'});
  assert.deepEqual(Buffer.concat(sent.slice(0, -1).map(message => Buffer.from(message.data, 'base64'))), Buffer.from(bytes));
  assert.throws(() => input.enqueue('later'), /closed/);
});

test('stdin queue counts in-flight bytes and rejects oversized input atomically', () => {
  const sent = [];
  const input = new InputQueue(message => sent.push(message));
  input.enqueue('x'.repeat(STDIN_PENDING_BYTES));
  assert.equal(input.pendingBytes, STDIN_PENDING_BYTES);
  assert.throws(() => input.enqueue('x'), RangeError);
  assert.equal(sent.length, 1);
  assert.equal(input.queue.length, 3);
  input.close();
  assert.equal(input.pendingBytes, 0);
  assert.equal(input.queue.length, 0);
  input.acknowledge(0);
  assert.equal(sent.length, 1);
});

test('scrollback uses inert text and bounds UTF-8 bytes and DOM nodes', () => {
  const document = new Document();
  const transcript = new Transcript(document.elements.transcript, document, 48, 3);
  transcript.append('stdout', '<img src=x onerror=alert(1)>');
  assert.equal(document.elements.transcript.children[0].textContent, '<img src=x onerror=alert(1)>');
  assert.equal(document.elements.transcript.children[0].children.length, 0);
  for (let index = 0; index < 20; index++) transcript.append(index % 2 ? 'stdout' : 'stderr', '🍎🍎');
  assert.ok(transcript.bytes <= 48);
  assert.ok(transcript.entries.length <= 3);
  assert.equal(transcript.bytes, encoder.encode(document.elements.transcript.textContent).length);
  transcript.append('system', '🍎'.repeat(1000));
  assert.ok(transcript.bytes <= 48);
  assert.ok(!document.elements.transcript.textContent.includes('�'));
  transcript.clear();
  assert.equal(transcript.bytes, 0);
  assert.equal(document.elements.transcript.children.length, 0);
});

test('copy text preserves stream chunks, newlines, commands and literal markup', () => {
  const document = new Document();
  const transcript = new Transcript(document.elements.transcript, document);
  transcript.append('command', '$ cat');
  transcript.append('stdout', 'hel');
  transcript.append('stdout', 'lo');
  transcript.append('stderr', '!');
  transcript.append('system', 'Exit 0');
  transcript.append('command', '$ printf markup');
  transcript.append('stdout', '<img src=x>\n');
  transcript.append('input', 'typed input\n');
  transcript.append('system', 'Exit 1');
  assert.equal(transcript.toText(), '$ cat\nhello!\nExit 0\n$ printf markup\n<img src=x>\ntyped input\nExit 1\n');
});

test('copy text contains only retained scrollback and becomes empty after clearing', () => {
  const document = new Document();
  const transcript = new Transcript(document.elements.transcript, document, 16, 2);
  transcript.append('command', '$ old command');
  transcript.append('stdout', 'old output');
  transcript.append('stderr', '🍎🍎🍎🍎🍎');
  assert.equal(transcript.toText(), '🍎🍎🍎🍎');
  assert.ok(!transcript.toText().includes('old'));
  assert.ok(!transcript.toText().includes('�'));
  transcript.clear();
  assert.equal(transcript.toText(), '');
});

test('copy snapshots a running session without submitting input, changing output or exposing the token', async () => {
  const ui = terminal({token: 'private-copy-test-token'});
  const writes = [];
  let finishWrite;
  ui.window.navigator.clipboard = {writeText: text => {
    writes.push(text);
    return new Promise(resolve => { finishWrite = resolve; });
  }};
  const socket = ui.start('cat');
  socket.message({type: 'stdout', data: encodeBase64(encoder.encode('visible output'))});
  ui.elements.composer.value = 'unsubmitted private draft';
  const active = ui.controller.active;
  const snapshot = ui.controller.transcript.toText();
  const copying = ui.controller.copySession();
  assert.equal(ui.elements['copy-session'].type, 'button');
  assert.equal(ui.elements['copy-session'].disabled, true);
  await ui.controller.copySession();
  assert.deepEqual(writes, [snapshot]);
  assert.ok(!writes[0].includes('private-copy-test-token'));
  assert.ok(!writes[0].includes('unsubmitted private draft'));
  socket.message({type: 'stdout', data: encodeBase64(encoder.encode(' later output'))});
  finishWrite();
  await copying;
  assert.equal(ui.elements['copy-session'].disabled, false);
  assert.match(ui.elements['copy-status'].textContent, /copied/i);
  assert.equal(ui.controller.active, active);
  assert.equal(ui.elements.composer.value, 'unsubmitted private draft');
  assert.deepEqual(socket.sent.map(message => message.type), ['start']);
  assert.equal(ui.controller.transcript.toText(), `${snapshot} later output`);
  ui.controller.destroy();
});

test('clipboard denial falls back to a temporary textarea and restores focus and selection', async () => {
  const ui = terminal();
  ui.controller.transcript.append('stdout', 'clipboard fallback 🍎');
  ui.elements.composer.value = 'draft selection';
  ui.elements.composer.focus();
  ui.elements.composer.setSelectionRange(2, 7);
  const selectedRange = {cloneRange() { return this; }};
  const restoredRanges = [];
  ui.window.getSelection = () => ({rangeCount: 1, getRangeAt: () => selectedRange,
    removeAllRanges: () => restoredRanges.push('cleared'), addRange: range => restoredRanges.push(range)});
  ui.window.navigator.clipboard = {writeText: async () => { throw new Error('Permission denied'); }};
  const children = [...ui.document.body.children];
  const legacyCopies = [];
  ui.document.execCommand = command => {
    assert.equal(command, 'copy');
    const field = ui.document.activeElement;
    legacyCopies.push(field.value);
    assert.equal(field.selectionStart, 0);
    assert.equal(field.selectionEnd, field.value.length);
    return true;
  };
  await ui.controller.copySession();
  assert.deepEqual(legacyCopies, ['clipboard fallback 🍎']);
  assert.deepEqual(ui.document.body.children, children);
  assert.equal(ui.document.activeElement, ui.elements.composer);
  assert.deepEqual([ui.elements.composer.selectionStart, ui.elements.composer.selectionEnd], [2, 7]);
  assert.deepEqual(restoredRanges, ['cleared', selectedRange]);
  assert.match(ui.elements['copy-status'].textContent, /copied/i);
  assert.equal(ui.controller.transcript.toText(), 'clipboard fallback 🍎');
  ui.controller.destroy();
});

test('missing clipboard API uses the fallback and reports fallback failure without leaving temporary input', async () => {
  const ui = terminal();
  ui.controller.transcript.append('stdout', 'retained output');
  const children = [...ui.document.body.children];
  let copies = 0;
  ui.document.execCommand = () => { copies++; return false; };
  await ui.controller.copySession();
  assert.equal(copies, 1);
  assert.equal(ui.elements['copy-session'].disabled, false);
  assert.match(ui.elements['copy-status'].textContent, /unavailable|could not|unable|failed/i);
  assert.deepEqual(ui.document.body.children, children);
  assert.equal(ui.controller.transcript.toText(), 'retained output');
  assert.equal(ui.sockets.length, 0);
  ui.controller.destroy();
});

test('the copy button is wired and an empty cleared session never touches the clipboard', async () => {
  const ui = terminal();
  const writes = [];
  ui.window.navigator.clipboard = {writeText: async text => { writes.push(text); }};
  ui.controller.transcript.append('stdout', 'copy by clicking');
  ui.elements['copy-session'].emit('click');
  await Promise.resolve();
  await Promise.resolve();
  assert.deepEqual(writes, ['copy by clicking']);
  ui.elements.clear.emit('click');
  await ui.controller.copySession();
  assert.deepEqual(writes, ['copy by clicking']);
  assert.match(ui.elements['copy-status'].textContent, /nothing to copy/i);
  assert.equal(ui.elements['copy-session'].disabled, false);
  ui.controller.destroy();
  assert.equal(ui.elements['copy-session'].events.get('click').size, 0);
});

test('history is bounded and restores the in-progress draft', () => {
  const history = new CommandHistory();
  history.add('one'); history.add('two'); history.add('two');
  assert.equal(history.navigate(-1, 'draft'), 'two');
  assert.equal(history.navigate(-1, 'two'), 'one');
  assert.equal(history.navigate(1, 'one'), 'two');
  assert.equal(history.navigate(1, 'two'), 'draft');
  for (let index = 0; index < 200; index++) history.add(`command-${index}`);
  assert.equal(history.entries.length, 100);
  for (let index = 0; index < 10; index++) history.add('x'.repeat(65000) + index);
  assert.ok(history.bytes <= 256 * 1024);
});

test('a command starts exactly once with token subprotocol and changes the form to stdin', () => {
  const ui = terminal({origin: 'https://localhost:8687'});
  ui.elements.composer.value = 'printf hello';
  ui.elements['command-form'].emit('submit');
  const socket = ui.sockets[0];
  assert.equal(socket.url, 'wss://localhost:8687/exec/ws');
  assert.deepEqual(socket.protocols, ['sandbox-terminal', 'sandbox-token.local-demo-token']);
  assert.ok(!socket.url.includes('token'));
  assert.equal(ui.elements.composer.disabled, true);
  assert.equal(socket.sent.length, 0);
  socket.open();
  assert.deepEqual(socket.sent, [{type: 'start', command: 'printf hello', cwd: '/workspace', stdin: true,
    timeoutMs: 120000, maxOutputBytes: 4194304}]);
  socket.message({type: 'started'});
  assert.equal(ui.elements.composer.disabled, false);
  assert.equal(ui.elements['prompt-label'].textContent, 'Stdin');
  assert.equal(ui.elements.cwd.disabled, true);
  ui.elements.composer.value = 'hello';
  ui.elements['command-form'].emit('submit');
  assert.equal(Buffer.from(socket.sent[1].data, 'base64').toString(), 'hello\n');
  ui.elements.eof.emit('click');
  assert.equal(socket.sent.length, 2);
  socket.message({type: 'stdin_ack', id: 0});
  assert.deepEqual(socket.sent.at(-1), {type: 'stdin_eof'});
  assert.equal(ui.elements.composer.disabled, true);
  socket.message({type: 'stdin_closed'});
  socket.message({type: 'exit', exitCode: 0, durationMs: 23});
  assert.equal(ui.controller.active, null);
  assert.equal(ui.elements.cwd.disabled, false);
  assert.equal(ui.elements['prompt-label'].textContent, 'Command');
  assert.match(ui.elements.transcript.textContent, /Exit 0 · 23 ms/);
  assert.equal(ui.sockets.length, 1);
  ui.controller.destroy();
});

test('stale socket callbacks cannot write output or stop a newer command', () => {
  const ui = terminal();
  const first = ui.start('first');
  first.message({type: 'exit', exitCode: 0});
  const second = ui.start('second');
  const active = ui.controller.active;
  const before = ui.elements.transcript.textContent;
  first.message({type: 'stdout', data: encodeBase64(encoder.encode('stale-output'))});
  first.emit('error'); first.emit('close'); first.message({type: 'exit', exitCode: 99});
  assert.equal(ui.controller.active, active);
  assert.equal(ui.elements.transcript.textContent, before);
  second.message({type: 'stdout', data: encodeBase64(encoder.encode('fresh-output'))});
  assert.match(ui.elements.transcript.textContent, /fresh-output/);
  ui.controller.destroy();
});

test('connection failures never reconnect or replay and discard pending input', () => {
  const ui = terminal();
  const socket = ui.start();
  ui.elements.composer.value = 'x'.repeat(65536);
  ui.elements['command-form'].emit('submit');
  const queue = ui.controller.active.input;
  socket.emit('error');
  assert.equal(ui.controller.active, null);
  assert.equal(queue.pendingBytes, 0);
  assert.equal(ui.sockets.length, 1);
  assert.equal(ui.timers.size, 0);
  assert.equal(ui.elements['connection-status'].dataset.state, 'error');
  ui.controller.destroy();
});

test('keyboard shortcuts preserve copy selection and support cancel, EOF, clear and history', () => {
  const ui = terminal();
  const socket = ui.start();
  ui.window.selection = 'selected output';
  const copied = ui.document.emit('keydown', {ctrlKey: true, key: 'c', target: ui.elements.transcript});
  assert.equal(copied.defaultPrevented, false);
  assert.equal(socket.sent.filter(message => message.type === 'cancel').length, 0);
  ui.window.selection = '';
  ui.elements.composer.value = 'selected input';
  ui.elements.composer.setSelectionRange(0, 5);
  ui.document.emit('keydown', {ctrlKey: true, key: 'c', target: ui.elements.composer});
  assert.equal(socket.sent.filter(message => message.type === 'cancel').length, 0);
  ui.elements.composer.setSelectionRange(0, 0);
  assert.equal(ui.document.emit('keydown', {ctrlKey: true, key: 'd'}).defaultPrevented, true);
  assert.deepEqual(socket.sent.at(-1), {type: 'stdin_eof'});
  assert.equal(ui.document.emit('keydown', {ctrlKey: true, key: 'c'}).defaultPrevented, true);
  assert.deepEqual(socket.sent.at(-1), {type: 'cancel'});
  socket.message({type: 'exit', signal: 9, exitCode: null});
  ui.elements.composer.value = 'draft';
  ui.elements.composer.emit('keydown', {key: 'ArrowUp'});
  assert.equal(ui.elements.composer.value, 'cat');
  ui.elements.composer.emit('keydown', {key: 'ArrowDown'});
  assert.equal(ui.elements.composer.value, 'draft');
  assert.equal(ui.document.emit('keydown', {ctrlKey: true, key: 'l'}).defaultPrevented, true);
  assert.equal(ui.elements.transcript.textContent, '');
  ui.controller.destroy();
});

test('Shift+Enter and IME composition do not execute and examples only populate the input', () => {
  const ui = terminal();
  ui.document.example.emit('click');
  assert.equal(ui.elements.composer.value, 'printf example');
  assert.equal(ui.sockets.length, 0);
  assert.equal(ui.elements.composer.emit('keydown', {key: 'Enter', shiftKey: true}).defaultPrevented, false);
  assert.equal(ui.elements.composer.emit('keydown', {key: 'Enter', isComposing: true}).defaultPrevented, false);
  assert.equal(ui.sockets.length, 0);
  ui.elements.composer.emit('keydown', {key: 'Enter'});
  assert.equal(ui.sockets.length, 1);
  ui.controller.destroy();
});

test('authorization mismatch, missing token and invalid cwd never run a command', () => {
  const missing = terminal({token: ''});
  missing.elements.composer.value = 'danger';
  missing.elements['command-form'].emit('submit');
  assert.equal(missing.sockets.length, 0);
  const invalid = terminal();
  invalid.elements.composer.value = 'danger';
  invalid.elements.cwd.value = 'relative';
  invalid.elements['command-form'].emit('submit');
  assert.equal(invalid.sockets.length, 0);
  invalid.elements.cwd.value = '/workspace';
  invalid.elements['command-form'].emit('submit');
  const socket = invalid.sockets[0];
  socket.protocol = '';
  socket.open();
  assert.equal(socket.sent.length, 0);
  assert.equal(invalid.controller.active, null);
  missing.controller.destroy(); invalid.controller.destroy();
});

test('cancel during startup retains its watchdog after a racing started event', () => {
  const ui = terminal();
  ui.elements.composer.value = 'sleep 60';
  ui.elements['command-form'].emit('submit');
  const socket = ui.sockets[0];
  socket.open();
  ui.controller.cancel();
  socket.message({type: 'started'});
  assert.equal(ui.elements.composer.disabled, true);
  assert.equal(ui.timers.size, 1);
  const timer = [...ui.timers.values()][0];
  assert.equal(timer.delay, 5000);
  timer.callback();
  assert.equal(ui.controller.active, null);
  assert.equal(socket.readyState, 3);
  ui.controller.destroy();
});

test('exit descriptions retain timeout, output cap, signal and duration', () => {
  assert.equal(exitDescription({timedOut: true, signal: 9, durationMs: 120002}), 'Timed out · Signal 9 · 120.00 s');
  assert.equal(exitDescription({outputLimitExceeded: true, exitCode: 1, durationMs: 450}), 'Output limit reached · Exit 1 · 450 ms');
});

test('default browser timers retain their Window/global receiver', () => {
  const originalSet = globalThis.setTimeout;
  const originalClear = globalThis.clearTimeout;
  const document = new Document();
  const window = new Events();
  window.location = {origin: 'http://127.0.0.1:8687'};
  window.getSelection = () => '';
  class Socket extends Events {
    constructor() { super(); this.readyState = 0; }
    close() { this.readyState = 3; this.emit('close'); }
  }
  const cleared = [];
  let controller;
  try {
    globalThis.setTimeout = function () {
      assert.equal(this, globalThis, 'native browser timers reject the controller receiver');
      return 123;
    };
    globalThis.clearTimeout = function (id) {
      assert.equal(this, globalThis, 'native browser timers reject the controller receiver');
      cleared.push(id);
    };
    controller = new TerminalController({document, window, WebSocketClass: Socket});
    controller.start('printf hello');
    assert.ok(controller.active);
    controller.cancel();
    assert.equal(controller.active, null);
    assert.ok(cleared.includes(123));
  } finally {
    globalThis.setTimeout = originalSet;
    globalThis.clearTimeout = originalClear;
    controller?.destroy();
  }
});

test('pagehide closes the command while a back-forward-cache restore keeps the form usable', () => {
  const ui = terminal();
  const first = ui.start('cat');
  ui.window.emit('pagehide', {persisted: true});
  assert.equal(first.readyState, 3);
  assert.equal(ui.controller.active, null);
  assert.equal(ui.elements.composer.disabled, false);
  assert.equal(ui.timers.size, 0);
  // BFCache restores the same document: there is no new module initialization.
  ui.window.emit('pageshow', {persisted: true});
  const second = ui.start('printf restored');
  assert.equal(ui.sockets.length, 2);
  assert.equal(second.sent[0].command, 'printf restored');
  assert.equal(ui.controller.active.started, true);
  first.emit('close');
  assert.equal(ui.controller.active.ws, second);
  ui.controller.destroy();
  assert.equal(ui.elements['command-form'].events.get('submit').size, 0);
});
