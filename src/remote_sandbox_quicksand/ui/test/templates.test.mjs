import assert from 'node:assert/strict';
import test from 'node:test';
import {loadAsset, served} from './load-assets.mjs';

const terminal = await loadAsset('terminal.html');
const proxy = await loadAsset('proxy.html');

test('terminal page provides the browser controller elements and same-origin module', () => {
  for (const id of ['transcript', 'composer', 'run', 'cancel', 'eof', 'clear', 'cwd', 'timeout',
    'command-form', 'connection-status', 'prompt-label', 'input-hint']) {
    assert.match(terminal, new RegExp(`id="${id}"`));
  }
  assert.match(terminal, /<script type="module" src="\/terminal\.js"><\/script>/);
  assert.match(terminal, /<meta name="terminal-token" content="[^"]+">/);
  assert.match(terminal, /<style nonce="[^"]+">/);
  assert.doesNotMatch(terminal, /<script[^>]*src="https?:/);
});

test('proxy page provides the editor elements and nonce-protected inline script', () => {
  for (const id of ['policy', 'save', 'reset', 'edit-state', 'message', 'status', 'rules', 'events',
    'event-count', 'no-events']) {
    assert.match(proxy, new RegExp(`id="${id}"`));
  }
  assert.match(proxy, /<meta name="proxy-token" content="[^"]+">/);
  const nonce = /<style nonce="([^"]+)">/.exec(proxy)?.[1];
  assert.ok(nonce);
  assert.ok(proxy.includes(`<script nonce="${nonce}">`));
  assert.doesNotMatch(proxy, /innerHTML|insertAdjacentHTML|<script[^>]*src=/);
});

test('raw templates expose exactly the documented substitutions', {skip: served}, () => {
  const placeholders = html => [...new Set(html.match(/__[A-Z_]+__/g) || [])].sort();
  assert.deepEqual(placeholders(terminal), [
    '__BRAND__', '__CWD__', '__NETWORK__', '__NONCE__', '__PROXY_LINK__', '__TITLE__', '__TOKEN__',
  ]);
  assert.deepEqual(placeholders(proxy), ['__NONCE__', '__TOKEN__']);
});

test('served pages have resolved title, branding and authentication placeholders', {skip: !served}, () => {
  for (const html of [terminal, proxy]) {
    assert.doesNotMatch(html, /(?:content|nonce)="__(?:TOKEN|NONCE)__"/);
  }
  assert.doesNotMatch(terminal, /<title>__TITLE__<\/title>|class="eyebrow">__BRAND__<|>__NETWORK__<|__PROXY_LINK__<\/header>/);
});
