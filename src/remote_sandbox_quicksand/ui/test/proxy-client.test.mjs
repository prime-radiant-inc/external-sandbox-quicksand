import assert from 'node:assert/strict';
import test from 'node:test';
import {runInNewContext} from 'node:vm';
import {loadAsset} from './load-assets.mjs';

const html = await loadAsset('proxy.html');
const POLICY = {allow: [{origin: 'https://api.example.test', methods: ['GET'], credential: {
  header: 'Authorization', placeholder: 'Bearer demo-token', prefix: 'Bearer ', secretEnv: 'EXAMPLE_API_KEY',
}}], guestEnv: {EXAMPLE_API_KEY: 'demo-token'}};
const snapshot = () => ({enabled: true, policy: structuredClone(POLICY), events: []});

function browser() {
  class Element {
    textContent = ''; className = ''; value = ''; disabled = false; hidden = false;
    children = []; listeners = new Map();
    append(...items) { this.children.push(...items); }
    replaceChildren(...items) { this.children = items; }
    addEventListener(event, listener) { this.listeners.set(event, listener); }
    fire(event) { return this.listeners.get(event)?.(); }
  }
  const elements = new Map();
  const byId = id => { if (!elements.has(id)) elements.set(id, new Element()); return elements.get(id); };
  const pending = [];
  let refresh;
  const script = /<script nonce="[^"]+">([\s\S]*?)<\/script>/.exec(html);
  assert.ok(script, 'Proxy page must contain its nonce-protected browser script');
  runInNewContext(script[1], {
    document: {getElementById: byId, querySelector: () => ({content: 'test-token'}), createElement: () => new Element()},
    fetch: (url, options) => {
      assert.equal(url, '/proxy/api');
      assert.equal(options.credentials, 'omit');
      assert.equal(options.redirect, 'error');
      return new Promise(resolve => pending.push({...options,
        resolve: value => resolve({ok: true, json: async () => value})}));
    },
    setInterval: (fn, ms) => { assert.equal(ms, 3000); refresh = fn; },
  });
  const settle = () => new Promise(resolve => setImmediate(resolve));
  return {byId, pending, refresh, settle};
}

test('proxy client preserves dirty edits during polling and discards to latest policy', async () => {
  const ui = browser();
  assert.equal(ui.pending[0].headers['X-Proxy-Token'], 'test-token');
  ui.pending.shift().resolve(snapshot()); await ui.settle();
  const editor = ui.byId('policy');
  editor.value = '{"allow":[]}'; editor.fire('input');
  assert.equal(ui.byId('save').disabled, false);
  const refresh = ui.refresh();
  const changed = {allow: [{origin: 'https://new.example.test'}]};
  ui.pending.shift().resolve({enabled: true, policy: changed, events: []}); await refresh;
  assert.equal(editor.value, '{"allow":[]}');
  assert.equal(ui.byId('edit-state').textContent, 'Unsaved edits');
  ui.byId('reset').fire('click');
  assert.deepEqual(JSON.parse(editor.value), changed);
  assert.equal(ui.byId('save').disabled, true);
});

test('proxy client ignores stale polls after Apply and renders hostile strings safely', async () => {
  const ui = browser();
  ui.pending.shift().resolve(snapshot()); await ui.settle();
  const oldRefresh = ui.refresh();
  const stale = ui.pending.shift();
  ui.byId('policy').value = 'invalid JSON'; ui.byId('policy').fire('input');
  await ui.byId('save').fire('click');
  assert.equal(ui.pending.length, 0);
  assert.match(ui.byId('message').textContent, /valid JSON/);
  ui.byId('policy').value = '{"allow":[]}'; ui.byId('policy').fire('input');
  const applied = ui.byId('save').fire('click');
  assert.equal(ui.byId('policy').disabled, true);
  assert.equal(ui.pending[0].method, 'PUT');
  assert.deepEqual(JSON.parse(ui.pending[0].body), {allow: []});
  const hostile = '<img src=x onerror=alert(1)>';
  ui.pending.shift().resolve({enabled: true, policy: {allow: []}, events: [{reason: hostile}]});
  await applied;
  stale.resolve(snapshot()); await oldRefresh;
  assert.deepEqual(JSON.parse(ui.byId('policy').value), {allow: []});
  assert.equal(ui.byId('events').children[0].children[3].textContent, hostile);
  assert.equal(ui.byId('policy').disabled, false);
});
