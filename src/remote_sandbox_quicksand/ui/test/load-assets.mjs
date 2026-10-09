import {readFile} from 'node:fs/promises';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

const directory = process.env.REMOTE_SANDBOX_UI_ASSETS;
const origin = process.env.REMOTE_SANDBOX_UI_URL;
if (directory && origin) throw new Error('Set only one of REMOTE_SANDBOX_UI_ASSETS and REMOTE_SANDBOX_UI_URL.');

const routes = {'terminal.html': '/', 'terminal.js': '/terminal.js', 'proxy.html': '/proxy'};
const localAssets = directory ? resolve(directory) : fileURLToPath(new URL('../assets/', import.meta.url));
export const served = Boolean(origin);

export async function loadAsset(name) {
  if (!Object.hasOwn(routes, name)) throw new Error(`Unknown UI asset: ${name}`);
  if (!origin) return readFile(resolve(localAssets, name), 'utf8');
  const url = new URL(origin);
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) {
    throw new Error('REMOTE_SANDBOX_UI_URL must be an HTTP(S) URL without credentials.');
  }
  const response = await fetch(new URL(routes[name], url), {
    method: 'GET', credentials: 'omit', redirect: 'error', signal: AbortSignal.timeout(10000),
  });
  if (!response.ok) throw new Error(`Cannot load ${name}: HTTP ${response.status}`);
  return response.text();
}

export async function loadModule(name) {
  const source = await loadAsset(name);
  return import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);
}
