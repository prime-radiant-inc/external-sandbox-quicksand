import asyncio
import json
import shlex
import struct
from types import SimpleNamespace

import pytest

from external_sandbox_quicksand.backend import AGENT_PORT_NAME, GUEST_DIR, QuicksandBackend, Process, parse_mounts


def test_mount_modes_and_aliases(tmp_path):
    directory = tmp_path / 'a directory'
    directory.mkdir()
    mounts = parse_mounts([('project=' + str(directory), 'ro')], True)
    assert mounts[0].guestPath == '/mnt/project'
    assert mounts[0].preservedPaths == [str(directory)]
    backend = QuicksandBackend(mounts)
    captured = {}
    backend.sandbox_factory = lambda **kwargs: captured.update(kwargs)
    backend.create_sandbox('/tmp/rsq-test/agent.sock')
    assert str(captured['network_mode']) == 'none'
    [mount] = captured['mounts']
    assert (mount.host, mount.guest, mount.readonly, mount.type) == (str(directory), '/mnt/project', True, '9p')
    assert backend.info()['network'] is False and backend.info()['backend'] == 'quicksand'


def test_agent_port_without_proxy_has_no_network_interface():
    args = QuicksandBackend().qemu_args('/tmp/rsq-x/agent.sock')
    assert args == ['-chardev', 'socket,path=/tmp/rsq-x/agent.sock,server=on,wait=off,id=rsagent',
                    '-device', f'virtserialport,chardev=rsagent,name={AGENT_PORT_NAME}']
    assert not any('netdev' in arg or 'nic' in arg for arg in args)


def test_proxy_adds_only_a_restricted_guestfwd_interface():
    backend = QuicksandBackend(proxy=object())
    backend.bridge = SimpleNamespace(port=45678)
    args = backend.qemu_args('/tmp/rsq-x/agent.sock')
    netdev = args[args.index('-netdev') + 1]
    assert netdev == 'user,id=rsnet,restrict=on,guestfwd=tcp:10.0.2.101:3128-tcp:127.0.0.1:45678'
    assert 'hostfwd' not in netdev and args[-1].endswith(',netdev=rsnet')


def test_overlapping_ro_rw_mounts_rejected(tmp_path):
    (tmp_path / 'child').mkdir()
    with pytest.raises(ValueError, match='overlap'):
        parse_mounts([(f'parent={tmp_path}', 'rw'), (f'child={tmp_path}/child', 'ro')])
    alias = tmp_path / 'alias'
    alias.symlink_to(tmp_path / 'child')
    with pytest.raises(ValueError, match='overlap'):
        parse_mounts([(f'a={alias}', 'rw'), (f'b={tmp_path}/child', 'ro')])


def test_reserved_aliases_and_mount_injection_rejected(tmp_path):
    with pytest.raises(ValueError, match='system path'):
        parse_mounts([('project=/tmp', 'rw')], True)
    directory = tmp_path / 'x,readonly'
    directory.mkdir()
    with pytest.raises(ValueError, match='commas'):
        parse_mounts([('project=' + str(directory), 'rw')])


async def test_slow_process_consumer_is_bounded_and_killed():
    class Backend:
        def __init__(self):
            self.killed = []
        async def _terminate_quietly(self, ident):
            self.killed.append(ident)
    backend = Backend()
    process = Process(backend, '1')
    for _ in range(65):
        process.feed({'type': 'stdout', 'data': 'YQ=='})
    await asyncio.sleep(0)
    assert process.events.qsize() == 1
    assert (await process.events.get())['type'] == 'error'
    assert backend.killed == ['1']


class FakeSandbox:
    """Stands in for Quicksand: owns the agent socket and plays the private guest agent."""

    def __init__(self, socket_path, *, bash=True, start_agent=True):
        self.socket_path, self.bash, self.start_agent = str(socket_path), bash, start_agent
        self.commands = []
        self.is_running = False
        self.accelerator = SimpleNamespace(value='hvf')
        self.server = None
        self.guest = None
        self.requests = []
        self.stopped = self.cleaned = False

    async def start(self):
        self.server = await asyncio.start_unix_server(self._connected, self.socket_path)
        self.is_running = True

    async def _connected(self, reader, writer):
        self.guest = (reader, writer)

    async def execute(self, command, timeout=30, stdin=None):
        self.commands.append((command, stdin))
        if 'guest_agent.py --port' in command and self.start_agent:
            asyncio.create_task(self._agent())
        return SimpleNamespace(stdout='aarch64\n' if command == 'uname -m' else '', stderr='', exit_code=0)

    async def _agent(self):
        while self.guest is None:
            await asyncio.sleep(0.01)
        reader, writer = self.guest

        def send(value):
            data = json.dumps(value).encode()
            writer.write(struct.pack('>I', len(data)) + data)

        send({'event': 'ready', 'environment': {'PATH': '/usr/bin'}, 'architecture': 'aarch64', 'bash': self.bash})
        while True:
            try:
                size = struct.unpack('>I', await reader.readexactly(4))[0]
            except asyncio.IncompleteReadError:
                return
            request = json.loads(await reader.readexactly(size))
            self.requests.append(request)
            send({'id': request['id'], 'result': {'echo': request['method']}})

    async def stop(self):
        self.stopped, self.is_running = True, False
        self.server.close()

    async def _cleanup(self):
        self.cleaned = True


def fake_backend(tmp_path, **options):
    mounts = parse_mounts([(f'project={tmp_path}', 'ro')], True)
    backend = QuicksandBackend(mounts)
    sandboxes = []

    def create_sandbox(socket_path):
        sandboxes.append(FakeSandbox(socket_path, **options))
        return sandboxes[-1]

    backend.create_sandbox = create_sandbox
    return backend, sandboxes


async def test_boot_installs_agent_files_binds_aliases_and_connects(tmp_path):
    backend, sandboxes = fake_backend(tmp_path)
    await backend.boot()
    try:
        [sandbox] = sandboxes
        commands = [command for command, _ in sandbox.commands]
        assert commands[0] == f'mkdir -p {GUEST_DIR} && chmod 755 {GUEST_DIR}'
        assert any(c.startswith(f'cat > {GUEST_DIR}/guest_agent.py') for c in commands)
        assert any(c.startswith(f'cat > {GUEST_DIR}/guest_fs.py') for c in commands)
        assert not any('guest-mux' in c for c in commands), 'No proxy helper without a proxy policy'
        alias = shlex.quote(str(tmp_path.resolve()))
        assert (f'mkdir -p {alias} && mount --bind /mnt/project {alias} && mount -o remount,bind,ro {alias}'
                in commands)
        launch = commands[-1]
        assert launch.startswith('EXTERNAL_SANDBOX_QUICKSAND_GUEST=1 setsid python3 -I -u')
        assert f'--port /dev/virtio-ports/{AGENT_PORT_NAME}' in launch and launch.endswith('&')
        assert backend.info()['accelerator'] == 'hvf' and backend.architecture == 'aarch64'
        assert await backend._rpc('fs', {}) == {'echo': 'fs'}
    finally:
        await backend.close()
    assert sandbox.stopped and backend.closed


async def test_boot_rejects_image_without_bash_and_stops_vm(tmp_path):
    backend, sandboxes = fake_backend(tmp_path, bash=False)
    with pytest.raises(RuntimeError, match='/bin/bash'):
        await backend.boot()
    assert sandboxes[0].stopped and backend.closed


async def test_boot_reports_agent_log_when_agent_never_starts(tmp_path, monkeypatch):
    backend, sandboxes = fake_backend(tmp_path, start_agent=False)
    real_wait_for = asyncio.wait_for

    async def short_wait(awaitable, timeout):
        return await real_wait_for(awaitable, min(timeout, 0.2))

    monkeypatch.setattr(asyncio, 'wait_for', short_wait)
    with pytest.raises(RuntimeError, match='Guest agent did not start'):
        await backend.boot()
    assert sandboxes[0].commands[-1][0].startswith('tail -c 4000 ')


async def test_lost_agent_connection_fails_running_processes(tmp_path):
    backend, sandboxes = fake_backend(tmp_path)
    await backend.boot()
    try:
        process = Process(backend, 'p1')
        backend.processes['p1'] = process
        sandboxes[0].guest[1].close()
        await asyncio.wait_for(backend.reader_task, 5)
        event = await process.events.get()
        assert event['type'] == 'error' and 'Guest agent disconnected' in event['error']
        with pytest.raises(RuntimeError, match='not running'):
            await backend._rpc('fs', {})
    finally:
        await backend.close()
