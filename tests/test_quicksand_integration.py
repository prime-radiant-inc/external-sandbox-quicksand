"""Opt-in real Quicksand VM tests. No model calls or host shell execution."""
import asyncio
import base64
import json
import os

import pytest
import pytest_asyncio

from remote_sandbox_quicksand.backend import QuicksandBackend, parse_mounts
from remote_sandbox_quicksand.images import resolve_image

pytestmark = [pytest.mark.integration, pytest.mark.asyncio(loop_scope='module'),
              pytest.mark.skipif(os.environ.get('RUN_QUICKSAND_TESTS') != '1', reason='Set RUN_QUICKSAND_TESTS=1')]


async def test_backend(mounts=(), proxy=None, packages=None):
    """SANDBOX_TEST_IMAGE selects alpine (default, prepared and cached) or ubuntu."""
    image = await resolve_image(os.environ.get('SANDBOX_TEST_IMAGE', 'alpine'), packages)
    return QuicksandBackend(list(mounts), image=image.reference, image_label=image.label, proxy=proxy)


test_backend.__test__ = False


@pytest_asyncio.fixture(scope='module', loop_scope='module')
async def sandbox(tmp_path_factory):
    root = tmp_path_factory.mktemp('quicksand')
    rw, ro = root / 'project', root / 'reference'
    rw.mkdir()
    ro.mkdir()
    (ro / 'input.txt').write_text('reference data')
    backend = await test_backend(parse_mounts([(f'project={rw}', 'rw'), (f'reference={ro}', 'ro')], True))
    await backend.boot()
    try:
        yield backend, rw, ro
    finally:
        await backend.close()


async def collect(process):
    out, err = bytearray(), bytearray()
    async with asyncio.timeout(15):
        while True:
            event = await process.events.get()
            if event['type'] == 'stdout':
                out.extend(base64.b64decode(event['data']))
            elif event['type'] == 'stderr':
                err.extend(base64.b64decode(event['data']))
            elif event['type'] == 'exit':
                return bytes(out), bytes(err), event
            else:
                pytest.fail(str(event))


async def test_real_incremental_binary_io(sandbox):
    backend, _, _ = sandbox
    process = await backend.start(['/bin/bash', '-c', 'printf ready; cat; printf problem >&2; exit 7'])
    first = await asyncio.wait_for(process.events.get(), 5)
    assert base64.b64decode(first['data']) == b'ready'
    # Input is withheld until output arrives, proving full duplex streaming.
    await process.write(b'\x00\xffhello\n')
    echoed = await asyncio.wait_for(process.events.get(), 5)
    assert base64.b64decode(echoed['data']) == b'\x00\xffhello\n'
    await process.close_stdin()
    out, err, exit_event = await collect(process)
    assert out == b'' and err == b'problem'
    assert exit_event['exitCode'] == 7 and exit_event['signal'] is None


async def test_actual_mounts_network_and_literal_argv(sandbox):
    backend, rw, ro = sandbox
    process = await backend.start(['/bin/bash', '-c',
        'uname -s; cat /mnt/reference/input.txt; echo written > /mnt/project/result; '
        'echo forbidden > /mnt/reference/input.txt; '
        'test ! -e /sys/class/net/eth0; printf "network=%s\\n" "$?"'], stdin=False)
    out, err, event = await collect(process)
    assert b'Linux' in out and b'network=0' in out
    assert b'Read-only file system' in err
    assert (rw / 'result').read_text() == 'written\n'
    assert (ro / 'input.txt').read_text() == 'reference data'
    literal = '$(touch /mnt/project/not-created); echo unsafe'
    process = await backend.start(['/usr/bin/python3', '-c', 'import sys;print(sys.argv[1])', literal], stdin=False)
    assert (await collect(process))[0] == (literal + '\n').encode()
    assert not (rw / 'not-created').exists()


async def test_guest_environment_replacement(sandbox):
    backend, _, _ = sandbox
    process = await backend.start(['/usr/bin/python3', '-c', 'import os,json;print(json.dumps(dict(os.environ)))'],
                                  env={'ONLY_VALUE': 'guest', 'LC_CTYPE': 'C.UTF-8'}, stdin=False)
    env = json.loads((await collect(process))[0])
    assert env == {'ONLY_VALUE': 'guest', 'LC_CTYPE': 'C.UTF-8'}


async def test_timeout_output_limit_cancel_and_signal(sandbox):
    backend, _, _ = sandbox
    process = await backend.start(['/bin/bash', '-c', 'sleep 60'], timeout_ms=100, stdin=False)
    result = (await collect(process))[2]
    assert result['timedOut'] and result['signal'] == 9
    process = await backend.start(['/bin/bash', '-c', 'yes x'], max_output_bytes=1024, stdin=False)
    out, _, event = await collect(process)
    assert len(out) == 1024 and event['outputLimitExceeded']
    process = await backend.start(['/bin/bash', '-c', 'sleep 60'], stdin=False)
    await process.terminate()
    assert (await collect(process))[2]['signal'] == 9
    process = await backend.start(['/usr/bin/python3', '-u', '-c',
        'import signal,time,sys;signal.signal(signal.SIGINT,lambda *a:sys.exit(42));print("ready");time.sleep(60)'], stdin=False)
    assert base64.b64decode((await asyncio.wait_for(process.events.get(), 5))['data']) == b'ready\n'
    await process.signal(2)
    assert (await collect(process))[2]['exitCode'] == 42


async def test_guest_filesystem_and_readonly(sandbox):
    backend, rw, _ = sandbox
    session = 'integration'
    await backend.fs('fs/writeFile', {'path': 'file:///mnt/project/binary', 'dataBase64': 'AP8='}, session)
    assert (rw / 'binary').read_bytes() == b'\x00\xff'
    data = await backend.fs('fs/readFile', {'path': 'file:///mnt/project/binary'}, session)
    assert data['dataBase64'] == 'AP8='
    with pytest.raises(RuntimeError):
        await backend.fs('fs/writeFile', {'path': 'file:///mnt/reference/blocked', 'dataBase64': 'YQ=='}, session)
    await backend.close_fs_session(session)


async def test_concurrent_commands_and_descendant_cleanup(sandbox):
    backend, _, _ = sandbox
    jobs = await asyncio.gather(*(backend.start(['/bin/bash', '-c', f'printf {i}; sleep .05'], stdin=False) for i in range(8)))
    results = await asyncio.gather(*(collect(job) for job in jobs))
    assert [r[0] for r in results] == [str(i).encode() for i in range(8)]
    child = await backend.start(['/bin/bash', '-c', 'sleep 60 & echo $!'], stdin=False)
    pid = int((await collect(child))[0])
    check = await backend.start(['/bin/bash', '-c', f'test ! -e /proc/{pid}/stat || test "$(cut -d" " -f3 /proc/{pid}/stat)" = Z'], stdin=False)
    assert (await collect(check))[2]['exitCode'] == 0


async def test_escaped_descendant_does_not_hold_request_open(sandbox):
    backend, _, _ = sandbox
    # New session escapes process-group cancellation and inherits stdout.
    script = ('import os,time; p=os.fork(); '
              'os._exit(0) if p else None; os.setsid(); time.sleep(60)')
    process = await backend.start(['/usr/bin/python3', '-c', script], stdin=False, timeout_ms=100)
    async with asyncio.timeout(5):
        while True:
            event = await process.events.get()
            if event['type'] == 'error':
                assert 'retained output pipes' in event['error']
                break
            assert event['type'] != 'exit'
    # It is still isolated in this disposable VM, removed at fixture teardown.


async def test_preserved_host_paths_keep_mount_modes(sandbox):
    backend, rw, ro = sandbox
    rw_alias, ro_alias = backend.mounts[0].preservedPaths[-1], backend.mounts[1].preservedPaths[-1]
    process = await backend.start(['/bin/bash', '-c', 'pwd; cat "$1/input.txt"; echo via-alias > result-alias; '
                                   'echo forbidden > "$1/input.txt"', 'bash', ro_alias], cwd=rw_alias, stdin=False)
    out, err, event = await collect(process)
    assert out == f'{rw_alias}\nreference data'.encode()
    assert b'Read-only file system' in err and event['exitCode'] == 1
    assert (rw / 'result-alias').read_text() == 'via-alias\n'
    assert (ro / 'input.txt').read_text() == 'reference data'


async def test_health_reports_quicksand_details(sandbox):
    backend, _, _ = sandbox
    info = backend.info()
    assert info['backend'] == 'quicksand' and info['shell'] == '/bin/bash'
    assert info['network'] is False and info['proxyEnabled'] is False and 'proxyTransport' not in info
    assert info['architecture'] in ('aarch64', 'x86_64') and info['accelerator']
