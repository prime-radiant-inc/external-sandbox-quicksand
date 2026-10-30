"""Host end of the guestfwd proxy transport, with a fake helper and the real Go helper."""
import asyncio
import contextlib
import os
import shutil
import socket
import subprocess
from pathlib import Path

import pytest

from external_sandbox_quicksand.proxy_bridge import (DATA, END, HEADER, MAGIC, MAX_CHANNELS, OPEN, RESET, MuxBridge,
                                                   guestfwd_netdev_args)

ROOT = Path(__file__).resolve().parents[1]


@contextlib.asynccontextmanager
async def echo_target(*, respond_after_eof=False):
    """A stand-in for the host proxy: echoes, optionally only after the client half-closes."""
    connections = []

    async def handle(reader, writer):
        connections.append(writer)
        if respond_after_eof:
            data = await reader.read()
            writer.write(b"reply:" + data)
        else:
            while data := await reader.read(65536):
                writer.write(data)
                await writer.drain()
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    try:
        yield server.sockets[0].getsockname()[:2], connections
    finally:
        server.close()
        for writer in connections:
            writer.close()


class FakeHelper:
    """The guest-mux side of the stream, as QEMU would deliver it."""

    def __init__(self, reader, writer):
        self.reader, self.writer = reader, writer

    @classmethod
    async def connect(cls, bridge, *, handshake=True):
        reader, writer = await asyncio.open_connection("127.0.0.1", bridge.port)
        helper = cls(reader, writer)
        if handshake:
            writer.write(MAGIC)
            assert await asyncio.wait_for(reader.readexactly(len(MAGIC)), 5) == MAGIC
        return helper

    def send(self, kind, channel, data=b""):
        self.writer.write(HEADER.pack(kind, channel, len(data)) + data)

    async def frame(self):
        kind, channel, size = HEADER.unpack(await asyncio.wait_for(self.reader.readexactly(HEADER.size), 5))
        return kind, channel, await self.reader.readexactly(size)

    async def collect(self, channel):
        data = bytearray()
        while True:
            kind, ident, payload = await self.frame()
            assert ident == channel
            if kind == DATA:
                data += payload
            else:
                return kind, bytes(data)


def test_netdev_is_restricted_and_has_one_forward():
    assert guestfwd_netdev_args(1234, mmio=False) == [
        "-netdev", "user,id=rsnet,restrict=on,guestfwd=tcp:10.0.2.101:3128-tcp:127.0.0.1:1234",
        "-device", "virtio-net-pci,netdev=rsnet"]
    with pytest.raises(ValueError):
        guestfwd_netdev_args(0, mmio=True)
    with pytest.raises(ValueError, match="loopback"):
        MuxBridge(("0.0.0.0", 80))


async def test_channels_reach_only_the_fixed_target_and_half_close():
    async with echo_target(respond_after_eof=True) as (target, _):
        bridge = await MuxBridge(target).start()
        try:
            helper = await FakeHelper.connect(bridge)
            await bridge.wait_ready(5)
            assert bridge.connected
            for channel in (1, 2):
                helper.send(OPEN, channel)
                helper.send(DATA, channel, f"request-{channel}".encode())
                helper.send(END, channel)
            replies = {}
            for _ in range(4):
                kind, channel, payload = await helper.frame()
                replies.setdefault(channel, []).append((kind, payload))
            assert replies == {1: [(DATA, b"reply:request-1"), (END, b"")],
                               2: [(DATA, b"reply:request-2"), (END, b"")]}
        finally:
            await bridge.close()


async def test_unknown_channel_data_and_unreachable_target_reset():
    unused = socket.socket()
    unused.bind(("127.0.0.1", 0))
    port = unused.getsockname()[1]
    unused.close()
    bridge = await MuxBridge(("127.0.0.1", port)).start()
    try:
        helper = await FakeHelper.connect(bridge)
        helper.send(DATA, 9, b"orphan")
        assert await helper.frame() == (RESET, 9, b"")
        helper.send(OPEN, 3)
        assert await helper.frame() == (RESET, 3, b"")
    finally:
        await bridge.close()


async def test_channel_limit_resets_excess_opens():
    async with echo_target() as (target, _):
        bridge = await MuxBridge(target).start()
        try:
            helper = await FakeHelper.connect(bridge)
            for channel in range(1, MAX_CHANNELS + 2):
                helper.send(OPEN, channel)
            assert await helper.frame() == (RESET, MAX_CHANNELS + 1, b"")
            helper.send(DATA, 1, b"still-works")
            assert await helper.frame() == (DATA, 1, b"still-works")
        finally:
            await bridge.close()


@pytest.mark.parametrize("frame", [HEADER.pack(OPEN, 0, 0), HEADER.pack(9, 1, 0),
                                   HEADER.pack(END, 1, 1) + b"x", HEADER.pack(DATA, 1, 65537)])
async def test_invalid_frames_close_the_transport(frame):
    async with echo_target() as (target, _):
        bridge = await MuxBridge(target).start()
        try:
            helper = await FakeHelper.connect(bridge)
            helper.writer.write(frame)
            await asyncio.wait_for(bridge.closed.wait(), 5)
            assert not bridge.connected and isinstance(bridge.error, ValueError)
            assert await helper.reader.read() == b""
        finally:
            await bridge.close()


async def test_bad_handshake_fails_wait_and_transport_is_never_replaced():
    async with echo_target() as (target, _):
        bridge = await MuxBridge(target).start()
        try:
            helper = await FakeHelper.connect(bridge, handshake=False)
            helper.writer.write(b"X" * len(MAGIC))
            with pytest.raises(RuntimeError, match="did not connect"):
                await bridge.wait_ready(5)
            # A second connection (a QEMU reconnect or another local process) is refused.
            late = await FakeHelper.connect(bridge, handshake=False)
            late.writer.write(MAGIC)
            try:
                assert await asyncio.wait_for(late.reader.read(), 5) == b""
            except ConnectionResetError:
                pass  # Closed with our handshake unread; either way, no session.
        finally:
            await bridge.close()


async def test_wait_ready_times_out_without_helper():
    async with echo_target() as (target, _):
        bridge = await MuxBridge(target).start()
        try:
            with pytest.raises(RuntimeError, match="did not connect"):
                await bridge.wait_ready(0.1)
        finally:
            await bridge.close()


@pytest.fixture(scope="module")
def host_helper(tmp_path_factory):
    """Compile the bundled guest_mux.go for this host so it can run against the bridge."""
    go = shutil.which("go")
    if go is None:
        pytest.skip("Go is required to run the real guest-mux helper on the host")
    output = tmp_path_factory.mktemp("guest-mux") / "guest-mux"
    subprocess.run([go, "build", "-o", str(output), str(ROOT / "guest-mux" / "guest_mux.go")],
                   check=True, env={**os.environ, "CGO_ENABLED": "0"}, timeout=300)
    return output


async def test_real_go_helper_multiplexes_concurrent_connections(host_helper):
    async with echo_target() as (target, _):
        bridge = await MuxBridge(target).start()
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        listen_port = probe.getsockname()[1]
        probe.close()
        helper = await asyncio.create_subprocess_exec(
            str(host_helper), f"127.0.0.1:{listen_port}", f"127.0.0.1:{bridge.port}",
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE)
        try:
            await bridge.wait_ready(10)

            async def round_trip(index):
                reader, writer = await asyncio.open_connection("127.0.0.1", listen_port)
                payload = bytes([index]) * (200_000 + index)
                writer.write(payload)
                await writer.drain()
                received = await reader.readexactly(len(payload))
                writer.close()
                return received == payload

            assert all(await asyncio.gather(*(round_trip(i) for i in range(8))))
        finally:
            await bridge.close()
            # Losing the stream stops the helper: no reconnect, no direct route.
            assert await asyncio.wait_for(helper.wait(), 10) == 1
