"""Host end of the guest proxy transport, multiplexed over one QEMU guestfwd stream.

QEMU's ``guestfwd=...-tcp:`` backend is one persistent character stream opened
when QEMU starts, not one host socket per guest connection. The bundled static
``guest-mux`` helper listens on guest loopback and multiplexes each guest
connection over that stream. This bridge demultiplexes channels and connects
each one to the fixed host proxy address. The guest can never choose a
destination; policy, TLS interception and credentials stay in the host proxy.

Adapted from the Quicksand parent-process egress proxy prototype.
"""
from __future__ import annotations

import asyncio
import contextlib
import struct

MAGIC = b"QUICKSAND-PROXY-MUX/1\n"
HEADER = struct.Struct("!BII")
OPEN, DATA, END, RESET = 1, 2, 3, 4
MAX_FRAME = 65536
MAX_CHANNELS = 64
QUEUED_FRAMES = 8
HANDSHAKE_TIMEOUT = 120
STALL_TIMEOUT = 30

GUEST_ADDRESS = "10.0.2.101"
GUEST_PORT = 3128
GUEST_LISTEN = f"127.0.0.1:{GUEST_PORT}"


def guestfwd_netdev_args(bridge_port: int, *, mmio: bool) -> list[str]:
    """A private restricted NIC whose only host path is the bridge stream."""
    if not 1 <= bridge_port <= 65535:
        raise ValueError("Bridge port must be between 1 and 65535")
    device = "virtio-net-device" if mmio else "virtio-net-pci"
    return ["-netdev", f"user,id=rsnet,restrict=on,guestfwd=tcp:{GUEST_ADDRESS}:{GUEST_PORT}"
                       f"-tcp:127.0.0.1:{bridge_port}",
            "-device", f"{device},netdev=rsnet"]


class MuxBridge:
    """Accept QEMU's single guestfwd connection and bridge its channels to ``target``."""

    def __init__(self, target: tuple[str, int]):
        host, port = target
        if host != "127.0.0.1":
            raise ValueError("Bridge target must be an IPv4 loopback address")
        self.target = (host, port)
        self.port = 0
        self.server = None
        self.ready = asyncio.Event()
        self.closed = asyncio.Event()
        self.writer = None
        self.session_task = None
        self.tasks = set()
        self.channels = {}
        self.write_lock = asyncio.Lock()
        self.error = None
        self.used = False

    async def start(self):
        self.server = await asyncio.start_server(self._accept, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    @property
    def connected(self):
        return self.ready.is_set() and not self.closed.is_set()

    async def _send(self, kind, channel, data=b""):
        async with asyncio.timeout(STALL_TIMEOUT):
            async with self.write_lock:
                if self.writer is None:
                    raise ConnectionError("Guest proxy transport is unavailable")
                self.writer.write(HEADER.pack(kind, channel, len(data)) + data)
                await self.writer.drain()

    async def _accept(self, reader, writer):
        # QEMU connects once at startup. A transport is never reused or replaced:
        # after it closes, guest proxy access fails closed until restart.
        if self.used:
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()
            return
        self.used = True
        self.writer = writer
        self.session_task = asyncio.current_task()
        try:
            magic = await asyncio.wait_for(reader.readexactly(len(MAGIC)), HANDSHAKE_TIMEOUT)
            if magic != MAGIC:
                raise ValueError("Invalid guest proxy transport handshake")
            writer.write(MAGIC)
            await writer.drain()
            self.ready.set()
            while True:
                kind, channel, size = HEADER.unpack(await reader.readexactly(HEADER.size))
                if size > MAX_FRAME or channel == 0 or kind not in (OPEN, DATA, END, RESET):
                    raise ValueError("Invalid guest proxy transport frame")
                if kind != DATA and size:
                    raise ValueError("Unexpected guest proxy control-frame payload")
                payload = await reader.readexactly(size)
                if kind == OPEN:
                    if channel in self.channels:
                        raise ValueError("Duplicate guest proxy channel")
                    if len(self.channels) >= MAX_CHANNELS:
                        await self._send(RESET, channel)
                        continue
                    queue = asyncio.Queue(maxsize=QUEUED_FRAMES)
                    self.channels[channel] = queue
                    task = asyncio.create_task(self._channel(channel, queue))
                    self.tasks.add(task)
                    task.add_done_callback(self.tasks.discard)
                elif channel in self.channels:
                    # Bound head-of-line blocking even if a channel's consumer
                    # exits while its inbox is full. A stalled mux fails closed.
                    await asyncio.wait_for(self.channels[channel].put((kind, payload)), STALL_TIMEOUT)
                elif kind == DATA:
                    await self._send(RESET, channel)
        except asyncio.CancelledError:
            raise
        except (OSError, ValueError, asyncio.IncompleteReadError, TimeoutError) as exc:
            self.error = exc
        finally:
            self.closed.set()
            for task in tuple(self.tasks):
                task.cancel()
            await asyncio.gather(*tuple(self.tasks), return_exceptions=True)
            self.channels.clear()
            self.writer = None
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()

    async def _channel(self, channel, queue):
        writer = upstream = downstream = None
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(*self.target), 10)

            async def guest_to_proxy():
                while True:
                    kind, data = await queue.get()
                    if kind == DATA:
                        writer.write(data)
                        await asyncio.wait_for(writer.drain(), STALL_TIMEOUT)
                    elif kind == END:
                        if writer.can_write_eof():
                            writer.write_eof()
                        else:
                            writer.close()
                        return
                    else:
                        writer.close()
                        raise ConnectionResetError("Guest reset channel")

            async def proxy_to_guest():
                while data := await reader.read(MAX_FRAME):
                    await self._send(DATA, channel, data)
                await self._send(END, channel)

            upstream = asyncio.create_task(guest_to_proxy())
            downstream = asyncio.create_task(proxy_to_guest())
            completed, _ = await asyncio.wait((upstream, downstream), return_when=asyncio.FIRST_COMPLETED)
            if upstream in completed:
                # END is a normal half-close: the proxy may still send a response.
                # Drain failures and RESET propagate immediately.
                upstream.result()
            await downstream
        except asyncio.CancelledError:
            raise
        except (OSError, ConnectionError, TimeoutError):
            with contextlib.suppress(OSError, ConnectionError, TimeoutError):
                await self._send(RESET, channel)
        finally:
            self.channels.pop(channel, None)
            tasks = [task for task in (upstream, downstream) if task]
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            if writer:
                writer.close()
                with contextlib.suppress(OSError):
                    await writer.wait_closed()

    async def wait_ready(self, timeout):
        """Wait for the guest helper handshake, failing early if the stream closes."""
        ready = asyncio.create_task(self.ready.wait())
        closed = asyncio.create_task(self.closed.wait())
        try:
            done, _ = await asyncio.wait((ready, closed), timeout=timeout, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for task in (ready, closed):
                task.cancel()
        if not self.ready.is_set():
            reason = f": {self.error}" if self.error else ""
            raise RuntimeError(f"Guest proxy transport did not connect{reason}")

    async def close(self):
        # Server.wait_closed() waits for active connections, so end the session first.
        if self.server:
            self.server.close()
        if self.session_task and not self.session_task.done():
            self.session_task.cancel()
            await asyncio.gather(self.session_task, return_exceptions=True)
        if self.server:
            await self.server.wait_closed()
            self.server = None
