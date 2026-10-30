"""Start the compatible localhost APIs with a disposable Quicksand virtual machine."""
import argparse
import asyncio
import contextlib
import json
import signal
import sys

from aiohttp import web

from .api import create_app
from .backend import QuicksandBackend, parse_mounts
from .images import resolve_image
from .proxy import HostProxy, load_policy


class MountAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        mounts = list(getattr(namespace, self.dest, None) or [])
        mounts.append((values, "ro" if option_string == "--mount-ro" else "rw"))
        setattr(namespace, self.dest, mounts)


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("paths", nargs="*", help="Writable host directories (same as --mount-rw)")
    result.add_argument("--image", default="alpine",
                        help="alpine (default, prepared once with bash and python3), ubuntu (requires the "
                             "ubuntu extra), or a Quicksand save directory providing /bin/bash and python3")
    result.add_argument("--packages", metavar="LIST",
                        help="Comma-separated Alpine packages for the prepared image, in addition to bash and "
                             "python3 (default: git,ripgrep); changing the list prepares a new cached image")
    result.add_argument("--cache-dir", metavar="DIR", help="Prepared image cache (default: ~/.cache/external-sandbox-quicksand)")
    result.add_argument("--prepare-image", action="store_true", help="Prepare the selected image, then exit")
    result.add_argument("--port", type=int, default=8688, help="Loopback TCP port (default: 8688); 0 selects an available port")
    result.add_argument("--cpus", type=int, default=2)
    result.add_argument("--memory", type=int, default=1024, help="VM memory in MiB")
    result.add_argument("--accel", choices=["auto", "tcg"], default="auto",
                        help="Hardware acceleration (HVF/KVM/WHPX) when available, or tcg software emulation")
    result.add_argument("--mount", "--mount-ro", "--mount-rw", dest="mounts", action=MountAction,
                        metavar="[NAME=]PATH", help="Share a host directory; --mount is read-write")
    result.add_argument("--preserve-paths", action="store_true", help="Also mount host directories at their original absolute paths")
    result.add_argument("--proxy-config", metavar="PATH", help="Enable host-enforced HTTP(S) egress using this allow-list JSON file")
    return result


async def serve(args):
    if not 0 <= args.port <= 65535:
        raise ValueError("Port must be between 0 and 65535")
    if not 1 <= args.cpus <= 64 or not 256 <= args.memory <= 65536:
        raise ValueError("CPUs must be 1–64 and memory 256–65536 MiB")
    mounts = parse_mounts([*(args.mounts or []), *((path, "rw") for path in args.paths)], args.preserve_paths)
    proxy = HostProxy(load_policy(args.proxy_config)) if args.proxy_config else None
    accel = None if args.accel == "tcg" else "auto"
    backend = QuicksandBackend(mounts, cpus=args.cpus, memory=args.memory, accel=accel, proxy=proxy)
    runner = None
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    async def start_sandbox():
        image = await resolve_image(args.image, args.packages, args.cache_dir, accel)
        backend.image, backend.image_label = image.reference, image.label
        if proxy:
            await proxy.start()
        await backend.boot()

    boot = asyncio.create_task(start_sandbox())
    stopping = asyncio.create_task(stop.wait())
    try:
        done, _ = await asyncio.wait([boot, stopping], return_when=asyncio.FIRST_COMPLETED)
        if stopping in done:
            boot.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await boot
            return
        await boot
        app = create_app(backend, proxy=proxy)
        runner = web.AppRunner(app, handler_cancellation=True, shutdown_timeout=5)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", args.port)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        info = {"event": "listening", "url": f"http://127.0.0.1:{port}", **backend.info()}
        if proxy:
            info["proxyManagementUrl"] = f"http://127.0.0.1:{port}/proxy"
        print(json.dumps(info), flush=True)
        # Loss of the sandbox is fatal. Never keep serving against a missing backend.
        done, _ = await asyncio.wait([stopping, backend.reader_task], return_when=asyncio.FIRST_COMPLETED)
        if backend.reader_task in done and not stop.is_set():
            raise RuntimeError("Guest agent stopped unexpectedly")
    finally:
        stopping.cancel()
        if not boot.done():
            boot.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await boot
        try:
            if runner:
                await runner.cleanup()
        finally:
            try:
                await backend.close()
            finally:
                try:
                    if proxy:
                        await proxy.close()
                finally:
                    for sig in (signal.SIGINT, signal.SIGTERM):
                        loop.remove_signal_handler(sig)


async def prepare(args):
    image = await resolve_image(args.image, args.packages, args.cache_dir, None if args.accel == "tcg" else "auto")
    print(json.dumps({"event": "prepared", "image": image.label, "reference": image.reference}), flush=True)


def main():
    args = parser().parse_args()
    try:
        asyncio.run(prepare(args) if args.prepare_image else serve(args))
    except (OSError, ValueError, RuntimeError, TimeoutError) as exc:
        print(f"external-sandbox-quicksand: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
