"""asyncio networking for the simulation nodes.

Every node (ground station, satellite, attacker) owns an :class:`AsyncRuntime` - an asyncio event
loop running in its own thread - and talks UDP through :class:`UdpEndpoint` datagram endpoints.
Synchronous callers (the Flask console, tests) can still call ``endpoint.sendto`` from any thread;
the datagram is handed to the node's loop with ``call_soon_threadsafe`` so ordering is preserved.
"""
from __future__ import annotations

import asyncio
import socket
import threading
from typing import Awaitable, Callable, Optional


class AsyncRuntime:
    """An asyncio event loop on a background thread, with task tracking and clean shutdown."""

    def __init__(self, name: str = "orbitlock-net"):
        self.loop = asyncio.new_event_loop()
        self._tasks: set = set()
        self._closed = False
        self._thread = threading.Thread(target=self._run, name=name, daemon=True)
        ready = threading.Event()
        self.loop.call_soon(ready.set)
        self._thread.start()
        ready.wait(2)

    def _run(self) -> None:
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    def in_loop(self) -> bool:
        try:
            return asyncio.get_running_loop() is self.loop
        except RuntimeError:
            return False

    def spawn(self, coro: Awaitable) -> Optional["asyncio.Future"]:
        """Schedule a coroutine on the loop from any thread. Returns a concurrent future."""
        if self._closed:
            if asyncio.iscoroutine(coro):
                coro.close()
            return None
        fut = asyncio.run_coroutine_threadsafe(self._track(coro), self.loop)
        return fut

    async def _track(self, coro: Awaitable):
        task = asyncio.current_task()
        self._tasks.add(task)
        try:
            return await coro
        except asyncio.CancelledError:
            return None
        finally:
            self._tasks.discard(task)

    def call_soon(self, fn: Callable, *args) -> None:
        if self._closed:
            return
        try:
            self.loop.call_soon_threadsafe(fn, *args)
        except RuntimeError:        # loop already closed
            pass

    def stop(self) -> None:
        if self._closed:
            return
        self._closed = True

        async def _shutdown():
            for t in list(self._tasks):
                t.cancel()
            await asyncio.sleep(0)

        try:
            asyncio.run_coroutine_threadsafe(_shutdown(), self.loop).result(timeout=1)
        except Exception:
            pass
        self.loop.call_soon_threadsafe(self.loop.stop)
        self._thread.join(timeout=2)
        if not self.loop.is_running():
            self.loop.close()


class UdpEndpoint(asyncio.DatagramProtocol):
    """A bound UDP socket driven by an asyncio datagram transport."""

    def __init__(self, rt: AsyncRuntime, sock: socket.socket,
                 on_datagram: Callable[[bytes, tuple], None]):
        self.rt = rt
        self.sock = sock
        self.on_datagram = on_datagram
        self.transport: Optional[asyncio.DatagramTransport] = None
        self.addr = sock.getsockname()
        fut = rt.spawn(self._open())
        if fut is not None:
            fut.result(timeout=2)

    async def _open(self) -> None:
        self.transport, _ = await self.rt.loop.create_datagram_endpoint(lambda: self, sock=self.sock)

    # -- asyncio.DatagramProtocol -------------------------------------------
    def datagram_received(self, data: bytes, addr) -> None:
        try:
            self.on_datagram(data, addr)
        except Exception:                      # a bad frame must never kill the receive path
            pass

    def error_received(self, exc) -> None:
        pass

    # -- tx -------------------------------------------------------------------
    def sendto(self, data: bytes, addr) -> None:
        tr = self.transport
        if tr is None or tr.is_closing():
            return
        if self.rt.in_loop():
            tr.sendto(data, addr)
        else:
            self.rt.call_soon(self._send_now, data, addr)

    def _send_now(self, data: bytes, addr) -> None:
        tr = self.transport
        if tr is not None and not tr.is_closing():
            tr.sendto(data, addr)

    def close(self) -> None:
        tr = self.transport
        if tr is not None:
            self.rt.call_soon(tr.close)
