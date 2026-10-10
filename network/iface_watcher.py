"""
NotTheNet - Netlink watcher for new IPv4 addresses.

Lets the iptables manager block pivot paths on interfaces that gain an
address after startup (e.g. a DHCP lease on a second NIC).
"""

from __future__ import annotations

import contextlib
import logging
import os
import select
import socket
import struct
import threading
from collections.abc import Callable

from network.host_state import _PROC_NET_DEV
from utils.logging_utils import sanitize_log_string

logger = logging.getLogger(__name__)


class _NetlinkInterfaceWatcher:
    """Watches for new IPv4 addresses via RTNETLINK and applies pivot DROP rules.

    Opens an AF_NETLINK/NETLINK_ROUTE socket subscribed to the
    RTMGRP_IPV4_IFADDR multicast group.  On each RTM_NEWADDR event it
    resolves the interface index to a name and calls back to
    ``_block_pivot_iface`` on ``IPTablesManager`` so that a bridge coming up
    *after* NTN starts (e.g. vmbr2 in Proxmox) is locked out immediately.

    Pure stdlib — no external dependencies.  Linux only; start() is a no-op
    on non-Linux hosts.
    """

    _RTMGRP_IPV4_IFADDR: int = 0x10
    _RTM_NEWADDR: int = 20
    # Linux socket constants — defined here so Pylance (Windows) does not flag
    # them as missing.  Values are stable across all Linux kernel versions.
    _AF_NETLINK: int = 16    # socket.AF_NETLINK on Linux
    _NETLINK_ROUTE: int = 0  # socket.NETLINK_ROUTE on Linux
    # nlmsghdr: __u32 nlmsg_len, __u16 nlmsg_type, __u16 nlmsg_flags,
    #           __u32 nlmsg_seq, __u32 nlmsg_pid  (total 16 bytes, LE)
    _NL_HDR: struct.Struct = struct.Struct("<IHHII")
    # ifaddrmsg: __u8 ifa_family, __u8 ifa_prefixlen, __u8 ifa_flags,
    #            __u8 ifa_scope, __u32 ifa_index  (total 8 bytes)
    _IFADDR_MSG: struct.Struct = struct.Struct("<BBBBI")

    def __init__(
        self,
        bridge: str,
        block_fn: Callable[[str], bool],
    ) -> None:
        self._bridge = bridge
        self._block_fn = block_fn
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._sock: socket.socket | None = None

    def start(self) -> None:
        """Start the watcher thread.  No-op on non-Linux hosts."""
        if not os.path.exists(_PROC_NET_DEV):
            logger.debug("NetlinkInterfaceWatcher: not Linux; watcher disabled.")
            return
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="ntn-iface-watcher"
        )
        self._thread.start()
        logger.debug("NetlinkInterfaceWatcher: started.")

    def stop(self) -> None:
        """Signal the watcher thread to exit and wait for it."""
        self._stop.set()
        if self._sock is not None:
            with contextlib.suppress(OSError):
                self._sock.close()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None
        logger.debug("NetlinkInterfaceWatcher: stopped.")

    def _run(self) -> None:
        try:
            self._sock = socket.socket(
                self._AF_NETLINK,
                socket.SOCK_RAW,
                self._NETLINK_ROUTE,
            )
            self._sock.bind((0, self._RTMGRP_IPV4_IFADDR))
        except OSError as exc:
            logger.warning("NetlinkInterfaceWatcher: socket error: %s", exc)
            return

        while not self._stop.is_set():
            try:
                ready, _, _ = select.select([self._sock], [], [], 1.0)
                if not ready:
                    continue
                data = self._sock.recv(8192)
                self._handle(data)
            except OSError:
                break

    def _handle(self, data: bytes) -> None:
        """Parse one or more netlink messages from *data*."""
        offset = 0
        hdr_size = self._NL_HDR.size
        msg_size = self._IFADDR_MSG.size
        while offset + hdr_size <= len(data):
            nl_len, nl_type, _, _, _ = self._NL_HDR.unpack_from(data, offset)
            payload_off = offset + hdr_size
            if nl_type == self._RTM_NEWADDR and payload_off + msg_size <= len(data):
                _, _, _, _, ifindex = self._IFADDR_MSG.unpack_from(data, payload_off)
                self._on_new_addr(ifindex)
            if nl_len < hdr_size:
                break
            offset += nl_len

    def _on_new_addr(self, ifindex: int) -> None:
        """Called when a new IPv4 address is assigned to any interface."""
        try:
            iface = socket.if_indextoname(ifindex)
        except OSError:
            return
        if iface in ("lo", self._bridge):
            return
        if iface.startswith(self._bridge + "."):
            return
        logger.warning(
            "NetlinkInterfaceWatcher: new address on %s after NTN start — "
            "applying pivot FORWARD DROP.",
            sanitize_log_string(iface),
        )
        self._block_fn(iface)
