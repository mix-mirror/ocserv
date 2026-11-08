#!/usr/bin/env python3
#
# Copyright (C) 2026 Nikos Mavrogiannopoulos
#
# This file is part of ocserv.
#
# ocserv is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# ocserv is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

"""Stand-in for main's occtl control socket, so that occtl's client-side
behavior can be tested without root and without a running server.

Usage: occtl-fake-server.py SOCKET SCENARIO LOGFILE

Every request received is appended to LOGFILE as "<command code>".
The SCENARIO selects how the server answers (see SCENARIOS below).
"""

import os
import socket
import struct
import sys

# src/occtl/ctl.h
CTL_CMD_STATUS = 1
CTL_CMD_LIST = 4
CTL_CMD_TOP = 11
CTL_CMD_LIST_COOKIES = 12

CTL_CMD_STATUS_REP = 101
CTL_CMD_LIST_REP = 104
CTL_CMD_TOP_UPDATE_REP = 109
CTL_CMD_LIST_COOKIES_REP = 110


# src/defs.h, PS_AUTH_*
PS_AUTH_INIT = 2
PS_AUTH_COMPLETED = 4

# A safe_id as main sends it: SAFE_ID_SIZE bytes including the final NUL
SAFE_ID_INIT = b"AbCdEf0123456789abcdefghijk\0"
SAFE_ID_DONE = b"XyZ987AbCdEfGhIjKlMnOpQrStu\0"


def varint(n):
    out = b""
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out += bytes([b | 0x80])
        else:
            return out + bytes([b])


def field_int(num, value):
    return varint(num << 3) + varint(value)


def field_bytes(num, value):
    if isinstance(value, str):
        value = value.encode()
    return varint((num << 3) | 2) + varint(len(value)) + value


def cookie_int_msg(safe_id, username, status):
    return (field_bytes(1, safe_id) + field_int(2, 1) + field_int(3, 0) +
            field_int(4, 1700000000) + field_bytes(5, username) +
            field_bytes(7, "fake-agent") + field_bytes(8, "192.0.2.10") +
            field_int(9, 0) + field_int(10, status) + field_int(11, 0) +
            field_bytes(12, "default"))


def zigzag(n):
    return (n << 1) ^ (n >> 31)


# Values that need JSON escaping, are UTF-8, or are long
JSON_USERNAME = 'quote"back\\slash'
JSON_GROUPNAME = "caf\u00e9-\u20ac"
JSON_DNS = 'dns"entry'
JSON_USER_AGENT = "A" * 600


def user_info_rep():
    """A user_info_rep with every string field main fills in."""
    msg = field_int(1, zigzag(1234)) + field_bytes(2, JSON_USERNAME)
    msg += field_bytes(3, JSON_GROUPNAME) + field_bytes(4, "192.0.2.20")
    for num in (5, 6, 7, 8, 9, 11, 14, 15, 26):
        msg += field_bytes(num, "")
    msg += field_int(10, 1700000000) + field_bytes(12, JSON_USER_AGENT)
    msg += field_int(13, PS_AUTH_COMPLETED) + field_bytes(18, JSON_DNS)
    msg += field_int(28, 90) + field_int(29, 300) + field_int(30, 0)
    msg += field_bytes(32, SAFE_ID_DONE) + field_bytes(33, "default")
    msg += field_int(34, 1700000000)
    return msg


def frame(cmd, payload=b""):
    """The framing of send_msg(): command byte, host-order length, body."""
    return struct.pack("=BI", cmd, len(payload)) + payload


def read_request(conn):
    """Reads one request; returns its command code or None on EOF."""
    hdr = b""
    while len(hdr) < 5:
        chunk = conn.recv(5 - len(hdr))
        if not chunk:
            return None
        hdr += chunk
    cmd, length = struct.unpack("=BI", hdr)
    body = b""
    while len(body) < length:
        chunk = conn.recv(length - len(body))
        if not chunk:
            return None
        body += chunk
    return cmd


def silent(conn, cmd):
    """Reads the request and never answers."""
    while conn.recv(4096):
        pass


def sessions(conn, cmd):
    """Answers CTL_CMD_LIST_COOKIES with an authenticating session listed
    before an authenticated one."""
    reply = (field_bytes(1, cookie_int_msg(SAFE_ID_INIT, "pending",
                                           PS_AUTH_INIT)) +
             field_bytes(1, cookie_int_msg(SAFE_ID_DONE, "alice",
                                           PS_AUTH_COMPLETED)))
    conn.sendall(frame(CTL_CMD_LIST_COOKIES_REP, reply))


def events(conn, cmd):
    """Answers CTL_CMD_TOP with an empty user list, then sends an update
    whose user list is empty, and keeps the connection open."""
    conn.sendall(frame(CTL_CMD_LIST_REP))
    # top_update_rep: connected = 1, user = empty user_list_rep
    conn.sendall(frame(CTL_CMD_TOP_UPDATE_REP,
                       field_int(1, 1) + field_bytes(4, b"")))
    while conn.recv(4096):
        pass


def users(conn, cmd):
    """Answers CTL_CMD_LIST with one user whose fields need escaping."""
    conn.sendall(frame(CTL_CMD_LIST_REP, field_bytes(1, user_info_rep())))


def status_nopids(conn, cmd):
    """Answers CTL_CMD_STATUS with a status_rep that lists no sec-mod
    PIDs, as main sends when it cannot allocate the list."""
    msg = field_int(1, 1) + field_int(2, 4242)
    for num in (4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
                20, 21, 22, 23, 24, 25):
        msg += field_int(num, 0)
    conn.sendall(frame(CTL_CMD_STATUS_REP, msg))


def events_close(conn, cmd):
    """Answers CTL_CMD_TOP with an empty user list and closes the
    connection, as main does for a second listener."""
    conn.sendall(frame(CTL_CMD_LIST_REP))


SCENARIOS = {
    "silent": silent,
    "events-close": events_close,
    "status-nopids": status_nopids,
    "sessions": sessions,
    "events": events,
    "users": users,
}


def main():
    path, scenario, logfile = sys.argv[1:4]
    handler = SCENARIOS[scenario]

    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(path)
    srv.listen(8)

    while True:
        conn, _ = srv.accept()
        with conn:
            cmd = read_request(conn)
            if cmd is None:
                continue
            with open(logfile, "a") as f:
                f.write("%d\n" % cmd)
            handler(conn, cmd)


if __name__ == "__main__":
    main()
